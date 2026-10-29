#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SPECTRE Bot 启动诊断脚本 —— 在服务器上运行: python3 diagnose.py

逐项检查: venv / 环境变量 / 依赖 / 目录权限 / 磁盘 / session / 网络 / 实际启动测试
把最后输出的 [SUMMARY] 部分贴给我即可。
"""
import os, sys, shutil, socket, subprocess, importlib, time
from pathlib import Path

BOT_BASE = Path(os.getenv("BOT_BASE", "/opt/deepseek-bot"))
ENV_FILE = BOT_BASE / ".env"
SESSION_DIR = BOT_BASE / "sessions"
VENV_PY = BOT_BASE / ".venv" / "bin" / "python"
REQUIRED_ENV = ["DEEPSEEK_API_KEY", "DEEPSEEK_BOT_TOKEN", "TG_API_ID", "TG_API_HASH"]

results = []
def check(name, ok, detail=""):
    results.append((name, ok, detail))
    status = "✅" if ok else "❌"
    print(f"{status} {name}" + (f" — {detail}" if detail else ""))

def run_venv(args, timeout=15):
    """用 venv python 运行命令, 返回 (returncode, stdout)"""
    py = str(VENV_PY) if VENV_PY.exists() else sys.executable
    r = subprocess.run([py] + args, capture_output=True, text=True, timeout=timeout,
                       cwd=str(BOT_BASE))
    return r.returncode, (r.stdout + r.stderr)

print("=" * 60)
print("SPECTRE Bot 启动诊断")
print(f"检查目录: {BOT_BASE}")
print("=" * 60)

# 1. Python 版本
py_ok = sys.version_info >= (3, 9)
check(f"系统 Python {sys.version.split()[0]}", py_ok, "需要 >= 3.9" if not py_ok else "")

# 2. 虚拟环境
check(f"虚拟环境 {VENV_PY}", VENV_PY.exists(),
      f"不存在! 用系统 python 跑依赖检查" if not VENV_PY.exists() else "存在")

# 3. 依赖 (优先用 venv 检查)
deps = ["telethon", "httpx", "dotenv", "PIL", "bs4", "lxml", "trafilatura",
        "ddgs", "googlesearch", "pypdf", "reportlab", "cryptography",
        "edge_tts", "fastapi", "uvicorn"]
missing = []
for d in deps:
    rc, out = run_venv(["-c", f"import {d}"])
    if rc != 0:
        missing.append(d)
check("依赖包", not missing, f"缺失: {', '.join(missing)}" if missing else "全部就位")

# 4. .env 文件
env_exists = ENV_FILE.exists()
check(f".env 文件 ({ENV_FILE})", env_exists, "" if env_exists else "不存在!")

env_vars = {}
if env_exists:
    for line in ENV_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env_vars[k.strip()] = v.strip().strip('"').strip("'")

# 5. 必填环境变量
for k in REQUIRED_ENV:
    val = os.getenv(k) or env_vars.get(k, "")
    ok = bool(val) and "YOUR" not in val.upper()
    check(f"环境变量 {k}", ok, "未设置或仍是占位符" if not ok else f"已设置(len={len(val)})")

# 6. 目录权限
check(f"安装目录 {BOT_BASE}", BOT_BASE.exists(), "不存在" if not BOT_BASE.exists() else
      f"可写={os.access(BOT_BASE, os.W_OK)}")
check(f"sessions 目录 {SESSION_DIR}", SESSION_DIR.exists(),
      "不存在" if not SESSION_DIR.exists() else f"可写={os.access(SESSION_DIR, os.W_OK)}")

# 7. 磁盘空间
disk_path = str(BOT_BASE if BOT_BASE.exists() else "/")
total, used, free = shutil.disk_usage(disk_path)
free_gb = free / (1024**3)
check(f"磁盘剩余 {free_gb:.1f} GB", free_gb > 1, f"建议 > 1GB, 太少会导致 SQLite/session 写失败")

# 8. Session 文件
sess = SESSION_DIR / "ds.session"
if sess.exists():
    size = sess.stat().st_size
    check(f"Session 文件 ds.session", size > 0, f"{size} bytes" if size > 0 else "空文件! 需删除重建")
else:
    check(f"Session 文件", False, f"{sess} 不存在, 首次启动会自动创建(无需担心)")

# 9. 网络连通性
print("\n🌐 网络连通性测试...")
for host, port in [("api.telegram.org", 443), ("api.deepseek.com", 443)]:
    try:
        sock = socket.create_connection((host, port), timeout=8)
        sock.close()
        check(f"网络 {host}:{port}", True, "可达")
    except Exception as e:
        check(f"网络 {host}:{port}", False, f"不可达: {e} (阿里云需开代理或安全组放行)")

# 10. 实际启动测试
print("\n🚀 实际启动测试 (最多等 25 秒)...")
env = os.environ.copy()
for k in REQUIRED_ENV:
    if k in env_vars and not env.get(k):
        env[k] = env_vars[k]

py = str(VENV_PY) if VENV_PY.exists() else sys.executable
startup_log = BOT_BASE / "startup_test.log"
try:
    with open(startup_log, "w") as lf:
        subprocess.run(
            [py, "-m", "deepseek_bot.run"],
            cwd=str(BOT_BASE), env=env, stdout=lf, stderr=subprocess.STDOUT,
            timeout=25
        )
    log = startup_log.read_text(encoding="utf-8", errors="replace")
    has_tb = "Traceback" in log
    print("\n--- 启动日志 (最后 50 行) ---")
    print("\n".join(log.splitlines()[-50:]))
    print("--- 日志结束 ---\n")
    if has_tb:
        check("启动测试", False, "有 Traceback, 请看上面日志定位错误")
    elif "@" in log:
        check("启动测试", True, "成功连上 Telegram, 看到 @用户名")
    else:
        check("启动测试", False, "没连上也没报错, 看日志判断")
except subprocess.TimeoutExpired:
    log = startup_log.read_text(encoding="utf-8", errors="replace") if startup_log.exists() else ""
    print("\n--- 启动日志 (最后 50 行) ---")
    print("\n".join(log.splitlines()[-50:]))
    print("--- 日志结束 ---\n")
    has_tb = "Traceback" in log
    check("启动测试", "@" in log and not has_tb,
          "超时(已连上TG在运行中)" if ("@" in log and not has_tb) else "超时但没看到 @用户名, 看日志")
except FileNotFoundError:
    check("启动测试", False, f"找不到 run 入口, 检查 {BOT_BASE}/deepseek_bot/ 是否完整")
except Exception as e:
    check("启动测试", False, f"异常: {e}")

# 11. systemd 服务状态
print("\n📋 systemd 服务状态:")
for svc in ["deepseek-bot", "deepseek-tg-chat", "spectre-bot", "tg-chatbot"]:
    r = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True)
    if r.returncode == 0:
        state = r.stdout.strip()
        check(f"服务 {svc}", state == "active", f"状态: {state}")

# 12. 端口占用 (8901 miniapp)
print("\n🔌 端口占用:")
r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True)
for line in r.stdout.splitlines():
    if ":8901" in line or ":443" in line:
        print(f"  {line.strip()}")

print("\n" + "=" * 60)
print("[SUMMARY] 把下面这一段贴给我:")
print("=" * 60)
for name, ok, detail in results:
    print(f"{'PASS' if ok else 'FAIL'} | {name} | {detail}")
