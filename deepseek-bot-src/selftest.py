# -*- coding: utf-8 -*-
"""大肥鱼自检 (selftest.py) — 一条命令出体检报告
用法: cd /opt/deepseek-bot && .venv/bin/python selftest.py

检查项: 服务/进程 · 插件 · 工具挂载与去重 · tg_daemon socket 与多号 · 配置(模型/推理/代理)
        · 面板渲染(_bg_card) · 后台播报(吞/播逻辑) · 富文本转换 · 磁盘
"""
import ast
import glob
import json
import os
import re
import socket
import subprocess
import sys
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BOT = "/opt/deepseek-bot/deepseek_bot/bot.py"
PASS, FAIL, WARN = [], [], []


def ok(name, extra=""):
    PASS.append(name)
    print(f"  ✅ {name}" + (f" — {extra}" if extra else ""))


def bad(name, extra=""):
    FAIL.append(name)
    print(f"  ❌ {name}" + (f" — {extra}" if extra else ""))


def warn(name, extra=""):
    WARN.append(name)
    print(f"  ⚠️  {name}" + (f" — {extra}" if extra else ""))


def sh(cmd, t=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return f"ERR {e}"


print("=" * 64)
print("① 服务 / 进程")
print("=" * 64)
if sh("systemctl is-active deepseek-bot").strip() == "active":
    ok("deepseek-bot 服务在跑")
else:
    bad("deepseek-bot 服务不是 active")
_n = sh("ps aux | grep -c '[t]g_daemon.py'").strip()
(ok if _n == "1" else warn)("tg_daemon 进程数=1", f"实际 {_n}")
if sh("ss -ltn | grep -c 8791").strip() == "1":
    ok("daemon socket 127.0.0.1:8791 在听")
else:
    warn("daemon socket 未监听", "首次 tg 调用会冷启动")

print("=" * 64)
print("② 代码 / 插件 / 工具")
print("=" * 64)
SRC = open(BOT, encoding="utf-8").read()
try:
    tree = ast.parse(SRC)
    ok("bot.py 语法(AST)")
except Exception as e:
    bad("bot.py 语法错误", str(e)[:120])
    tree = None
try:
    pl = glob.glob("/opt/deepseek-bot/knowledge/toolPlugins/*.json")
    names = []
    for f in pl:
        try:
            names.append(json.load(open(f, encoding="utf-8")).get("name"))
        except Exception:
            pass
    if len(names) >= 14 and all(names):
        ok(f"插件注册 {len(names)} 个", ", ".join(sorted(n for n in names if n))[:90])
    else:
        warn(f"插件数偏少/有坏 json", f"{len(names)} 个: {names}")
except Exception as e:
    bad("插件扫描失败", str(e)[:100])

# 工具挂载去重(模拟多AI关键词命中 team 的场景 → 不应重复)
if tree:
    ok_tools = False
    try:
        ns = {}
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id in ("_TOOL_BASE", "HEAVY_KW", "_NEED_MAP"):
                        ns[t.id] = ast.literal_eval(node.value)
        if "_TOOL_BASE" in ns and "HEAVY_KW" in ns:
            base = set(ns["_TOOL_BASE"])
            hk = set(ns["HEAVY_KW"].keys())
            dup = base & hk
            if dup:
                warn("常驻与重型关键词有交集(已由代码内去重兜底)", ", ".join(sorted(dup)))
            else:
                ok("工具集合无重名风险")
    except Exception as e:
        warn("工具集静态检查跳过", str(e)[:80])

print("=" * 64)
print("③ 配置(模型 / 推理 / 代理)")
print("=" * 64)
try:
    mc = json.load(open("/opt/deepseek-bot/model_switch.json", encoding="utf-8"))
    ok("模型配置可读", f"mode={mc.get('mode')} think={mc.get('think') or 'auto'}")
except Exception as e:
    warn("模型配置读取失败", str(e)[:80])
try:
    px = json.load(open("/opt/deepseek-bot/proxy.json", encoding="utf-8"))
    tun = str(px.get("_tunnel") or "")
    if tun:
        ok("代理隧道已配置", tun.split(":")[0] + ":" + (tun.split(":")[1] if ":" in tun else ""))
    else:
        warn("代理未配置(_tunnel 空)")
except Exception as e:
    warn("代理配置读取失败", str(e)[:80])

print("=" * 64)
print("④ 关键函数存在性")
print("=" * 64)
NEED = ["_bg_card", "_bg_reporter", "_bg_render", "_bg_http", "_disk_cleanup", "_disk_guard", "_disk_info",
        "_media_ext_sniff", "_think_for", "_tools_for", "_home_card", "_send_file_http", "_tg_daemon_start"]
miss = [f for f in NEED if f"def {f}(" not in SRC]
(ok if not miss else bad)("关键函数齐全" if not miss else "缺函数", ", ".join(miss))
MARK = {"后台播报": "_bg_reporter", "完成提示": "完成后主动提示", "禁用路线": "===禁用路线(CRITICAL)===",
        "后台任务提示词": "===后台任务与进度(CRITICAL)===", "ask超时兜底": "_ans_to", "下载双路": "_attempts_d",
        "后缀嗅探": "_media_ext_sniff", "推理等级": "_THINK_LBL", "面板门槛": "_scan_kw",
        "提示词分层": "[sp] 分层摘出", "定时任务按钮": "sched:off", "完整内容按钮": "full:",
        "rewind回滚": "rewind|回滚", "edit差异": "_REWIND_LOG", "排队分支失败统计": "_tool_fail_note(_fn, _res)",
        "多引擎搜索": "_web_search_multi", "深度检索": "_deep_research", "正文净化": "trafilatura",
        "联网检索提示词": "===联网检索(CRITICAL)===",
        "HTML转实体(dt富文本)": "_html_to_entities", "dt偏移平移": "_dt_apply", "实体合并": "_merge_entities",
        "文件发送统一入口": "_flush_pending_files",
        "顶层reasoning_effort": "_think_params", "tool_choice强指定": "_FORCE_TOOL",
        "缓存前缀优化": "[cache] 易变时间", "群管gid防呆": "拿不到群ID", "吞消息诊断": "[swallow]",
        "自我扩展工具": "selfext", "值守工具": "watch", "值守线程": "[watch] 值守线程已启动",
        "脚本形态计数": "_sh_shape_count", "值守模块": "_watch_loop",
        "任务清单工具": "def _todo_txt", "清单心跳显示": "清单 2/5", "清单渲染": "_todo_txt("}
for k, v in MARK.items():
    (ok if v in SRC else bad)(f"标记: {k}")

print("=" * 64)
print("⑤ 功能逻辑自测(AST 抽函数跑)")
print("=" * 64)
if tree:
    seg = {}
    _WANT_FN = ("_bg_human", "_bg_human_size", "_bg_render", "_bg_card", "_media_ext_sniff",
                # 2026-09-11 面板改用自定义表情/彩色按钮后, _bg_card 依赖这些辅助函数, 抽函数时要一起带上
                "_px", "_strip_px", "_b", "_strip_btn_extras", "_has_btn_extras")
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in _WANT_FN:
            seg[node.name] = ast.get_source_segment(SRC, node)
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id in ("_THINK_LBL", "_PMAP"):
                    seg[t.id] = ast.get_source_segment(SRC, node)

    class _B:
        @staticmethod
        def inline(text, data):
            return (text, data)

    g = {"time": time, "os": os, "Button": _B, "_BG_SH": {}, "_running_procs": {}, "_TEAM_INFO": {},
         "_ASK_PEND": {}, "_pending_files": {}, "_disk_info": lambda: (100, 30, 30), "print": print}
    try:
        for k in ("_THINK_LBL", "_PMAP") + _WANT_FN:   # 常量必须先于函数 exec(_px 会读 _PMAP)
            if k in seg:
                exec(seg[k], g)
        txt, btns = g["_bg_card"](None, True)
        _miss = [x for x in ("后台任务面板", "磁盘") if x not in txt]
        assert not _miss and btns, f"缺字段 {_miss} 按钮数={sum(len(r) for r in btns) if btns else 0}"
        ok("后台任务面板渲染", f"{len(txt)} 字, {sum(len(r) for r in btns)} 按钮")
    except Exception as e:
        bad("后台任务面板渲染", f"{type(e).__name__}: {e}"[:160])
    # 后缀嗅探: 造个假 mp4 头
    try:
        p = "/tmp/_selftest_sniff.bin"
        open(p, "wb").write(b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 32)
        r = g["_media_ext_sniff"](p)
        os.remove(p)
        (ok if r == ".mp4" else bad)("魔数嗅探 mp4", f"返回 {r}")
    except Exception as e:
        warn("魔数嗅探测试跳过", str(e)[:80])

# 播报吞/播逻辑
TALK_CASES = [
    ("主人又甩了个链接——先看看是什么歌\n本小姐直接抓页面看内容:", "吞"),
    ("主人这歌扒到了\n- 🎵 下载?\n- 📝 还是想扒歌词?", "吞"),
    ("刚拿到 130 个接口, 正在逐个探未授权", "播"),
    ("发现 /anon/evaluate/detail 泄露手机号", "播"),
]
import re as _re
_imp = _re.compile(r'(发现|找到|拿到|成功|完成|结果|返回|已经|搞定|拿下|突破|命中|失败|出错|报错|漏洞|过期|无效|无法|拒绝|并发|✅|❌|⚠|http|://)')
_act = _re.compile(r'(了[。；\n]|正在|在(扫|查|拉|读|跑|测|搜|看|抓|翻)|(扫|查|拉|读|跑|测|搜|看|抓|翻)了|(扫描|请求|探测|枚举|遍历|爆破|测试|下载|解析)完|准备|开始|继续|再试|改用|换成|重试|阶段|第\d+轮|拿到|看到|返回了|\d+个|\d+条)')
_pre = _re.compile(r'(先看看|先看下|先查|先抓|先读|先跑|先扫|先测|直接抓|直接上工具|直接扒|试试|试一试|这就|马上|本小姐来|先分析|看一眼|看看到底|看下)')
_opt = _re.compile(r'(你是想|你要哪个|请选择|选一个|选哪个|还是想|要不要|A[\.、\)）]|1[\.、\)）]\s|回复(数字|序号))')
_tk_ok = 0
for t, want in TALK_CASES:
    swallow = bool(_opt.search(t[:200])) or ((not _imp.search(t[:100])) and ((not _act.search(t[:60])) or bool(_pre.search(t[:60]))))
    got = "吞" if swallow else "播"
    _tk_ok += (got == want)
(ok if _tk_ok == len(TALK_CASES) else bad)(f"播报吞/播判定 {_tk_ok}/{len(TALK_CASES)}")

print("=" * 64)
print("⑥ 数据 / 磁盘")
print("=" * 64)
try:
    h = json.load(open("/opt/deepseek-bot/history.json", encoding="utf-8"))
    ok("历史库可读", f"{len(h)} 会话 / {sum(len(v) for v in h.values() if isinstance(v, list))} 条 / {os.path.getsize('/opt/deepseek-bot/history.json')//1024}KB")
except Exception as e:
    bad("历史库读取失败", str(e)[:100])
st = os.statvfs("/")
pct = int((st.f_blocks - st.f_bavail) * 100 / st.f_blocks)
(ok if pct < 85 else warn)(f"磁盘占用 {pct}%")
tmp_sz = sh("du -sh /tmp 2>/dev/null | awk '{print $1}'").strip()
big = sh("find /tmp -type f -size +200M 2>/dev/null | head -5").strip()
print(f"     /tmp 占用 {tmp_sz}" + (f" | >200M 文件:\n       " + "\n       ".join(big.split("\n")) if big else ""))

print("=" * 64)
print(f"结果: ✅ {len(PASS)} 通过 | ⚠️ {len(WARN)} 警告 | ❌ {len(FAIL)} 失败")
if WARN:
    print("警告:", "; ".join(WARN))
if FAIL:
    print("失败:", "; ".join(FAIL))
print("=" * 64)
sys.exit(1 if FAIL else 0)
