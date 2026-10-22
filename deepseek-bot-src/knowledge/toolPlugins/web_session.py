#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
web_session — 多账号常驻网页会话插件(2026-10-22)

和 web_visit 的区别:
  web_visit   一次性打开、看完就关, 不留登录态。
  web_session 页面**常驻不关**, 每个账号独立 profile/指纹/代理, 登录一次后续接着点。

用法(框架以 JSON argv[1] 调用):
  {"act":"open","account":"main","url":"https://example.com"}
  {"act":"see","account":"main"}                       # 看当前页面(截图+正文)
  {"act":"click","account":"main","text":"登录"}        # 或 selector="#submit"
  {"act":"type","account":"main","selector":"input","value":"hi","enter":true}
  {"act":"scroll","account":"main","dy":900}
  {"act":"tabs"/"switch"/"close"/"list"}

daemon 不存在时自动拉起(web_session_daemon.py), 之后常驻复用。
"""
import json
import os
import socket
import subprocess
import sys
import time

BOT_BASE = os.getenv("BOT_BASE", "/opt/deepseek-bot")
SOCK_F = os.path.join(BOT_BASE, "web_session.sock")

ACTS = {
    "open": "打开网页(常驻)", "see": "查看当前页面", "click": "点击",
    "type": "输入", "press": "按键", "scroll": "滚动", "back": "后退",
    "reload": "刷新", "wait": "等待", "tabs": "标签列表", "switch": "切换标签",
    "new_tab": "新开标签", "close_tab": "关闭标签", "close": "关闭该账号浏览器",
    "list": "列出常驻会话",
}


def _daemon_path():
    for p in (os.path.join(BOT_BASE, "web_session_daemon.py"),
              os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
                  os.path.abspath(__file__)))), "web_session_daemon.py")):
        if os.path.exists(p):
            return p
    return ""


def _alive():
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(0.4)
        s.connect(SOCK_F)
        s.close()
        return True
    except Exception:
        return False


def _spawn():
    path = _daemon_path()
    if not path:
        return False
    try:
        os.makedirs(BOT_BASE, exist_ok=True)
    except Exception:
        pass
    log = open(os.path.join(BOT_BASE, "web_session.log"), "a")
    subprocess.Popen([sys.executable, path], stdout=log, stderr=log,
                     start_new_session=True, close_fds=True)
    for _ in range(40):
        time.sleep(0.25)
        if _alive():
            return True
    return False


def call(req):
    if not _alive() and not _spawn():
        return {"ok": False, "error": "无法启动 web_session 守护进程(检查 playwright 是否安装, 见 web_session.log)"}
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(185)
        s.connect(SOCK_F)
        s.sendall((json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8"))
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        return json.loads(buf.decode("utf-8").strip() or "{}")
    except Exception as e:
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, str(e)[:200])}


def render(r):
    if not r.get("ok"):
        return "ERROR: " + str(r.get("error") or "未知错误")
    if "sessions" in r:
        if not r["sessions"]:
            return "当前无常驻会话。用 open 打开一个账号的页面。"
        lines = ["常驻会话 %d 个:" % len(r["sessions"])]
        for x in r["sessions"]:
            lines.append("· %s [%s] 空闲%ss  %s\n  %s" % (
                x.get("account"), x.get("profile"), x.get("idle"),
                (x.get("title") or "")[:60], x.get("url") or ""))
        return "\n".join(lines)
    out = []
    if r.get("msg"):
        out.append(str(r["msg"]))
    if r.get("title") or r.get("url"):
        out.append("页面: %s\nURL: %s" % (r.get("title") or "", r.get("url") or ""))
    if r.get("tabs") and len(r["tabs"]) > 1:
        out.append("标签(%d): " % len(r["tabs"]) + " | ".join(
            "%d.%s %s" % (t["index"], (t["title"] or "")[:20], t["url"][:60]) for t in r["tabs"]))
    if r.get("screenshot"):
        out.append("截图: %s" % r["screenshot"])
    if r.get("text"):
        out.append("正文:\n" + r["text"])
    if r.get("account"):
        out.append("(账号 %s, 指纹 %s)" % (r["account"], r.get("profile") or "-"))
    return "\n".join(out) or "OK"


def main():
    try:
        req = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
    except Exception:
        req = {}
    act = (req.get("act") or "see").lower()
    if act == "help":
        for k, v in ACTS.items():
            print("· %s: %s" % (k, v))
        return
    if act not in ACTS:
        print("未知 act '%s', 可用: %s" % (act, " / ".join(ACTS)))
        return
    if act != "list" and not req.get("account"):
        req["account"] = "default"
    print(render(call(req)))


if __name__ == "__main__":
    main()
