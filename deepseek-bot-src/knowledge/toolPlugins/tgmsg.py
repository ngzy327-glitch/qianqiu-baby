#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# tgmsg — 精确读单条 TG 消息(2026-09-11 改走常驻 daemon socket, 不再起子进程抢 session 锁)
# 用法(argv[1]):
#   '现金红包:3570'             acct1 精确读
#   'acct2:现金红包:3570'       指定 acct2
#   '现金红包:3570:raw'         完整JSON
#   'acct=acct2 group=现金红包 id=3570 raw=1'
import json
import os
import socket
import sys

SOCK_HOST = "127.0.0.1"
SOCK_PORT = 8791
BASE = "/opt/deepseek-bot"


def parse(raw):
    acct = "acct1"
    group = None
    mid = None
    raw_flag = False
    s = (raw or "").strip()
    if "=" in s:
        kv = {}
        for tok in s.replace("&", " ").split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                kv[k.strip().lower()] = v.strip()
        acct = kv.get("acct", kv.get("account", "acct1")).lower()
        group = kv.get("group")
        mid = kv.get("id", kv.get("msgid"))
        raw_flag = kv.get("raw", "").lower() in ("1", "true", "yes", "raw")
        if acct in ("api_acct1", "bot"):
            acct = "acct1"
        return acct, group, mid, raw_flag
    parts = [p.strip() for p in s.split(":")]
    if parts and parts[0].lower() in ("acct1", "acct2", "api_acct1"):
        acct = parts.pop(0).lower()
    if len(parts) >= 2:
        group = parts[0]
        mid = parts[1]
        if len(parts) >= 3 and parts[2].lower() in ("raw", "1", "true"):
            raw_flag = True
    elif len(parts) == 1:
        mid = parts[0]
    if acct == "api_acct1":
        acct = "acct1"
    return acct, group, mid, raw_flag


def call_daemon(acct, args, timeout=90):
    """走常驻 daemon(优先); 失败回退直跑 tg_user.py(会提示锁风险)"""
    try:
        s = socket.create_connection((SOCK_HOST, SOCK_PORT), timeout=timeout)
        s.settimeout(timeout)
        req = json.dumps({"id": 1, "account": acct, "act": "msg", "args": args}, ensure_ascii=False) + "\n"
        s.sendall(req.encode("utf-8"))
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        d = json.loads(buf.decode("utf-8", "replace").strip() or "{}")
        if d.get("ok"):
            return d.get("out") or "(空)"
        return "ERR(daemon): " + str(d.get("err"))
    except Exception as e:
        return f"ERR(daemon不可用): {type(e).__name__}: {e}\n提示: 让大肥鱼随便跑一次 tg 工具即可拉起 daemon; 或直接用内置 tg 工具(act=msg)"


def main():
    if len(sys.argv) < 2:
        print("TGMSG\nUSAGE: tgmsg '<群>:<消息ID>[:raw]'  或 acct=acct2 group=现金红包 id=3570 raw=1")
        return
    acct, group, mid, raw_f = parse(sys.argv[1])
    if not mid:
        print("TGMSG\nERR: 缺消息ID (用法: '<群名>:<消息ID>' 或 'acct=acct1 group=群名 id=123')")
        return
    args = []
    if group:
        args.append(group)
    args.append(str(mid))
    if raw_f:
        args.append("raw")
    print("TGMSG")
    print(call_daemon(acct, args))


if __name__ == "__main__":
    main()
