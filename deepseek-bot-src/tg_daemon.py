# -*- coding: utf-8 -*-
"""
TG 双号常驻服务(2026-09-08): 一次连接多次命令, 消除 bot 每次操作冷启动子进程的 1.6~3.5s 延迟。

协议(stdin/stdout, 每行一个 JSON):
  请求: {"id": 1, "account": "acct1", "act": "dialogs", "args": [20]}
  响应: {"id": 1, "ok": true, "out": "..."}   或 {"id":1,"ok":false,"err":"..."}

stdout 只走协议(经 sys.__stdout__); 所有辅助 print 被重定向到日志文件, 不污染协议。
日志: /opt/deepseek-bot/tg_daemon.log
"""
import asyncio
import io
import json
import os
import sys
import time

LOG = "/opt/deepseek-bot/tg_daemon.log"

sys.path.insert(0, "/opt/deepseek-bot")
import tg_user  # 复用 ACCOUNTS / get_client / 全部 cmd_*


def _log(msg):
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), msg))
    except Exception:
        pass


class _RedirectStdout:
    """把后续所有 print 吸进日志文件(协议走 sys.__stdout__)"""
    def __init__(self, path):
        self._f = open(path, "a", encoding="utf-8")
    def write(self, s):
        try:
            self._f.write(s)
        except Exception:
            pass
        return len(s)
    def flush(self):
        try:
            self._f.flush()
        except Exception:
            pass


def _resp_line(obj):
    sys.__stdout__.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.__stdout__.flush()


def _acquire_single():
    """fcntl 单实例锁(防双 daemon 并发踩 session 文件导致 database is locked)"""
    try:
        import fcntl
        _f = open("/tmp/tg_daemon.lock", "w")
        try:
            fcntl.flock(_f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        try:
            with open("/tmp/tg_daemon.pid", "w") as pf:
                pf.write(str(os.getpid()))
        except Exception:
            pass
        return True
    except Exception:
        return True  # 非 linux 环境不阻塞


# ---- main() 参数解析 1:1 复刻(sys.argv[3:] == args) ----
def _parse_args(act, args):
    args = list(args)

    def s(i, d=""):
        return str(args[i]) if len(args) > i and args[i] is not None else d

    def n(i, d=0, cast=int):
        try:
            return cast(args[i]) if len(args) > i and args[i] is not None else d
        except Exception:
            return d

    def oi(i):
        try:
            return int(args[i]) if len(args) > i and args[i] is not None else None
        except Exception:
            return None

    if act == "dialogs":
        return {"limit": n(0, 20)}
    if act == "messages":
        return {"target": s(0, "me"), "limit": n(1, 50), "offset_id": oi(2),
                "raw": s(3).lower() in ("raw", "json", "1", "true")}
    if act == "msg":
        return {"target": s(0, ""), "msg_id": s(1, "")}
    if act == "send":
        return {"target": s(0, ""), "text": " ".join(args[1:])}
    if act == "click":
        return {"target": s(0, ""), "msg_id": n(1, 0), "row": n(2, 0), "col": n(3, 0)}
    if act == "buttons":
        return {"target": s(0, ""), "msg_id": n(1, 0)}
    if act == "webapp":
        if len(args) > 1 and args[1] is not None:
            return {"kwargs": (s(0, ""), n(1, 0))}
        return {"kwargs": (s(0, ""),)}
    if act == "groupinfo":
        return {"target": s(0, "")}
    if act == "user":
        return {"target": s(0, "")}
    if act == "search":
        return {"target": s(0, ""), "keyword": s(1, ""), "limit": oi(2) or 50, "offset_id": oi(3)}
    if act in ("stats", "whois"):
        return {"target": s(0, ""), "limit": oi(1) or 200, "offset_id": oi(2)}
    if act == "members":
        return {"target": s(0, ""), "limit": oi(1) or 200}
    if act == "join":
        return {"invite": s(0, "")}
    if act == "react":
        return {"target": s(0, ""), "msg_id": n(1, 0), "emoji": s(2, "👍")}
    if act == "accounts":
        return {}
    if act == "unread":
        return {"limit": n(0, 50)}
    return None


# ==================== 操作护栏(2026-10-22) ====================
# 分级: 只读直通; 写入类受频率限制 + 全量审计。AI 层的"先确认再执行"在 bot 提示词与 tg 工具描述里约束。
READ_ACTS = {"dialogs", "messages", "msg", "search", "stats", "whois",
             "members", "groupinfo", "user", "buttons", "accounts", "unread"}
WRITE_ACTS = {"send", "react", "click", "join", "webapp"}
AUDIT_LOG = os.path.join(os.getenv("BOT_BASE", "/opt/deepseek-bot"), "audit.log")
_W_RATE = {}          # account -> [ts, ...] 写操作时间戳
_W_LIMIT = 10         # 每账号每分钟写操作上限(防 FloodWait/封号)


def _rate_ok(account):
    """写操作频率闸门: 超限时返回 False"""
    now = time.time()
    win = [t for t in _W_RATE.get(account, []) if now - t < 60]
    if len(win) >= _W_LIMIT:
        _W_RATE[account] = win
        return False
    win.append(now)
    _W_RATE[account] = win
    return True


def _audit(account, act, args, ok, note=""):
    """操作审计: JSONL 落盘, 每条含时间/账号/操作/参数摘要/结果"""
    try:
        rec = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "account": account,
               "act": act, "args": [str(x)[:80] for x in (args or [])][:4],
               "ok": bool(ok), "note": str(note)[:120]}
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


async def _run_cmd(client, cfg, act, args):
    fn = getattr(tg_user, "cmd_" + act, None)
    if fn is None:
        return "未知操作: %s" % act
    kw = _parse_args(act, args)
    if kw is None:
        return "参数解析失败: %s" % act
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        if act == "webapp":
            await fn(client, cfg, *kw["kwargs"])
        else:
            await fn(client, cfg, **kw)
    finally:
        sys.stdout = old
    out = buf.getvalue().strip()
    return out or "Done"


CLIENTS = {}


async def _get_client(account):
    if account in CLIENTS:
        c, cfg = CLIENTS[account]
        if c.is_connected():
            return c, cfg
        try:
            await c.connect()
            return c, cfg
        except Exception as e:
            _log("重连失败 %s: %s" % (account, e))
            CLIENTS.pop(account, None)
    try:
        c, cfg = await tg_user.get_client(account)
    except Exception as e:
        _log("连接异常 %s: %s" % (account, e))
        return None, None
    if c is None:
        _log("连接失败 %s: Session 未授权/未知账号" % account)
        return None, None
    c.flood_sleep_threshold = 15
    CLIENTS[account] = (c, cfg)
    _log("已连接账号 %s" % account)
    return c, cfg


async def handle(req):
    account = str(req.get("account", "acct1")).lower()
    act = str(req.get("act", "")).lower()
    args = req.get("args") or []
    if act == "accounts":
        # 列账号不需要 client 连接
        try:
            return await tg_user.cmd_accounts(None, None)
        except Exception:
            import io as _io, contextlib as _cl
            _b = _io.StringIO()
            with _cl.redirect_stdout(_b):
                await tg_user.cmd_accounts(None, None)
            return _b.getvalue().strip()
    if account not in tg_user.ACCOUNTS:
        return "未知账号 '%s'，可用: %s" % (account, " / ".join(tg_user.ACCOUNTS.keys()))
    if not act:
        return "缺少 act"
    if act in WRITE_ACTS and not _rate_ok(account):
        _audit(account, act, args, False, "rate_limited")
        return "ERROR: 操作过于频繁(每账号每分钟写操作上限 %d 次), 请稍后" % _W_LIMIT
    c, cfg = await _get_client(account)
    if c is None:
        _audit(account, act, args, False, "no_session")
        return "ERROR: 会话未授权/连接失败"
    try:
        out = await asyncio.wait_for(_run_cmd(c, cfg, act, args), timeout=60)
        _audit(account, act, args, not str(out).startswith("ERROR"), "write" if act in WRITE_ACTS else "read")
        return out
    except asyncio.TimeoutError:
        _audit(account, act, args, False, "timeout")
        return "TG命令超时(60s)"
    except Exception as e:
        _audit(account, act, args, False, "%s" % type(e).__name__)
        return "ERROR: %s: %s" % (type(e).__name__, e)


async def _sock_client(reader, writer):
    """2026-09-11 本地TCP接入(127.0.0.1): 供插件/脚本复用daemon, 避免各自起子进程抢session锁"""
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            try:
                req = json.loads(line.decode("utf-8", "replace").strip())
            except Exception:
                writer.write(b'{"id":-1,"ok":false,"err":"bad json"}\n')
                await writer.drain()
                continue
            try:
                out = await handle(req)
                resp = {"id": req.get("id", 0), "ok": True, "out": out}
            except Exception as e:
                resp = {"id": req.get("id", 0), "ok": False, "err": str(e)[:300]}
            writer.write((json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8"))
            await writer.drain()
    except Exception as _se:
        _log("socket 会话异常: %s" % _se)
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def amain():
    _log("tg_daemon 启动 pid=%s py=%s" % (os.getpid(), sys.executable))
    try:
        _srv = await asyncio.start_server(_sock_client, "127.0.0.1", 8791)
        _log("本地 socket 已监听 127.0.0.1:8791")
    except Exception as _se2:
        _log("socket 监听失败: %s" % _se2)
    loop = asyncio.get_running_loop()
    try:
        while True:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                _log("stdin EOF, 退出")
                break
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except Exception:
                _resp_line({"id": -1, "ok": False, "err": "bad json"})
                continue
            rid = req.get("id", 0)
            try:
                out = await handle(req)
                _resp_line({"id": rid, "ok": True, "out": out})
            except Exception as e:
                _log("handle 异常: %s" % e)
                _resp_line({"id": rid, "ok": False, "err": str(e)[:500]})
    finally:
        for account, (c, _cfg) in list(CLIENTS.items()):
            try:
                await c.disconnect()
            except Exception:
                pass
        _log("tg_daemon 退出")


def main():
    if not _acquire_single():
        _log("已有 tg_daemon 实例在跑(单实例锁), 退出")
        return
    sys.stdout = _RedirectStdout(LOG)
    sys.stderr = _RedirectStdout(LOG)
    asyncio.run(amain())


if __name__ == "__main__":
    main()
