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
    if act == "login":
        return {}
    if act == "logincode":
        return {"code": s(0, "")}
    if act == "loginpass":
        return {"password": s(0, "")}
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


# ==================== 登录引导(2026-10-22) ====================
_PENDING_LOGINS = {}   # account -> (client, phone_code_hash)


async def _handle_login(act, account, args):
    """tg act=login → 发码; act=logincode tgt=账号:验证码 → 完成; 开了两步验证再 act=loginpass"""
    if account not in tg_user.ACCOUNTS:
        return "未知账号 '%s'，可用: %s" % (account, " / ".join(tg_user.ACCOUNTS.keys()))
    cfg = tg_user.ACCOUNTS[account]
    if act == "login":
        try:
            _old = _PENDING_LOGINS.pop(account, None)
            if _old:
                try: await _old[0].disconnect()
                except Exception: pass
            client, ph = await tg_user.login_start(account)
            _PENDING_LOGINS[account] = (client, ph)
            _audit(account, "login", [], True, "code_sent")
            return ("📨 验证码已发到 %s 的 Telegram 客户端。\n"
                    "请回复: tg act=logincode tgt=%s:验证码" % (cfg.get("phone", "?"), account))
        except Exception as e:
            _audit(account, "login", [], False, str(e)[:80])
            return "ERROR: 登录发起失败: %s" % e
    pend = _PENDING_LOGINS.get(account)
    if not pend:
        return "ERROR: 没有进行中的登录会话, 请先 tg act=login"
    client, ph = pend
    if act == "logincode":
        code = str(args[0] if args else "").strip().replace(" ", "").replace("-", "")
        r = await tg_user.login_finish(client, cfg, code, ph)
        if r == "need_password":
            return "🔐 该账号开了两步验证, 请回复: tg act=loginpass tgt=%s:密码" % account
        if r == "ok":
            _PENDING_LOGINS.pop(account, None)
            CLIENTS.pop(account, None)   # 下次操作重连正式 session
            _audit(account, "login", [], True, "done")
            return "✅ 登录成功! session 已保存, 账号 %s 现在可以用了" % account
        return "ERROR: 登录失败"
    if act == "loginpass":
        password = str(args[0] if args else "")
        r = await tg_user.login_finish(client, cfg, "", ph, password=password)
        if r == "ok":
            _PENDING_LOGINS.pop(account, None)
            CLIENTS.pop(account, None)
            _audit(account, "login", [], True, "done_2fa")
            return "✅ 登录成功(两步验证通过)! 账号 %s 现在可以用了" % account
        return "ERROR: 密码错误或登录失败"
    return "未知登录操作"


# ==================== 规则引擎: 自动回复 + 消息路由(2026-10-22) ====================
# autoreply.json: [{"enabled":true,"accounts":["ops"],"match":"在吗","reply":"在的, 请问什么事~","scope":"private|group|all"}]
# routes.json:    [{"enabled":true,"accounts":["main"],"match":"下单","action":"notify|forward","target":"<账号>:<群>"}]
_RULES_F = os.path.join(os.getenv("BOT_BASE", "/opt/deepseek-bot"), "autoreply.json")
_ROUTES_F = os.path.join(os.getenv("BOT_BASE", "/opt/deepseek-bot"), "routes.json")
_LISTENED = set()


def _load_json(p, default):
    try:
        if os.path.exists(p):
            return json.loads(open(p, encoding="utf-8").read()) or default
    except Exception:
        pass
    return default


async def _rules_notify(text):
    """路由命中时通知主人(bot API 直发, 不经 AI)"""
    token = os.getenv("DEEPSEEK_BOT_TOKEN", "")
    owner = os.getenv("OWNER_ID", "")
    if not token or not owner:
        return
    try:
        import httpx as _hx
        async with _hx.AsyncClient(timeout=8) as hc:
            await hc.post("https://api.telegram.org/bot%s/sendMessage" % token,
                          json={"chat_id": int(owner), "text": text[:3900]})
    except Exception:
        pass


async def _apply_rules(account, client, cfg, event):
    """新消息规则匹配: 自动回复 + 路由转发"""
    text = (getattr(event.message, "message", "") or "")
    if not text:
        return
    low = text.lower()
    # ---- 自动回复 ----
    for r in _load_json(_RULES_F, []):
        try:
            if not r.get("enabled", True):
                continue
            accts = r.get("accounts")
            if accts and account not in accts:
                continue
            kw = str(r.get("match", "")).lower()
            if not kw or kw not in low:
                continue
            scope = str(r.get("scope", "private"))
            if scope == "private" and not event.is_private:
                continue
            if scope == "group" and event.is_private:
                continue
            if not _rate_ok(account):       # 自动回复也算写操作, 过限流
                _audit(account, "autoreply", [kw], False, "rate_limited")
                continue
            await event.reply(str(r.get("reply", "收到")))
            _audit(account, "autoreply", [kw], True, "sent")
            _log("自动回复命中 [%s] kw=%s" % (account, kw))
        except Exception as ex:
            _log("autoreply 执行异常: %s" % ex)
    # ---- 消息路由 ----
    for r in _load_json(_ROUTES_F, []):
        try:
            if not r.get("enabled", True):
                continue
            accts = r.get("accounts")
            if accts and account not in accts:
                continue
            kw = str(r.get("match", "")).lower()
            if not kw or kw not in low:
                continue
            action = str(r.get("action", "notify"))
            if action == "notify":
                await _rules_notify("📡 路由命中 [%s] 关键词「%s」\n来自: %s\n内容: %s"
                                    % (account, kw, getattr(event.chat, "title", None) or "私聊", text[:500]))
            elif action == "forward":
                tgt = str(r.get("target", ""))
                if ":" in tgt and _rate_ok(account):
                    t_acc, t_grp = tgt.split(":", 1)
                    await tg_user.cmd_send(client, cfg, t_grp, "【路由转发】\n" + text[:1500])
                    _audit(account, "route_fwd", [kw, tgt], True, "")
        except Exception as ex:
            _log("route 执行异常: %s" % ex)


async def _ensure_listener(account, client, cfg):
    """每个账号挂一次新消息监听(自动回复/路由规则生效的前提)"""
    if account in _LISTENED:
        return
    _LISTENED.add(account)
    try:
        from telethon import events as _ev
        @client.on(_ev.NewMessage(incoming=True))
        async def _on_msg(e, _acc=account, _cli=client, _cfg=cfg):
            try:
                await _apply_rules(_acc, _cli, _cfg, e)
            except Exception as _ex:
                _log("规则引擎异常 [%s]: %s" % (_acc, _ex))
        _log("规则监听器已挂载 [%s]" % account)
    except Exception as ex:
        _log("监听器挂载失败 [%s]: %s" % (account, ex))


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
    await _ensure_listener(account, c, cfg)   # 挂上规则监听器(自动回复/路由)
    return c, cfg


async def handle(req):
    account = str(req.get("account", "acct1")).lower()
    act = str(req.get("act", "")).lower()
    args = req.get("args") or []
    if act in ("login", "logincode", "loginpass"):
        return await _handle_login(act, account, args)
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
    # 启动时预热: 连接所有已登录账号并挂规则监听器(自动回复/路由 24h 生效)
    for _acc in tg_user.ACCOUNTS:
        try:
            await _get_client(_acc)
        except Exception as _we:
            _log("预热账号 %s 失败(未登录或网络问题, 用到时再连): %s" % (_acc, _we))
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
