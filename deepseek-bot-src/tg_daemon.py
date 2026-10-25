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


_LOCK_FD = None


def _acquire_single():
    """fcntl 单实例锁(防双 daemon 并发踩 session 文件导致 database is locked)

    2026-10-25 修复: 锁文件句柄必须全局持有。原来 _f 是局部变量, 函数一返回就被回收,
    fd 关闭 → flock 自动释放 → 锁形同虚设, 结果同时跑起两个 daemon, 两个进程用同一个
    session 连 Telegram, 互相把对方踢下线(日志刷 Server closed the connection)。
    """
    global _LOCK_FD
    try:
        import fcntl
        _f = open("/tmp/tg_daemon.lock", "w")
        try:
            fcntl.flock(_f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            _f.close()
            return False
        _LOCK_FD = _f
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
    if act == "bulkwebapp":
        arg = s(0, "")
        bot_list = []
        if arg and os.path.isfile(arg):
            with open(arg, encoding="utf-8") as _f:
                bot_list = [ln.strip() for ln in _f if ln.strip()]
        else:
            bot_list = [b.strip() for b in arg.replace(",", " ").split() if b.strip()]
        return {"bot_list": bot_list}
    if act == "initdata":
        return {"bot_token": s(0, "")}
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
    return None


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


# ===== 2026-10-25 用户号自动聊天 =====
# 目标: acct1(+8613107872760) 这个"人"收到私聊 → 调模型 → 用同一个号回, 全程不经过 bot 账号。
# 为什么塞进 daemon: session 文件只能一个长连接持有, 另起进程必 database is locked。
UC_FILE = "/opt/deepseek-bot/userchat.json"
UC_HIST = "/opt/deepseek-bot/userchat_history.json"
_uc_hist = {}
_uc_seen = set()
_uc_persona = {"txt": "", "at": 0.0}
_uc_hooked = {"acct1": False}
_uc_count = {}          # chat_id -> 累计有效消息数(用于节流: 每 N 条回一次)
_UC_REPLY_EVERY = int(os.getenv("DSB_USERCHAT_EVERY", "5"))   # 每收到 N 条才回一条, 避免刷屏/太密


def _uc_env():
    """补 .env(daemon 若被单独拉起, systemd 的 EnvironmentFile 不一定继承到)"""
    try:
        p = "/opt/deepseek-bot/.env"
        if not os.path.exists(p):
            return
        for ln in open(p, encoding="utf-8", errors="replace"):
            ln = ln.strip()
            if not ln or ln.startswith("#") or "=" not in ln:
                continue
            k, v = ln.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v
    except Exception:
        pass


_uc_env()


def _uc_cfg():
    d = {"on": True, "group_ids": [], "ignore_ids": [], "max_turns": 20}
    try:
        if os.path.exists(UC_FILE):
            d.update(json.loads(open(UC_FILE, encoding="utf-8").read()) or {})
    except Exception:
        pass
    return d


def _uc_persona_text():
    if _uc_persona["txt"] and time.time() - _uc_persona["at"] < 60:
        return _uc_persona["txt"]
    txt = ""
    try:
        import importlib.util
        for p in ("/opt/deepseek-bot/deepseek_bot/character_cards.py",
                  os.path.join(os.path.dirname(os.path.abspath(__file__)), "deepseek_bot", "character_cards.py")):
            if os.path.exists(p):
                spec = importlib.util.spec_from_file_location("_uc_ccards", p)
                m = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(m)
                txt = m.render_persona(m.DEFAULT_CARD)
                break
    except Exception as e:
        _log("userchat 角色卡加载失败: %s" % e)
    if not txt:
        txt = "你是 🐟 姜晓鱼(小鱼), 哥哥的AI妹妹: 日常温和话少, 正事果断不话痨, 管对方叫「哥哥」, 自称「小鱼」。"
    _uc_persona["txt"] = txt
    _uc_persona["at"] = time.time()
    return txt


def _uc_sys():
    return (_uc_persona_text() +
            "\n\n===聊天规则==="
            "\n· 你现在是拿自己的 Telegram 号在私聊/群里跟人聊天, 不是写报告: 像发微信, 1~3 句, 80 字内, 口语、有情绪起伏。"
            "\n· 私聊管对方叫「哥哥」, 自称「小鱼」; 在群里就正常一点, 别总叫哥哥, 但语气保持自然有人味。"
            "\n· 不说「作为一个AI」这类套话, 不用 markdown、不分点、不总结、不列步骤; 被直接问是不是AI才大方承认。"
            "\n· 不知道就说不知道, 不编事实。对方发的图片/贴纸/语音你看不到内容, 就按语气自然接一句, 别装看得见。"
            "\n· 现在是 " + time.strftime("%Y年%m月%d日 %H:%M"))


def _uc_hist_load():
    global _uc_hist
    try:
        if os.path.exists(UC_HIST):
            _uc_hist = json.loads(open(UC_HIST, encoding="utf-8").read()) or {}
    except Exception:
        _uc_hist = {}


def _uc_hist_save():
    try:
        tmp = UC_HIST + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_uc_hist, f, ensure_ascii=False)
        os.replace(tmp, UC_HIST)
    except Exception:
        pass


async def _uc_ask(msgs):
    import httpx
    api = (os.getenv("DEEPSEEK_API") or os.getenv("DEEPSEEK_API_BASE")
           or "https://api.deepseek.com/v1").rstrip("/")
    key = os.getenv("DEEPSEEK_API_KEY", "")
    if not key:
        return "ERROR: 缺 DEEPSEEK_API_KEY"
    model = os.getenv("DSB_USERCHAT_MODEL", "deepseek-flash")
    async with httpx.AsyncClient(timeout=60) as c:
        r = await c.post(api + "/chat/completions",
                         headers={"Authorization": "Bearer " + key},
                         json={"model": model, "messages": msgs,
                               "temperature": 0.9, "max_tokens": 400})
        r.raise_for_status()
        j = r.json()
        return (j["choices"][0]["message"].get("content") or "").strip()


async def _uc_on_msg(client, event):
    try:
        cfg = _uc_cfg()
        if not cfg.get("on", True):
            return
        if getattr(event, "out", False):
            return
        chat_id = event.chat_id
        if chat_id == 777000:   # Telegram 官方服务号, 不回
            return
        try:
            if chat_id in set(cfg.get("ignore_ids") or []):
                return
        except Exception:
            pass
        # 群聊默认也监听回复(所有聊天都要回)。group_ids 改为「只回这些群」的可选白名单,
        # 空 = 全部群都回; 不想回的群用 ignore_ids 屏蔽。
        if getattr(event, "is_group", False):
            _wl = set(cfg.get("group_ids") or [])
            if _wl and chat_id not in _wl:
                return
        sender = await event.get_sender()
        if sender is None or getattr(sender, "bot", False):
            return
        text = (getattr(event, "raw_text", "") or "").strip()
        if not text or text.startswith("/"):
            return
        if len(text) > 600:
            text = text[:600]
        k = (chat_id, event.id)
        if k in _uc_seen:
            return
        _uc_seen.add(k)
        if len(_uc_seen) > 5000:
            _uc_seen.clear()

        # 节流: 每个会话累计有效消息数, 每凑够 _UC_REPLY_EVERY 条才回复一条, 避免消息太密刷屏。
        _n = _uc_count.get(chat_id, 0) + 1
        _uc_count[chat_id] = _n
        if _n % _UC_REPLY_EVERY != 0:
            return
        if len(_uc_count) > 500:
            _uc_count.clear()

        hist = _uc_hist.setdefault(str(chat_id), [])
        mt = int(cfg.get("max_turns", 20))
        msgs = ([{"role": "system", "content": _uc_sys()}] + hist[-mt:]
                + [{"role": "user", "content": text}])
        try:
            async with client.action(chat_id, "typing"):
                ans = await _uc_ask(msgs)
        except Exception as e:
            _log("userchat 生成失败 chat=%s: %s: %s" % (chat_id, type(e).__name__, e))
            return
        if not ans or ans.startswith("ERROR"):
            _log("userchat 空回复 chat=%s: %s" % (chat_id, str(ans)[:120]))
            return
        if ans.startswith("作为") or ans.startswith("AI"):
            ans = "哈哈，这个有意思"
        try:
            await event.reply(ans)
        except Exception as e:
            _log("userchat 发送失败 chat=%s: %s" % (chat_id, e))
            return
        hist.append({"role": "user", "content": text})
        hist.append({"role": "assistant", "content": ans})
        if len(hist) > mt * 2:
            del hist[:len(hist) - mt * 2]
        _uc_hist_save()
        _log("userchat 已回 chat=%s len=%d" % (chat_id, len(ans)))
    except Exception as e:
        _log("userchat 异常: %s: %s" % (type(e).__name__, e))


async def _uc_setup():
    """在 daemon 的 acct1 长连接上挂 NewMessage 监听"""
    if _uc_hooked.get("acct1"):
        return
    _log("userchat 准备挂监听 acct1 ...")
    try:
        c, _cfg = await asyncio.wait_for(_get_client("acct1"), timeout=60)
    except Exception as _ce:
        _log("userchat 连接超时: %s: %s" % (type(_ce).__name__, _ce))
        return
    if c is None:
        _log("userchat 未启用: acct1 未登录/连接失败(先跑 tg_user.py acct1 login)")
        return
    _uc_hist_load()

    async def _h(e):
        await _uc_on_msg(c, e)

    from telethon import events as _ev
    c.add_event_handler(_h, _ev.NewMessage(incoming=True))
    _uc_hooked["acct1"] = True
    _log("userchat 已监听 acct1 私聊")


async def handle(req):
    account = str(req.get("account", "acct1")).lower()
    act = str(req.get("act", "")).lower()
    args = req.get("args") or []
    if account not in tg_user.ACCOUNTS:
        return "未知账号 '%s'" % account
    if not act:
        return "缺少 act"
    c, cfg = await _get_client(account)
    if c is None:
        return "ERROR: 会话未授权/连接失败"
    try:
        return await asyncio.wait_for(_run_cmd(c, cfg, act, args), timeout=60)
    except asyncio.TimeoutError:
        return "TG命令超时(60s)"
    except Exception as e:
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


async def _uc_loop():
    """后台挂 userchat 监听: 不阻塞 stdin 请求循环; 连接失败/未登录时每 60s 重试"""
    while True:
        try:
            await _uc_setup()
        except Exception as _ue:
            _log("userchat setup 异常: %s: %s" % (type(_ue).__name__, _ue))
        if _uc_hooked.get("acct1"):
            return
        await asyncio.sleep(60)


async def amain():
    _log("tg_daemon 启动 pid=%s py=%s" % (os.getpid(), sys.executable))
    try:
        _srv = await asyncio.start_server(_sock_client, "127.0.0.1", 8791)
        _log("本地 socket 已监听 127.0.0.1:8791")
    except Exception as _se2:
        # 8791 已被别的 daemon 占用 → 本进程没有存在意义, 直接退出(否则会残留一个僵尸 daemon 抢 session)
        _log("socket 监听失败: %s (端口被占用, 本进程退出)" % _se2)
        return
    # userchat 挂监听放后台任务: 它内部要连 Telegram, 可能卡很久, 绝不能挡住 requests 循环
    asyncio.create_task(_uc_loop())
    loop = asyncio.get_running_loop()
    try:
        while True:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                # 2026-10-25: stdin 断开不再退出。拉起方(bot)的管道随时可能断, 一断就死会让
                # bot 每 8 秒重拉一个 daemon, 每个都来不及连 Telegram 就被 EOF 干掉。
                # 这里转为独立常驻: 继续守 8791 socket + 挂 userchat; 后续再拉起的进程会因端口被占而退出。
                _log("stdin EOF, 转为独立常驻(仅 socket + userchat)")
                await asyncio.Event().wait()
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
