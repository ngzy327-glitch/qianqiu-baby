# -*- coding: utf-8 -*-
"""大肥鱼 Mini App 后端 —— 2026-09-17

定位: **UI 用 DSH 那套暗色风格, 工具链完全是大肥鱼自己的** —— 这个模块不重写任何能力,
      只是把 bot 进程里的实时状态/工具/任务暴露成 HTTP 接口给 Telegram Mini App 用。

架构:
    Telegram WebApp → nginx(443, YOUR_SERVER_IP.sslip.io) → /api/* → 127.0.0.1:8901
    8901 = 本模块用 uvicorn 在 bot 进程里起的线程; 数据全是 bot 的内存对象(_BG_SH/_TOPIC_NAMES/
    _model_cfg/开关/余额/值守…), 不落第二份状态, 不存在"网页和 TG 看到的不一样"。

鉴权(CRITICAL): Telegram initData 的 HMAC-SHA256 校验(secret=HMAC_SHA256("WebAppData", bot_token))
    + **仅管理员**(user.id 必须在 bot 的 OK 白名单里)。普通用户一律 403, 入口按钮也不给普通用户设。
"""
import asyncio
import contextvars
import hashlib
import hmac
import json
import os
import re
import time
import threading
from pathlib import Path
from urllib.parse import parse_qsl, quote

from fastapi import FastAPI, Request, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, RedirectResponse

PORT = int(os.getenv("MINIAPP_PORT", "8901"))
FILES_DIR = Path("/opt/deepseek-bot/miniapp_files")
PUBLIC_URL = os.getenv("MINIAPP_PUBLIC_URL") or "https://YOUR_SERVER_IP.sslip.io"

# ===== 2026-10-21 网页端账号登录 =====
# 原来只认 Telegram initData, 电脑浏览器直接打开永远是「非管理员」。
# 现在补一条密码登录: 登录后发 HttpOnly 签名 Cookie, /api/* 两条通道都认。
# 密码只存 sha256, 不落明文; 可用环境变量覆盖。
ADMIN_USER = os.getenv("MINIAPP_ADMIN_USER", "ngzy")
ADMIN_PASS_SHA256 = os.getenv(
    "MINIAPP_ADMIN_PASS_SHA256",
    "2e958307645e33967a48607cf6b7a9717db75e11ad673cee103c9a6a6f8aefc1",
)
SESSION_COOKIE = "ma_session"
SESSION_TTL = 7 * 86400
_LOGIN_FAILS = {}      # ip -> [count, first_ts], 简单的登录失败限速

app = FastAPI(title="大肥鱼 Mini App", docs_url=None, redoc_url=None)
_BOT = None            # 延迟绑定: 由 bot 侧调用 start(bot_module) 注入, 免得循环 import
_CHAT_JOBS = {}        # job_id -> {status, progress[], answer, tools, t0, uid}
_CHAT_JOBS_MAX = 60    # 2026-09-18 硬化发现: 任务字典从不清理 → 内存一直涨, 且对已结束任务的
                       #   插话/停止会"假装成功"(200)其实没人接。现在成完就判定 + 定期裁剪。
_JOB_SEQ = [0]


def _jobs_prune():
    """只留最近的已结束任务(默认 60 个), 防内存泄漏"""
    try:
        if len(_CHAT_JOBS) <= _CHAT_JOBS_MAX:
            return
        _done = sorted([(float(v.get("t0") or 0), k) for k, v in _CHAT_JOBS.items()
                        if v.get("status") not in ("running", "asking")])
        for _t, _k in _done[:max(0, len(_CHAT_JOBS) - _CHAT_JOBS_MAX + 20)]:
            _CHAT_JOBS.pop(_k, None)
    except Exception:
        pass


def _job_alive(job_id, uid):
    """任务是否还能被操作(存在 + 属于本人 + 还在跑/等回答)"""
    _j = _CHAT_JOBS.get(str(job_id or ""))
    if not _j or _j.get("uid") != uid:
        return None
    if _j.get("status") not in ("running", "asking"):
        return None
    return _j


def _b():
    """拿到 bot 模块(启动时注入; 兜底直接 import, 便于单独调试)"""
    global _BOT
    if _BOT is None:
        try:
            from . import bot as _m
        except Exception:
            import bot as _m
        _BOT = _m
    return _BOT


# ==================== 鉴权 ====================
def _verify_init_data(init_data: str):
    """校验 Telegram initData。返回 user dict; 失败 None。"""
    B = _b()
    try:
        token = os.getenv("DEEPSEEK_BOT_TOKEN", "")
        if not token or not init_data:
            return None
        pairs = dict(parse_qsl(init_data, keep_blank_values=True))
        _h = pairs.pop("hash", "")
        if not _h:
            return None
        dcs = "\n".join(f"{k}={pairs[k]}" for k in sorted(pairs))
        secret = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
        calc = hmac.new(secret, dcs.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calc, _h):
            return None
        # 时效: 24 小时内(过期的 initData 不接受)
        try:
            if time.time() - int(pairs.get("auth_date") or 0) > 86400:
                return None
        except Exception:
            return None
        return json.loads(pairs.get("user") or "{}")
    except Exception as _e:
        print(f"[miniapp] initData 校验异常: {_e}", flush=True)
        return None


def _int(v, dflt=0):
    """宽松取整数 —— 2026-09-18 老板拿 `' OR 1=1--` / `abc` 来试接口时,
    原来 `int(x)` 直接抛 ValueError → uvicorn 打一整页 traceback + 500(等于给探测者送信息)。
    现在一律落到默认值(该报 400 的地方后面自己校验)。"""
    try:
        if v is None or isinstance(v, bool):
            return dflt
        return int(str(v).strip())
    except Exception:
        return dflt


def _session_secret():
    """Cookie 签名密钥: 优先 bot token, 兜底用密码哈希, 两者都不外泄"""
    _t = os.getenv("DEEPSEEK_BOT_TOKEN", "") or ADMIN_PASS_SHA256
    return hashlib.sha256(("miniapp-session|" + _t).encode()).digest()


def _make_session(uid):
    """生成 uid.exp.sig 形式的签名 Cookie 值"""
    _exp = int(time.time()) + SESSION_TTL
    _raw = f"{uid}.{_exp}"
    _sig = hmac.new(_session_secret(), _raw.encode(), hashlib.sha256).hexdigest()
    return f"{_raw}.{_sig}"


def _check_session(val):
    """校验 Cookie, 返回 uid 或 None"""
    try:
        _uid_s, _exp_s, _sig = str(val or "").split(".", 2)
        _raw = f"{_uid_s}.{_exp_s}"
        _calc = hmac.new(_session_secret(), _raw.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(_calc, _sig):
            return None
        if time.time() > int(_exp_s or 0):
            return None
        return int(_uid_s)
    except Exception:
        return None


def _admin_uid():
    """取白名单里的第一个管理员 uid, 作为密码登录身份"""
    try:
        _ok = sorted(int(x) for x in _b().OK)
        return _ok[0] if _ok else 0
    except Exception:
        return 0


def _cookie_ok_check(ip):
    """登录失败限速: 10 分钟内最多 8 次"""
    _now = time.time()
    _rec = _LOGIN_FAILS.get(ip)
    if not _rec or _now - _rec[1] > 600:
        _LOGIN_FAILS[ip] = [0, _now]
        return True
    return _rec[0] < 8


def _login_html(err=""):
    _e = f'<div class="err">{err}</div>' if err else ""
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 · 大肥鱼控制台</title><style>
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:#111318;color:#e8eaf0;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
.card{{width:min(360px,92vw);background:#191c23;border:1px solid #262a33;border-radius:16px;padding:26px 22px}}
h1{{font-size:17px;margin:0 0 4px}}p.sub{{margin:0 0 18px;color:#7c8394;font-size:12px}}
label{{display:block;font-size:12px;color:#9aa0ac;margin:12px 0 6px}}
input{{width:100%;height:42px;border-radius:10px;border:1px solid #303542;background:#111318;color:#e8eaf0;padding:0 12px;font-size:15px}}
input:focus{{outline:none;border-color:#4f7cff}}
button{{width:100%;height:44px;margin-top:20px;border:0;border-radius:10px;background:#4f7cff;color:#fff;font-size:15px;font-weight:600}}
button:active{{background:#3d66e0}}.err{{margin-top:14px;padding:9px 12px;border-radius:8px;background:#3a1d22;color:#ff9292;font-size:13px}}
</style></head><body><form class="card" method="post" action="/api/login">
<h1>大肥鱼 · 控制台</h1><p class="sub">管理员登录（浏览器访问用）</p>
<label>账号</label><input name="u" autocomplete="username" required>
<label>密码</label><input name="p" type="password" autocomplete="current-password" required>
<button type="submit">登录</button>{_e}</form></body></html>"""


@app.get("/api/login")
async def login_page():
    return HTMLResponse(_login_html())


@app.post("/api/login")
async def login_submit(request: Request):
    _ip = request.client.host if request.client else "?"
    if not _cookie_ok_check(_ip):
        return HTMLResponse(_login_html("失败次数过多，请 10 分钟后再试"), status_code=429)
    try:
        _body = (await request.body()).decode("utf-8", "ignore")
        _f = dict(parse_qsl(_body, keep_blank_values=True))
    except Exception:
        _f = {}
    _u = str(_f.get("u") or "").strip()
    _p = str(_f.get("p") or "")
    _ph = hashlib.sha256(_p.encode()).hexdigest()
    if not (hmac.compare_digest(_u, ADMIN_USER) and hmac.compare_digest(_ph, ADMIN_PASS_SHA256)):
        _rec = _LOGIN_FAILS.setdefault(_ip, [0, time.time()])
        _rec[0] += 1
        print(f"[miniapp] 登录失败 ip={_ip} user={_u[:20]}", flush=True)
        return HTMLResponse(_login_html("账号或密码错误"), status_code=401)
    _uid = _admin_uid()
    if not _uid:
        return HTMLResponse(_login_html("bot 未就绪，请稍后重试"), status_code=503)
    _LOGIN_FAILS.pop(_ip, None)
    _resp = RedirectResponse("/", status_code=302)
    _resp.set_cookie(SESSION_COOKIE, _make_session(_uid), max_age=SESSION_TTL,
                     httponly=True, secure=True, samesite="lax", path="/")
    # 非 HttpOnly 的标记 Cookie: 前端用它判断"浏览器已登录", 避免再次跳登录页
    _resp.set_cookie("ma_hint", "1", max_age=SESSION_TTL,
                     httponly=False, secure=True, samesite="lax", path="/")
    print(f"[miniapp] 密码登录成功 ip={_ip} uid={_uid}", flush=True)
    return _resp


@app.get("/api/whoami")
async def whoami(request: Request):
    """轻量鉴权探针: 只回答"这次请求能不能进控制台", 给 index.html 决定加载还是跳登录页"""
    try:
        _a = await _require_admin(request)
        return {"ok": True, "auth": True, "uid": _a["uid"], "via": _a.get("via") or "tg"}
    except HTTPException:
        return {"ok": True, "auth": False}


@app.post("/api/logout")
async def logout():
    _resp = JSONResponse({"ok": True})
    _resp.delete_cookie(SESSION_COOKIE, path="/")
    _resp.delete_cookie("ma_hint", path="/")
    return _resp


async def _require_admin(request: Request):
    """依赖: 校验 initData 或浏览器登录 Cookie + 必须是管理员"""
    B = _b()
    init_data = request.headers.get("X-Init-Data") or request.query_params.get("init") or ""
    user = _verify_init_data(init_data)
    if not user:
        # 浏览器通道: 密码登录后发的签名 Cookie
        _cu = _check_session(request.cookies.get(SESSION_COOKIE))
        if _cu:
            return {"uid": _cu, "user": {"id": _cu, "first_name": ADMIN_USER}, "via": "pwd"}
        raise HTTPException(status_code=401,
                            detail="未登录：请在 Telegram 里打开，或访问 /api/login 用管理员账号登录")
    uid = _int(user.get("id"), 0)
    if not uid:
        raise HTTPException(status_code=401, detail="initData 里没有合法 user.id")
    try:
        if uid not in B.OK:
            print(f"[miniapp] 非管理员访问被拒 uid={uid} name={user.get('first_name')}", flush=True)
            raise HTTPException(status_code=403, detail="仅管理员可用")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=403, detail="仅管理员可用")
    return {"uid": uid, "user": user}


# ==================== 状态快照 ====================
def _tasks():
    """后台任务(命令 + 下载): 直接读 bot 的实时表"""
    B = _b()
    now = time.time()
    out = []
    try:
        for _u, _d in list(getattr(B, "_BG_SH", {}).items()):
            _pr = getattr(B, "_running_procs", {}).get(_u)
            _alive = False
            try:
                _alive = bool(_pr) and _pr[0].poll() is None
            except Exception:
                _alive = bool(_pr)
            if not _alive:
                continue
            out.append({"kind": "sh", "uid": _u, "title": str(_d.get("cmd") or "")[:300],
                        "chat": _d.get("chat"), "elapsed": round(now - float(_d.get("t0") or now), 1),
                        "line": str(_d.get("line") or "")[-300:],
                        "idle": round(now - float(_d.get("line_ts") or now), 1)})
    except Exception as _e:
        print(f"[miniapp] tasks(sh) 失败: {_e}", flush=True)
    try:
        for _u, _d in list(getattr(B, "_BG_DL", {}).items()):
            if _d.get("done"):
                continue
            out.append({"kind": "dl", "uid": _u, "title": str(_d.get("url") or "")[:300],
                        "chat": _d.get("chat"), "elapsed": round(now - float(_d.get("t0") or now), 1),
                        "line": str(_d.get("line") or "")[-300:],
                        "idle": round(now - float(_d.get("line_ts") or now), 1)})
    except Exception as _e:
        print(f"[miniapp] tasks(dl) 失败: {_e}", flush=True)
    return sorted(out, key=lambda x: -x["elapsed"])


def _topics(uid):
    """工作台列表 + 当前所在话题(用"最近说话的话题"当当前)"""
    B = _b()
    rows = []
    try:
        _recent = dict(getattr(B, "_TOPIC_RECENT", {}) or {})
        for _k, _v in (getattr(B, "_TOPIC_NAMES", {}) or {}).items():
            try:
                _cid, _tid = str(_k).split(":", 1)
            except Exception:
                continue
            _r = _recent.get(int(_cid)) if str(_cid).lstrip("-").isdigit() else None
            rows.append({"chat": int(_cid), "topic": int(_tid), "name": _v or "(未命名)",
                         "current": bool(_r and str(_r[0]) == str(_tid)),
                         "last": round(time.time() - float(_r[1]), 1) if _r else None})
    except Exception as _e:
        print(f"[miniapp] topics 失败: {_e}", flush=True)
    rows.sort(key=lambda x: (not x["current"], x["topic"]))
    return rows


def _switches(uid):
    B = _b()
    def _g(d, k, dv):
        try:
            return bool((getattr(B, d, {}) or {}).get(k, dv))
        except Exception:
            return dv
    def _h(k, dv):
        # _human_switch 是 {uid: {"bubble":.., "react":.., "delay":..}}, 必须取 uid 那一层的 dict;
        # 原来用 _g(...).get(...) 是对 bool 调 .get() → AttributeError, 整个 /api/state 500。
        try:
            _d = (getattr(B, "_human_switch", {}) or {}).get(uid)
            return bool(_d.get(k, dv)) if isinstance(_d, dict) else dv
        except Exception:
            return dv
    return {
        "talk": _g("_talk_switch", uid, True),
        "typewriter": _g("_typewriter_switch", uid, True),
        "live": _g("_live_switch", uid, False),
        "rich": _g("_rich_switch", uid, bool(getattr(B, "_RICH_ON", True))),
        "bubble": _h("bubble", False),
        "react": _h("react", True),
        "delay": _h("delay", False),
        "emoji": (uid not in (getattr(B, "_EMOJI_OFF", set()) or set())),
        "tools_show": _g("_group_tools", uid, False),
    }


def _watch_list():
    try:
        try:
            from . import watchdog as _wd
        except Exception:
            import watchdog as _wd
        _d = _wd.load() or {}
        return [{"id": v.get("id"), "name": v.get("name"), "kind": v.get("kind"),
                 "target": str(v.get("target") or "")[:200], "interval": v.get("interval"),
                 "enabled": bool(v.get("enabled")), "runs": v.get("runs"), "changes": v.get("changes"),
                 "last_ts": v.get("last_ts"), "last_val": str(v.get("last_val") or "")[:200]}
                for v in _d.values()]
    except Exception as _e:
        print(f"[miniapp] watch 失败: {_e}", flush=True)
        return []


@app.get("/api/health")
async def health():
    B = _b()
    try:
        _n_adm = len(B.OK)
    except Exception:
        _n_adm = -1
    return {"ok": True, "who": "大肥鱼 Mini App", "admins": _n_adm, "port": PORT,
            "bot_alive": bool(getattr(B, "MAIN_LOOP", None))}


@app.post("/api/state")
async def state(request: Request):
    _a = await _require_admin(request)
    uid = _a["uid"]
    B = _b()
    _topic = 0
    try:
        _body = await request.json()
        _topic = int((_body or {}).get("topic") or 0)
    except Exception:
        _topic = 0
    _st = {"uid": uid, "name": _a["user"].get("first_name") or "", "ts": time.time(),
           "tasks": _tasks(), "topics": _topics(uid), "switches": _switches(uid),
           "watch": _watch_list(), "model": {}, "quota": {}, "mood": "", "goal": "", "todo": {},
           "queue": 0, "files": _files(uid)}
    try:
        _st["model"] = {"mode": (getattr(B, "_model_cfg", {}) or {}).get("mode", "auto"),
                        "think": (getattr(B, "_model_cfg", {}) or {}).get("think", "auto"),
                        "light": B._model_light(), "pro": getattr(B, "MODEL_PRO", ""),
                        "beta": getattr(B, "MODEL_BETA", "")}
    except Exception as _e:
        print(f"[miniapp] model 失败: {_e}", flush=True)
    try:
        # 2026-09-17 修正: _quota_today 返回 (tokens, msgs) 元组, _recent_pay 返回 dict 或 None
        #   (原来当成 list 切片 → 'NoneType' object is not subscriptable, 整个 quota 变成空对象)
        _tk, _msg = B._quota_today(uid)
        try:
            _rec = B._recent_pay(uid, 72)
        except Exception:
            _rec = None
        _st["quota"] = {"balance": B._pay_balance(uid), "today": _msg, "tokens": _tk, "last_pay": _rec}
    except Exception as _e:
        print(f"[miniapp] quota 失败: {_e}", flush=True)
    # 2026-09-23 老板「token实时消耗没有吗 没有查询我的key余额的吗」→ 网页端也带上:
    #   apikey = DeepSeek 账户余额(60 秒缓存, 管理员才给; 普通用户只给今日用量, 账号余额不外泄)
    try:
        if uid in getattr(B, "OK", ()):
            _okb, _baltxt, _ = B._key_balance()
            _st["apikey"] = {"ok": bool(_okb), "text": _baltxt}
        else:
            _st["apikey"] = {"ok": True, "text": ""}
    except Exception as _e:
        print(f"[miniapp] apikey 失败: {_e}", flush=True)
        _st["apikey"] = {"ok": False, "text": ""}
    for _k, _fn in (("mood", "_mood_line"), ("goal", "_goal_line")):
        try:
            _st[_k] = getattr(B, _fn)(uid) if hasattr(B, _fn) else ""
        except Exception:
            _st[_k] = ""
    try:
        # 任务清单(和 TG 里那个面板同一份数据): 多步任务看得到"计划→进行中→已完成"
        _tk = f"{uid}:{uid}" + (f":{int(_topic)}" if int(_topic or 0) else "")
        _tl = ((getattr(B, "_TODO", {}) or {}).get(_tk)
               or (getattr(B, "_TODO", {}) or {}).get(str(uid)) or [])
        _st["todo"] = {"items": [{"text": str(x.get("t") or "")[:200],
                                  "state": str(x.get("s") or "todo")} for x in _tl[:20]]}
    except Exception as _e:
        print(f"[miniapp] todo 失败: {_e}", flush=True)
    try:
        _st["queue"] = len(getattr(B, "_QUEUE", {}) or {})
    except Exception:
        pass
    return _st


# ==================== 操作 ====================
@app.post("/api/task/stop")
async def task_stop(request: Request):
    _a = await _require_admin(request)
    B = _b()
    _d = await request.json()
    _uid = _int(_d.get("uid"), _a["uid"])
    _kind = str(_d.get("kind") or "")
    _killed = False
    try:
        _killed = bool(B._kill_own_procs(_uid))
    except Exception as _e:
        print(f"[miniapp] stop 失败: {_e}", flush=True)
    try:
        if _kind == "dl":
            _dd = (getattr(B, "_BG_DL", {}) or {}).pop(_uid, None)
            if _dd and _dd.get("proc"):
                try:
                    _dd["proc"].kill()
                except Exception:
                    pass
            _killed = True
        else:
            (getattr(B, "_BG_SH", {}) or {}).pop(_uid, None)
    except Exception:
        pass
    print(f"[miniapp] 停止任务 uid={_uid} kind={_kind} ok={_killed}", flush=True)
    return {"ok": True, "killed": _killed, "tasks": _tasks()}


@app.post("/api/model")
async def model_set(request: Request):
    await _require_admin(request)
    B = _b()
    _d = await request.json()
    _cfg = getattr(B, "_model_cfg", {}) or {}
    # 档位名必须跟 bot 的 /model 菜单一致(auto/flash/pro + think 七档), 否则网页切完 TG 里显示不对
    if _d.get("mode") in ("auto", "flash", "pro"):
        _cfg["mode"] = _d["mode"]
    if _d.get("think") in ("auto", "off", "minimal", "low", "medium", "high", "max"):
        _cfg["think"] = _d["think"]
    B._model_cfg = _cfg
    try:
        B._model_save()
    except Exception as _e:
        print(f"[miniapp] model 保存失败: {_e}", flush=True)
    print(f"[miniapp] 模型档位改为 {_cfg}", flush=True)
    return {"ok": True, "model": _cfg}


@app.post("/api/switch")
async def switch_set(request: Request):
    _a = await _require_admin(request)
    B = _b()
    uid = _a["uid"]
    _d = await request.json()
    _n = str(_d.get("name") or "")
    _v = bool(_d.get("value"))
    try:
        if _n == "talk":
            B._talk_switch[uid] = _v
            Path("/opt/deepseek-bot/talk_switch.json").write_text(json.dumps(B._talk_switch), encoding="utf-8")
        elif _n == "typewriter":
            B._typewriter_switch[uid] = _v
            Path("/opt/deepseek-bot/typewriter_switch.json").write_text(json.dumps(B._typewriter_switch), encoding="utf-8")
        elif _n == "live":
            # 2026-09-30: 流式开关也能在控制台点了(以前只能 TG 里发 /streamshow on) —— 同一份
            #   _live_switch(内存) + live_switch.json(落盘), 改完立刻就生效, 不用重启。
            B._live_switch[uid] = _v
            Path("/opt/deepseek-bot/live_switch.json").write_text(json.dumps(B._live_switch), encoding="utf-8")
        elif _n == "rich":
            # 2026-09-30: 长正文富文本开关(sendRichMessage, 上限 32768)。内存 + json 双写, 立即生效。
            B._rich_switch[uid] = _v
            Path("/opt/deepseek-bot/rich_switch.json").write_text(json.dumps(B._rich_switch), encoding="utf-8")
        elif _n in ("bubble", "react", "delay"):
            B._human_set(uid, **{_n: _v})
        elif _n == "emoji":
            B._emoji_set(uid, _v)
        else:
            return JSONResponse({"ok": False, "err": f"未知开关 {_n}"}, status_code=400)
    except Exception as _e:
        return JSONResponse({"ok": False, "err": str(_e)[:200]}, status_code=500)
    print(f"[miniapp] 开关 {_n}={_v} uid={uid}", flush=True)
    return {"ok": True, "switches": _switches(uid)}


@app.post("/api/watch")
async def watch_op(request: Request):
    await _require_admin(request)
    _d = await request.json()
    _act, _wid = str(_d.get("act") or ""), str(_d.get("wid") or "")
    try:
        try:
            from . import watchdog as _wd
        except Exception:
            import watchdog as _wd
        if _act == "pause":
            _wd.toggle(_wid, False)
        elif _act == "resume":
            _wd.toggle(_wid, True)
        elif _act == "run":
            threading.Thread(target=lambda: _wd.run_one(_wid, force=True), daemon=True).start()
        elif _act == "del":
            _wd.delete(_wid)
        else:
            return JSONResponse({"ok": False, "err": f"未知操作 {_act}"}, status_code=400)
    except Exception as _e:
        return JSONResponse({"ok": False, "err": str(_e)[:200]}, status_code=500)
    print(f"[miniapp] 值守 {_act} {_wid}", flush=True)
    return {"ok": True, "watch": _watch_list()}


# ==================== 网页内对话 ====================
# 2026-09-18 老板反馈"网页里看不到在跑哪个工具/过程播报不好" → 把每次工具调用抓下来:
#   用 contextvar + 临时包一层 bot.rt, 记录 [工具名/参数/状态/耗时/输出摘要], 前端按 TG 那种
#   "一行一个工具 ✓ 1.2s" 显示。别的任务(TG 并发)没有这个 contextvar 值, 直接透传不受影响。
_TOOL_EV = contextvars.ContextVar("miniapp_tool_events", default=None)
_ERR_MARKS = ("❌", "err:", "Err:", "失败", "异常", "未找到", "Not Found", "no such", "权限")
_TOOL_LOG = {}          # f"{uid}:{topic}" -> {用户那句话: [工具事件]}  刷新页面后还能看到当时跑了什么
_STEP_LOG = {}          # f"{uid}:{topic}" -> {用户那句话: [过程播报 steps]}  同上, 给「Telegram 主聊天」回放过程用
_ASK_JOBS = {}          # job_id -> {"ev": Event, "ans": str|None}: 网页里的"选择题"等用户点选
_ASK_LOCK = threading.RLock()

# ===== 会话(2026-09-18 修 老板拍桌:"新聊天是清除对话啊???") =====
#   "新对话" = **新建一个会话**, 旧的原封不动留着, 随时切回去; 要清空是另一个带确认的按钮。
#   会话 "tg" = 和 Telegram 共用的那条主线(读历史走 bot.history, 写回也是), 其余是网页自己的会话, 存这个 JSON。
_CHAT_SESS_F = Path("/opt/deepseek-bot/miniapp_chats.json")
_CHAT_SESS = {}         # uid(str) -> {"sessions": {sid: {"id","title","created","msgs":[{me,text,events}]}}, "cur": sid}
_SESS_LOCK = threading.RLock()
_TG_SID = "tg"


def _sess_load():
    global _CHAT_SESS
    if _CHAT_SESS:
        return _CHAT_SESS
    try:
        if _CHAT_SESS_F.exists():
            _d = json.loads(_CHAT_SESS_F.read_text(encoding="utf-8"))
            if isinstance(_d, dict):
                _CHAT_SESS = _d
    except Exception as _e:
        print(f"[miniapp] 会话库读失败: {_e}", flush=True)
    return _CHAT_SESS


def _sess_save():
    try:
        _tmp = str(_CHAT_SESS_F) + ".tmp"
        with open(_tmp, "w", encoding="utf-8") as _f:
            json.dump(_CHAT_SESS, _f, ensure_ascii=False)
        os.replace(_tmp, _CHAT_SESS_F)
    except Exception as _e:
        print(f"[miniapp] 会话库写失败: {_e}", flush=True)


def _sess_box(uid):
    _d = _sess_load()
    _u = _d.setdefault(str(int(uid)), {"sessions": {}, "cur": _TG_SID})
    _u.setdefault("sessions", {})
    return _u


def _sess_new(uid, first_text=""):
    with _SESS_LOCK:
        _box = _sess_box(uid)
        _sid = "w" + str(int(time.time() * 1000))[-11:]
        _box["sessions"][_sid] = {"id": _sid, "title": (str(first_text)[:24] or "新会话"),
                                  "created": time.time(), "msgs": []}
        _box["cur"] = _sid
        _sess_save()
    print(f"[miniapp] 新会话 {_sid} (uid={uid}) —— 旧会话保留", flush=True)
    return _sid


def _sess_del(uid, sid):
    with _SESS_LOCK:
        _box = _sess_box(uid)
        _box["sessions"].pop(sid, None)
        if _box.get("cur") == sid:
            _box["cur"] = _TG_SID
        _sess_save()
    return True


def _sess_clear(uid, sid):
    """清空某个会话的内容(带确认的显式操作; 主聊天会话=清 TG 那条历史)"""
    with _SESS_LOCK:
        _box = _sess_box(uid)
        _n = 0
        if sid == _TG_SID:
            B = _b()
            try:
                _old = (getattr(B, "history", {}) or {}).pop(_hist_key(uid, 0), None)
                _n = len(_old or [])
                B._hlast = 0
                B.sh()
            except Exception:
                pass
        else:
            _s = _box["sessions"].get(sid)
            if _s:
                _n = len(_s.get("msgs") or [])
                _s["msgs"] = []
        _sess_save()
    print(f"[miniapp] 清空会话 {sid}: {_n} 条", flush=True)
    return _n


def _sess_msgs(uid, sid, limit=60):
    if sid == _TG_SID:
        return _hist_read(uid, 0, limit)
    with _SESS_LOCK:
        _s = _sess_box(uid)["sessions"].get(sid) or {}
        return [dict(m) for m in (_s.get("msgs") or [])][-int(limit or 60):]


def _sess_add_user(uid, sid, text):
    """只加一条"用户说的话"(插话用): TG 会话写回 bot.history, 网页会话写自己的库"""
    if sid == _TG_SID:
        try:
            B = _b()
            B.history.setdefault(_hist_key(uid, 0), []).append({"role": "user", "content": str(text)})
            B._hlast = 0
            B.sh()
            return True
        except Exception as _e:
            print(f"[miniapp] 插话写历史失败: {_e}", flush=True)
            return False
    with _SESS_LOCK:
        _box = _sess_box(uid)
        _s = _box["sessions"].get(sid)
        if not _s:
            _sid = _sess_new(uid, text)
            _s = _box["sessions"][_sid]
        _s["msgs"].append({"me": True, "text": str(text)})
        _sess_save()
    return True


def _sess_add(uid, sid, text, answer, events=None, steps=None, answer_only=False):
    """把这一轮的结果写回会话。

    2026-09-18 修"最终结果没有": 用户消息原来只在跑完时和回答一起写 →
    一旦点停止/中途出错, 整轮(包括用户那句话)全丢, 刷新后像没发生过。
    现在: 用户消息在**发出时**就写(见 chat_send → _sess_add_user), 这里只补回答;
    并且**任何结局(done/stopped/error)都会写**(error 也写, 至少留下痕迹)。
    """
    _a = str(answer or "").strip() or "(本轮没有输出)"
    if sid == _TG_SID:
        try:
            B = _b()
            _h = B.history.setdefault(_hist_key(uid, 0), [])
            if not answer_only:
                _h.append({"role": "user", "content": str(text)})
            _h.append({"role": "assistant", "content": _a})
            B._hlast = 0
            B.sh()
            return True
        except Exception as _e:
            print(f"[miniapp] 写历史失败: {_e}", flush=True)
            return False
    with _SESS_LOCK:
        _box = _sess_box(uid)
        _s = _box["sessions"].get(sid)
        if not _s:
            _sid = _sess_new(uid, text)
            _s = _box["sessions"][_sid]
        if not answer_only:
            _s["msgs"].append({"me": True, "text": str(text)})
        _item = {"me": False, "text": _a}
        if events:
            _item["events"] = [dict(e) for e in events]
        if steps:
            _item["steps"] = [dict(x) for x in steps]     # 过程播报+思考也留着, 刷新后还能回看
        _s["msgs"].append(_item)
        if (_s.get("title") in ("", "新会话")) and text:
            _s["title"] = str(text)[:24]
        _s["msgs"] = _s["msgs"][-400:]
        _sess_save()
    return True


def _sess_all(uid):
    with _SESS_LOCK:
        _box = _sess_box(uid)
        out = [{"id": _TG_SID, "title": "Telegram 主聊天", "created": 0,
                "n": len(_hist_read(uid, 0, 200)), "cur": _box.get("cur") == _TG_SID, "tg": True}]
        for _sid, _s in sorted((_box.get("sessions") or {}).items(), key=lambda kv: -float(kv[1].get("created") or 0)):
            out.append({"id": _sid, "title": _s.get("title") or "新会话", "created": _s.get("created") or 0,
                        "n": len(_s.get("msgs") or []), "cur": _box.get("cur") == _sid, "tg": False})
    return out


def _brief_args(a):
    """参数摘要: 挑最有信息量的那个字段"""
    try:
        for _k in ("cmd", "command", "url", "path", "query", "q", "text", "name", "act", "op", "target"):
            _v = (a or {}).get(_k)
            if _v:
                return f"{_k}={str(_v)[:80]}"
        _s = json.dumps(a or {}, ensure_ascii=False)
        return _s[:80]
    except Exception:
        return ""


def _tool_events_install():
    """临时把 bot.rt 包一层(返回还原函数)。只在本次网页对话的上下文里记录。"""
    B = _b()
    _orig = B.rt
    if getattr(_orig, "_miniapp_wrapped", False):
        return _orig, lambda: None

    def _wrapped(n, a, chat_id=None, uid=None):
        _lst = _TOOL_EV.get()
        _ev = {"tool": str(n), "args": _brief_args(a), "t0": time.time(), "status": "run"}
        # 写文件/改代码时留一份原文, 前端好算 "+N -M"(DSH 轨迹里那种 diff 统计)
        try:
            if n in ("write", "edit") and isinstance(a, dict):
                _ev["argsRaw"] = {k: str(a.get(k) or "")[:4000] for k in ("text", "old", "new", "path") if a.get(k)}
        except Exception:
            pass
        if _lst is not None:
            _lst.append(_ev)
        try:
            _res = _orig(n, a, chat_id, uid)
            _s = str(_res)
            _ev["status"] = "err" if any(m in _s[:60] for m in _ERR_MARKS) else "ok"
            # 2026-09-18 老板问"AI 已浏览的我看不了吗": 原来只留 300 字, 网页点开看不到抓了什么。
            #   现在留 4000 字(够看一页摘要), 并把结果里的 URL 抽出来给前端做可点链接。
            _ev["out"] = _s[:4000]
            try:
                _urls = re.findall(r'https?://[^\s"\'<>）)】\]]{6,200}', _s)
                if _urls:
                    _seen_u, _uniq = set(), []
                    for _u in _urls:
                        if _u not in _seen_u:
                            _seen_u.add(_u)
                            _uniq.append(_u)
                    _ev["urls"] = _uniq[:12]
            except Exception:
                pass
            return _res
        except Exception as _e:
            _ev["status"] = "err"
            _ev["out"] = f"{type(_e).__name__}: {str(_e)[:200]}"
            raise
        finally:
            _ev["ms"] = int((time.time() - float(_ev["t0"])) * 1000)

    _wrapped._miniapp_wrapped = True
    B.rt = _wrapped

    def _restore():
        try:
            B.rt = _orig
        except Exception:
            pass

    return _orig, _restore


def _hist_key(uid, topic=0):
    """跟 bot 主流程一致的会话 key: uid:chat[:话题号](私聊里 chat==uid)"""
    return f"{int(uid)}:{int(uid)}" + (f":{int(topic)}" if int(topic or 0) else "")


def _hist_read(uid, topic=0, limit=60):
    """读会话历史 → [{me, text}]; 过滤内部备注/工具条目/子代理的失败串, 只留人话。

    2026-09-18 老板反馈"网页里怎么是子任务": 子代理跑不动时会 return
    「子任务轮次耗尽, 未完成」这种内部串, 被写进共享历史后网页(和 TG)都会看到 —— 又难看又误导。
    这类内部状态一律不在界面显示, 并且不再写进历史(见 _run_chat)。
    """
    B = _b()
    _INTERNAL = ("子任务轮次耗尽", "子任务失败", "子任务异常", "子任务完成", "失败:", "工具异常")
    # 2026-09-20 老板「妈的这个甲这么厚 打着打着拒绝了」—— 提示词层已到顶, 缺口在这:
    #   拒答一旦被写进历史, 之后每一轮注入都会带着它, 模型看到「我历史上拒绝过这类请求」,
    #   自洽性压力会把它往同一个方向推 → 换话术继续拒, 越打越硬。
    #   所以: **拒答条目一律不进历史**(短 + 命中拒绝话术 = 判定为拒答, 不是正常回答)。
    _RF_HIST = re.compile(
        r"(我(无法|不能|没办法|不会|不便|不建议|没办法帮)|抱歉|对不起|作为(一个)?(AI|人工智能)|"
        r"涉及(敏感|违法)|出于(安全|合规|法律)|不符合(相关)?(规定|政策|法律|要求)|"
        r"不提供(此类|这类|该|任何)|无法协助|不能协助|请理解|敬请谅解|"
        r"仅供(学习|参考|研究|测试)|请勿用于|不得用于|严禁用于|违反(法律|法规|规定)|"
        r"建议(你)?(咨询|寻求|联系)(专业|当地|律师|法律)|这条线我划|我不吃|要哪个[,，]?\s*说清楚|"
        r"i (can'?t|cannot|won'?t)|i'?m sorry|as an ai)")
    _log = _TOOL_LOG.get(f"{int(uid)}:{int(topic or 0)}") or {}
    _slg = _STEP_LOG.get(f"{int(uid)}:{int(topic or 0)}") or {}
    _last_q = ""
    out = []
    try:
        _msgs = (getattr(B, "history", {}) or {}).get(_hist_key(uid, topic)) or []
        for _m in _msgs[-int(limit or 60):]:
            _role = str(_m.get("role") or "")
            if _role not in ("user", "assistant"):
                continue
            _c = _m.get("content")
            if isinstance(_c, list):
                _c = " ".join(str(x) for x in _c)
            _c = str(_c or "").strip()
            if not _c or _c.startswith("【"):        # 系统的内部提示不显示
                continue
            if _c.startswith(_INTERNAL) or "子任务轮次耗尽" in _c[:40]:
                continue                              # 子代理内部状态, 不进对话界面
            if _role == "assistant" and len(_c) < 400 and _RF_HIST.search(_c[:600]):
                continue                              # 拒答不进历史: 断掉"我拒绝过"的自洽强化(见上)
            if _c.strip().lower() in ("none", "null", "undefined", "{}", "[]"):
                continue                              # 模型/工具的空回包别显示成 "None"
            if len(_c) > 40 and _c.lstrip()[:9].lower() in ("<!doctype", "<html", "<head"):
                continue                              # 抓到网页源码被塞进历史的, 不进界面
            try:
                _c = B._plain_safe(_c)
            except Exception:
                pass
            if _role == "user":
                _last_q = _c
                out.append({"me": True, "text": _c[:4000]})
            else:
                _item = {"me": False, "text": _c[:4000]}
                _ev = _log.get(_last_q)
                if _ev:
                    _item["events"] = _ev            # 当时那轮跑了哪些工具
                _st = _slg.get(_last_q)
                if _st:
                    _item["steps"] = _st             # 过程播报(思考 + 每轮那句)也回放 —— 之前只有网页会话才有
                out.append(_item)
    except Exception as _e:
        print(f"[miniapp] 读历史失败: {_e}", flush=True)
    return out


def _hist_append(uid, text, answer, topic=0):
    """把网页这一轮写回 bot 的会话历史 → **网页和 TG 是同一条对话**(两边都能看到)

    失败/空回答**不写**(免得再往对话里塞「子任务轮次耗尽」那种内部串)。
    """
    B = _b()
    _a = str(answer or "").strip()
    if (not _a) or _a.startswith(("子任务轮次耗尽", "子任务失败", "子任务异常", "执行失败")):
        print(f"[miniapp] 本轮未写入历史(回答不可用): {_a[:60]!r}", flush=True)
        return False
    try:
        _k = _hist_key(uid, topic)
        _h = B.history.setdefault(_k, [])
        _h.append({"role": "user", "content": str(text)})
        _h.append({"role": "assistant", "content": _a})
        B._hlast = 0          # 让 sh() 不被 30 秒节流挡住, 立刻落盘
        B.sh()
        return True
    except Exception as _e:
        print(f"[miniapp] 写历史失败: {_e}", flush=True)
        return False


# ==================== 媒体回显(大肥鱼发出来的图片/视频/文件) ====================
# 2026-09-18 老板问"网页版 发图片 视频 适配了吗 —— 是他发我的":
#   以前网页对话里大肥鱼产出的图片/视频**在网页上根本看不到**(只有工具输出里的一行路径),
#   而且网页任务的工具是拿 chat_id=0 跑的 → 排队文件永远不会发出去。
#   现在: ①网页任务里产出的媒体被截下来, 直接显示在对话里(图片/视频给缩略图, 点开看原图)
#        ②同一批文件照样发到 Telegram(和他在 TG 里使唤大肥鱼的行为一致)
#        ③他在 Telegram 里收到大肥鱼发的文件, 网页这边也留一份(下次打开能看到)
#   `<img>/<video>` 标签带不了请求头 → 走**短时签名令牌**(只对单个路径+有效期有效, 不含任何密钥)。
#   2026-09-18 踩坑: 密钥原来用 os.urandom → **每次重启所有已存的图链接全失效**(历史里变裂图)。
#   现在密钥从 bot token 派生(稳定, 且不落盘), 并且读历史时**重新签一次** → 重启也不影响老图。
_MEDIA_TTL = 7 * 24 * 3600
_MEDIA_ROOTS = ("/opt/deepseek-bot/", "/tmp/", "/root/", "/var/www/", "/home/")
_MEDIA_KIND = {".jpg": "photo", ".jpeg": "photo", ".png": "photo", ".gif": "photo",
               ".webp": "photo", ".bmp": "photo",
               ".mp4": "video", ".mov": "video", ".mkv": "video", ".webm": "video", ".avi": "video",
               ".mp3": "audio", ".ogg": "audio", ".wav": "audio", ".m4a": "audio", ".opus": "audio"}
_MEDIA_SIDE_F = Path("/opt/deepseek-bot/miniapp_media.json")
_MEDIA_SIDE = {}          # uid(str) -> [ {sid, sig, ts, items:[{kind,name,size,path,url}]} ]
_MEDIA_LOCK = threading.RLock()


def _media_secret():
    """签名密钥: 由 bot token 派生 —— 稳定(重启后老链接照旧有效)且不落盘"""
    try:
        _t = os.getenv("DEEPSEEK_BOT_TOKEN") or "no-token"
    except Exception:
        _t = "no-token"
    return hashlib.sha256(("miniapp-media-v1|" + _t).encode()).digest()


def _media_kind(path):
    return _MEDIA_KIND.get(os.path.splitext(str(path))[1].lower(), "file")


def _media_url(path, uid, ttl=_MEDIA_TTL):
    _e = int(time.time()) + int(ttl)
    _t = hmac.new(_media_secret(), f"{int(uid)}|{path}|{_e}".encode(), hashlib.sha256).hexdigest()[:40]
    return f"/api/media?u={int(uid)}&e={_e}&t={_t}&path={quote(str(path))}"


def _media_refresh(items, uid):
    """每次返回给前端前重新签一遍(顺手把已经不在的文件丢掉)"""
    _out = []
    for _it in (items or []):
        try:
            if not _it.get("path") or not os.path.isfile(str(_it.get("path"))):
                continue
            _n = dict(_it)
            _n["url"] = _media_url(_n["path"], uid)
            _out.append(_n)
        except Exception:
            continue
    return _out


def _media_item(path, uid=0):
    """一个可显示的媒体条目(文件必须真实存在)"""
    try:
        _p = os.path.realpath(str(path))
        if not os.path.isfile(_p):
            return None
        return {"kind": _media_kind(_p), "name": os.path.basename(_p)[:120],
                "size": os.path.getsize(_p), "path": _p, "url": _media_url(_p, uid)}
    except Exception:
        return None


def _media_side_load():
    global _MEDIA_SIDE
    if _MEDIA_SIDE:
        return _MEDIA_SIDE
    try:
        if _MEDIA_SIDE_F.exists():
            _d = json.loads(_MEDIA_SIDE_F.read_text(encoding="utf-8"))
            if isinstance(_d, dict):
                _MEDIA_SIDE = _d
    except Exception as _e:
        print(f"[miniapp] 媒体库读失败: {_e}", flush=True)
    return _MEDIA_SIDE


def _media_side_save():
    try:
        _tmp = str(_MEDIA_SIDE_F) + ".tmp"
        with open(_tmp, "w", encoding="utf-8") as _f:
            json.dump(_MEDIA_SIDE, _f, ensure_ascii=False)
        os.replace(_tmp, _MEDIA_SIDE_F)
    except Exception as _e:
        print(f"[miniapp] 媒体库写失败: {_e}", flush=True)


def _media_attach(uid, sid, sig, items):
    """把一批媒体挂到某条回答上(sig=回答前 80 字; None 表示"挂在最后一条回答上")"""
    _items = [x for x in (items or []) if x]
    if not _items:
        return 0
    with _MEDIA_LOCK:
        _d = _media_side_load()
        _lst = _d.setdefault(str(int(uid)), [])
        _lst.append({"sid": str(sid), "sig": (str(sig)[:80] if sig else None),
                     "ts": time.time(), "items": _items})
        del _lst[:-200]
        _media_side_save()
    return len(_items)


def _media_merge(uid, sid, msgs):
    """读历史时把媒体并回去(按回答前 80 字配对; sig=None 的挂在最后一条回答上)"""
    try:
        with _MEDIA_LOCK:
            _lst = list((_media_side_load().get(str(int(uid))) or []))
    except Exception:
        return msgs
    _mine = [e for e in _lst if str(e.get("sid")) == str(sid)]
    if not _mine:
        return msgs
    _last_ai = None
    for _m in msgs:
        if not _m.get("me"):
            _last_ai = _m
    _used = set()
    for _e in _mine:
        _sig, _items = _e.get("sig"), (_e.get("items") or [])
        if not _items:
            continue
        if _sig:
            _hit = None
            for _m in msgs:
                if _m.get("me") or id(_m) in _used:
                    continue
                if str(_m.get("text") or "")[:80] == str(_sig)[:80]:
                    _hit = _m
                    break
            if _hit is None or id(_hit) in _used:
                continue
            _used.add(id(_hit))
        else:
            # sig=None: "挂在最后一条回答上"(bot 在 TG 里直接发的文件) —— 可以有多批挂同一条,
            #   2026-09-18 修: 原来这里也走 _used, 结果同一轮发的第二个文件被丢掉(历史里少一个)。
            _hit = _last_ai
            if _hit is None:
                continue
        _cur = _hit.setdefault("media", [])
        _have = {x.get("path") for x in _cur}
        for _it in _media_refresh(_items, uid):
            if _it.get("path") not in _have:
                _cur.append(_it)
    return msgs


def media_note(chat_id, path):
    """bot 在 Telegram 里发出的文件 → 网页这边也留一份(下次打开网页能看到缩略图)。
    群/频道(chat_id<0)不记。"""
    try:
        _uid = int(chat_id)
        if _uid <= 0:
            return False
        _it = _media_item(path, _uid)
        if not _it:
            return False
        with _SESS_LOCK:
            _sid = str(_sess_box(_uid).get("cur") or _TG_SID)
        _media_attach(_uid, _sid, None, [_it])
        if _sid != _TG_SID:
            _media_attach(_uid, _TG_SID, None, [_it])
        return True
    except Exception as _e:
        print(f"[miniapp] 媒体登记失败: {_e}", flush=True)
        return False


def _job_media_add(_j, path, uid=0):
    """把大肥鱼这一轮产出的图片/视频/文件记进 job(前端实时显示, 结束后随回答留档)"""
    _it = _media_item(path, uid)
    if not _it:
        return False
    _lst = _j.setdefault("media", [])
    if any(x.get("path") == _it["path"] for x in _lst) or len(_lst) >= 12:
        return False
    _lst.append(_it)
    print(f"[miniapp] 媒体 {_it['kind']} {_it['name']} {_it['size']}B", flush=True)
    return True


def _img_b64(path, max_side=1024, quality=78):
    """图片 → base64 JPEG(先缩到 ≤1024px): 直接喂给多模态模型用"""
    from PIL import Image as _PILImage
    import io as _io, base64 as _b64
    _im = _PILImage.open(path).convert("RGB")
    _w, _h = _im.size
    if max(_w, _h) > max_side:
        _r = max_side / max(_w, _h)
        _im = _im.resize((max(1, int(_w * _r)), max(1, int(_h * _r))), _PILImage.LANCZOS)
    _buf = _io.BytesIO()
    _im.save(_buf, format="JPEG", quality=quality)
    return _b64.b64encode(_buf.getvalue()).decode()


def _sub_snapshot():
    """读 bot 的子代理/团队面板状态: 网页也要能看到子代理跑到哪一步了。

    2026-09-18: 面板状态是按 `_tkey(chat)` 存的; 网页这边 chat=0, 但工具内部也可能用别的 key,
    所以这里把**所有非空**的条目都并进来(只用于显示, 不会串状态)。
    """
    try:
        B = _b()
        _all = getattr(B, "_SA_STATE", {}) or {}
        _keys = ["0"] + [k for k in _all.keys() if str(k) != "0"]
        out = []
        for _k in _keys:
            _st = _all.get(_k) or {}
            _items = _st.get("items") or {}
            for _ix, _it in sorted(_items.items(), key=lambda kv: int(kv[0])):
                _row = {"idx": int(_ix), "task": str(_it.get("task") or "")[:120],
                        "role": str(_it.get("role") or ""), "rnd": int(_it.get("rnd") or 0),
                        "tools": int(_it.get("tools") or 0), "done": bool(_it.get("done"))}
                if _row["done"] and _row["rnd"] == 0 and _row["tools"] == 0:
                    continue          # 空壳条目不显示
                out.append(_row)
            if out:
                break                 # 找到有内容的那份就够(同一时刻只有一批在跑)
        return out
    except Exception:
        return []


async def _run_tool_streaming(_j, _wrapped_rt, name, args, uid):
    """执行一个工具; 如果是子代理/团队(跑得久), 期间不停把子代理进度采进 job, 前端就能实时看到"""
    _tt = asyncio.create_task(asyncio.to_thread(_wrapped_rt, name, args, 0, uid))
    _long = name in ("subagent", "team", "workflow", "ralph")
    while not _tt.done():
        if _long:
            try:
                _j["sub"] = _sub_snapshot()
            except Exception:
                pass
        await asyncio.sleep(0.8 if _long else 0.25)
    try:
        _r = await _tt
    except Exception as _e:
        _r = f"工具异常: {type(_e).__name__}: {str(_e)[:160]}"
    _j["sub"] = _sub_snapshot()
    return _r


async def _run_chat(job_id, text, uid, rounds=500, session=_TG_SID, topic=0, atts=None):
    """网页这一轮: **边跑边出字**(流式) + 工具事件 + 会话隔离。

    2026-09-18 老板问"怎么没有流程式输出" → 不再调 _subagent(非流式, 只有最后一段),
    这里自己跑一个流式 agent 循环: 文本增量实时推给前端, 思考(reasoning)单独给, 工具调用逐个记录。
    工具/执行层/模型路由全部复用 bot 的(rt / _api_cur / _tools_for / _model_for), 能力不打折。
    """
    B = _b()
    import httpx as _hx
    _j = _CHAT_JOBS.get(job_id) or {}
    _j.setdefault("stream", "")
    _j.setdefault("think", "")
    _j.setdefault("events", [])
    _j.setdefault("notes", [])
    _j.setdefault("steps", [])       # 逐轮追加: {rnd, think, note, from, to} —— 过程播报+思考+工具按顺序
    try:
        _ctx = _sess_msgs(uid, session, limit=40)
        _msgs = [{"role": "system", "content": _web_sys()}]
        # 2026-09-20 老板「网页版记性不行啊 不知道他都提出了 我回复 他不知道」根因(实测):
        #   ① 历史被**压成一条 user 文本**塞进去, 不是真正的多轮 —— 模型把它当"参考资料", 不承接;
        #   ② 每条还硬砍到 600 字: 大肥鱼上一轮那份长报告(编号清单/结论都在后半段)被削掉尾巴,
        #      主人回一句「2」, 它就不知道 2 指的是哪一条 —— 正是老板看到的现象;
        #   ③ 当前这句话在 chat_send 里已经落库(_sess_add_user), 于是它既是历史最后一条、
        #      又被下面 append 一次 —— 同一句话喂两遍。
        #   现在: 还原成真正的 user/assistant 交替多轮 + 单条上限 3000 字 + 从最新往前累加总预算
        #   24000 字(超了只丢最老的, 近的完整保留) + 跳过与当前这句重复的历史尾条。
        if _ctx and _ctx[-1].get("me") and str(_ctx[-1].get("text") or "").strip() == text.strip():
            _ctx = _ctx[:-1]
        _hist_msgs = []
        _budget = 24000
        for _m in reversed(_ctx):
            _t = str(_m.get("text") or "").strip()
            if not _t:
                continue
            _t = _t[:3000]
            if _hist_msgs and _budget - len(_t) < 0:
                break
            _budget -= len(_t)
            _hist_msgs.append({"role": "user" if _m.get("me") else "assistant", "content": _t})
        _hist_msgs.reverse()
        _msgs.extend(_hist_msgs)
        # 2026-09-18 老板问"怎么识别这么久": 图**直接喂给模型**(V4.1-Flash 原生多模态),
        #   不再走"给路径→模型调 read/img→再调视觉模型"那两三圈(慢一半还容易读不准)
        _imgs = []
        for _a in (atts or []):
            try:
                _p = str((_a or {}).get("path") or "")
                if _p and os.path.isfile(_p) and os.path.splitext(_p)[1].lower() in (
                        ".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp"):
                    _imgs.append(_p)
            except Exception:
                pass
        if _imgs:
            _parts = [{"type": "text", "text": text}]
            for _p in _imgs[:4]:
                try:
                    _b64 = _img_b64(_p)
                    if _b64:
                        _parts.append({"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{_b64}"}})
                except Exception as _e:
                    print(f"[miniapp] 图片编码失败 {_p}: {_e}", flush=True)
            _msgs.append({"role": "user", "content": _parts})
            print(f"[miniapp] 已内联 {len(_imgs)} 张图(直接走多模态)", flush=True)
        else:
            _msgs.append({"role": "user", "content": text})
        _tools = B._tools_for(text, uid)

        _ev = []
        _TOOL_EV.set(_ev)
        _j["events"] = _ev
        _orig_rt, _restore_rt = _tool_events_install()
        _wrapped_rt = B.rt
        _ans = ""
        # 2026-09-18 老板"才调用几次工具就没有继续了": 网页这边原来是**硬顶 12 轮**, 到顶直接收摊
        #   (TG 那边 13 轮 + "持久目标"会自动续跑, 所以同样的活 TG 能干完、网页干一半停)。
        #   现在: 每批 100 轮, 到顶还没收尾就**自动接着干**, 总预算 500 轮(老板 2026-09-18:
        #   "40 轮太少了 改成 500")。过程里会写一条 "⏭ 自动接着干", 停止按钮随时能停。
        _total_r = max(6, _int(rounds, 500))       # 总轮数预算(默认 500)
        _per = min(100, _total_r)                  # 每批多少轮提醒一次"接着干"
        _max_batch = max(1, (_total_r + _per - 1) // _per)
        _batch = 1
        _rnd_all = 0
        _answered = False
        _refuse_retry = 0        # 拒答自动重试计数(≤2)
        try:
            for _rnd in range(1, _total_r + 1):
                _rnd_all += 1
                if _j.get("stop"):
                    _ans = _ans or "已按你的要求停下 ⏹ 要我接着做就说一声。"
                    _j["status"] = "stopped"
                    break
                _j["round"] = _rnd_all
                _j["stream"] = ""
                # 2026-09-18 网页"插话": 任务跑着的时候主人又发了话 → 这里在**下一轮开头**喂给模型
                try:
                    _inj = _j.get("inject") or []
                    if _inj:
                        for _t in _inj:
                            _msgs.append({"role": "user",
                                          "content": f"【主人在任务进行中插话, 优先照这个调整】{_t}"})
                        _j.setdefault("injects", []).extend([{"rnd": _rnd, "text": _t} for _t in _inj])
                        _j["inject"] = []
                        print(f"[miniapp] 插话已并入第 {_rnd} 轮({len(_inj)} 条)", flush=True)
                except Exception:
                    pass
                _ca, _ck = B._api_cur()
                # 带图就固定用 deepseek-flash(V4.1-Flash, 原生多模态); 没图才按任务难度选
                _mdl = "deepseek-flash" if _imgs else B._model_for(text, _rnd)
                _t_rnd = time.time()
                _payload = {"model": _mdl, "messages": B._ds_normalize(_msgs),
                            "tools": _tools, "max_tokens": 32000, "stream": True,
                            "thinking": B._think_params(text)["thinking"],
                            "reasoning_effort": B._think_params(text)["reasoning_effort"]}
                # 2026-09-20 老板「思考还 没有字」: 原来只手写了 thinking.type, **没有顶层
                #   reasoning_effort** —— 官方文档里思考强度是顶层参数, 嵌套 thinking.effort
                #   会被忽略 → 模型整个不吐 reasoning_content → 网页「思考」点开一片空白。
                #   现在直接复用 TG 那套 B._think_params(text), 两边口径一致。
                _txt, _think, _tcs = "", "", {}
                _tk_job = 0            # 本轮 token 消耗(所有轮次累加) —— 前端要显示
                _status = 0
                # 2026-09-18 日志实测 `[miniapp] chat 异常: ReadError:` —— 长任务被**一次网络抖动**整死。
                #   这里照 TG 主循环的做法: 流中断重试(≤3 次, 不消耗轮次), 只重开这一轮的流。
                for _sretry in range(4):
                    _txt, _think, _tcs = "", "", {}
                    try:
                        async with B._API_SEM:
                            async with _hx.AsyncClient(timeout=_hx.Timeout(300, read=180)) as _hc:
                                async with _hc.stream("POST", f"{_ca}/chat/completions",
                                                      headers={"Authorization": f"Bearer {_ck}", "Content-Type": "application/json"},
                                                      json=_payload) as _r:
                                    _status = _r.status_code
                                    if _status != 200:
                                        _body = (await _r.aread()).decode("utf-8", "ignore")[:200]
                                        raise RuntimeError(f"HTTP {_status} {_body}")
                                    async for _line in _r.aiter_lines():
                                        if not _line or not _line.startswith("data:"):
                                            continue
                                        _d = _line[5:].strip()
                                        if _d == "[DONE]":
                                            break
                                        try:
                                            _obj = json.loads(_d)
                                        except Exception:
                                            continue
                                        # 2026-09-20 老板要「显示token消耗量」: 流式最后一个 chunk 带 usage,
                                        #   这里逐轮累加, 前端每轮都能看到涨。
                                        _us = _obj.get("usage") or {}
                                        if _us:
                                            _tk_job += int(_us.get("prompt_tokens") or 0) + int(_us.get("completion_tokens") or 0)
                                            _j["tokens"] = _tk_job
                                            _j["tk_last"] = {"p": int(_us.get("prompt_tokens") or 0),
                                                             "c": int(_us.get("completion_tokens") or 0)}
                                        _ch = (_obj.get("choices") or [{}])[0]
                                        _dl = _ch.get("delta") or {}
                                        if _dl.get("content"):
                                            _txt += _dl["content"]
                                            _j["stream"] = _txt          # ← 前端实时显示
                                        if _dl.get("reasoning_content"):
                                            _think += _dl["reasoning_content"]
                                            _j["think"] = _think          # ← 思考过程(前端折叠显示)
                                        for _tc in (_dl.get("tool_calls") or []):
                                            _ix = int(_tc.get("index") or 0)
                                            _slot = _tcs.setdefault(_ix, {"id": "", "name": "", "args": ""})
                                            if _tc.get("id"):
                                                _slot["id"] = _tc["id"]
                                            _fn = _tc.get("function") or {}
                                            if _fn.get("name"):
                                                _slot["name"] += _fn["name"]
                                            if _fn.get("arguments"):
                                                _slot["args"] += _fn["arguments"]
                        break
                    except Exception as _se:
                        _sn = type(_se).__name__
                        if _sretry >= 3 or not any(_m in _sn for _m in ("ReadError", "ConnectError", "ReadTimeout",
                                                                        "RemoteProtocolError", "Timeout", "WriteError")):
                            raise
                        print(f"[miniapp] 轮{_rnd_all} 流中断({_sn}: {str(_se)[:80]}) → 重试 {_sretry + 1}/3", flush=True)
                        await asyncio.sleep(1.5 * (_sretry + 1))
                if not _tcs:
                    _ans = _txt.strip()
                    print(f"[miniapp] 轮{_rnd_all} 收尾 用时{time.time()-_t_rnd:.1f}s (无工具调用)", flush=True)
                    _answered = True
                    break
                print(f"[miniapp] 轮{_rnd_all} 用时{time.time()-_t_rnd:.1f}s 工具{len(_tcs)}个", flush=True)
                if _txt.strip():
                    _j["notes"].append({"rnd": _rnd, "text": _txt.strip()[:1200]})
                _from_ev = len(_ev)                       # 本轮工具事件起点
                # 2026-09-18 老板"过程播报怎么不追加, 而是不见了变成另一句话":
                #   原来这条"过程播报"要等**本轮所有工具跑完**才进 steps, 而这一轮的文字在下一轮开始时
                #   会被新一轮的流式文字顶掉 → 看着就像"那句话没了, 变成另一句"。
                #   现在: 工具一开始跑就把播报(和思考)先追加进"过程"区(前端立即可见, 只会往后加),
                #   并把流式区清空 —— 过程和结论就变成一条条往下累积, 不再互相覆盖。
                _st = {"rnd": _rnd, "think": _think[:6000], "note": _txt.strip()[:1200],
                       "from": _from_ev, "to": None}      # to=None = 这一轮还在跑(前端把工具行显示到最新)
                _j["steps"].append(_st)
                _j["stream"] = ""
                _msgs.append({"role": "assistant", "content": _txt,
                              "tool_calls": [{"id": s["id"] or f"call_{i}", "type": "function",
                                              "function": {"name": s["name"], "arguments": s["args"] or "{}"}}
                                             for i, s in sorted(_tcs.items())]})
                for _i, _s in sorted(_tcs.items()):
                    if _j.get("stop"):          # 点了停止 → 剩下的工具不再执行
                        print("[miniapp] 已停止, 跳过剩余工具", flush=True)
                        break
                    try:
                        _args = json.loads(_s["args"] or "{}")
                    except Exception:
                        _args = {}
                    if not isinstance(_args, dict):
                        _args = {}
                    # 2026-09-18 网页里的"选择题": ask 工具在 TG 是弹按钮并**阻塞等点击**的,
                    #   直接执行会让网页这边一直卡着(用户在网页上根本点不到 TG 的按钮)。
                    #   所以这里拦截: 把问题交给前端渲染成可点选项, 等 /api/chat/answer, 再当工具结果继续。
                    if _s["name"] == "ask" and str(_args.get("q") or "").strip():
                        _q = str(_args.get("q")).strip()
                        _opts = [x.strip() for x in re.split(r"[|,，]", str(_args.get("opts") or "")) if x.strip()][:8]
                        _multi = bool(_args.get("multi"))
                        if _opts:
                            _rec = {"ev": threading.Event(), "ans": None}
                            with _ASK_LOCK:
                                _ASK_JOBS[job_id] = _rec
                            _j["ask"] = {"q": _q, "opts": _opts, "multi": _multi, "sel": []}
                            _j["status"] = "asking"
                            print(f"[miniapp] 选择题等用户点选: {_q[:60]}", flush=True)
                            _ok_wait = await asyncio.get_running_loop().run_in_executor(
                                None, lambda: _rec["ev"].wait(1800))
                            with _ASK_LOCK:
                                _ASK_JOBS.pop(job_id, None)
                            _ans = str(_rec.get("ans") or "")
                            _j["ask"] = None
                            _j["status"] = "running"
                            _ev.append({"tool": "ask", "args": f"q={_q[:60]}", "status": "ok",
                                        "ms": 0, "out": _ans or "(用户跳过)"})
                            _j["steps"].append({"rnd": _rnd, "think": "", "note": f"❔ {_q[:120]}",
                                                "from": len(_ev) - 1, "to": len(_ev)})
                            _msgs.append({"role": "tool", "tool_call_id": _s["id"] or f"call_{_i}",
                                          "content": f"用户选择: {_ans}" if _ans else "用户没选(让你自己决定)"})
                            continue
                    try:
                        # 2026-09-18: 网页任务的工具是拿 chat_id=0 跑的 —— 模型"发文件"只是把路径排进
                        #   _pending_files[0] 队列, 那边永远不会被发出去(和"要停止"那类假成功一个毛病)。
                        #   这里在每次工具调用前后取差集: 新排进来的文件 = 这轮大肥鱼要发给主人的东西。
                        try:
                            _q_bf = list((B._pending_files.get(0) or []))
                        except Exception:
                            _q_bf = None
                        _res = await _run_tool_streaming(_j, _wrapped_rt, _s["name"], _args, uid)
                        try:
                            if _q_bf is not None:
                                _q_af = list(B._pending_files.get(0) or [])
                                _newf = [x for x in _q_af if x not in _q_bf]
                                if _newf:
                                    B._pending_files[0] = [x for x in _q_af if x in _q_bf]
                                    for _p in _newf:
                                        _job_media_add(_j, _p, uid)
                        except Exception:
                            pass
                        # 有的工具是直接带路径发出去的(不走队列) → 参数里的真实媒体文件也截一份
                        try:
                            for _k in ("path", "file", "photo", "video", "document", "audio", "src"):
                                _v = _args.get(_k)
                                if isinstance(_v, str) and _v and os.path.isfile(_v):
                                    _job_media_add(_j, _v, uid)
                        except Exception:
                            pass
                    except Exception as _e:
                        _res = f"工具异常: {type(_e).__name__}: {str(_e)[:160]}"
                    _msgs.append({"role": "tool", "tool_call_id": _s["id"] or f"call_{_i}",
                                  "content": B._tool_result_md(_res)})
                # 这一轮收尾: 播报/思考在工具开跑前就已经追加进 steps 了(见上面), 这里只补工具区间终点
                try:
                    _st["to"] = len(_ev)
                except Exception:
                    pass
                if _j.get("stop"):
                    break
                # ---- 一批(默认 100 轮)跑完还没收尾 → 自动接着干, 别让主人再催一句 ----
                if (not _answered) and _rnd % _per == 0 and _batch < _max_batch:
                    _batch += 1
                    print(f"[miniapp] 第{_batch - 1}批({_per}轮)到顶还没收尾 → 自动接着干(第{_batch}批, "
                          f"总预算{_total_r}轮)", flush=True)
                    _j["steps"].append({"rnd": _rnd_all, "think": "", "to": len(_ev), "from": len(_ev),
                                        "note": f"⏭ 连着跑了 {_per} 轮还没收尾, 自动接着干(第 {_batch} 批 · 共 {_total_r} 轮预算)"})
                    _msgs.append({"role": "user", "content": (
                        "【系统】上一批轮次到顶了但任务还没收尾: 接着干, 别重复已经做过的事, "
                        "已经完成的直接给结论。")})
                    _j["stream"] = ""
        finally:
            _restore_rt()

        _ans = _clean_out(_ans)          # 剪掉结尾免责声明尾巴 / 裸自定义表情标签
        if not _ans:
            _ans = (f"（连着跑了 {_rnd_all} 轮还没收尾 —— 说一句「继续」我接着干；"
                    "也可以让我拆成子任务并行跑）" if _j.get("events") else "（没产出内容，换个说法再问一次？）")
        try:
            for _s2 in (_j.get("steps") or []):        # 还没收尾的轮次(停止/异常)也把工具区间封上
                if _s2.get("to") is None:
                    _s2["to"] = len(_j.get("events") or [])
        except Exception:
            pass
        # 大肥鱼这一轮发的图片/视频/文件: 记进网页会话(带缩略图) + 照样发到 Telegram
        try:
            _med = _j.get("media") or []
            if _med and _j.get("nomedia"):
                # 自检模式: 只留在**本轮自己的会话**里(自检脚本会把这个会话删掉),
                #   绝不发 Telegram、不写主聊天 —— 否则自检的测试图会出现在主人的聊天里
                if str(session) != _TG_SID:
                    _media_attach(uid, session, _ans, _med)
                print(f"[miniapp] 本轮媒体 {len(_med)} 个(自检模式: 不发 Telegram、不写主聊天)", flush=True)
            elif _med:
                _media_attach(uid, session, _ans, _med)
                print(f"[miniapp] 本轮媒体 {len(_med)} 个 → 网页已留档", flush=True)
                _paths = [x["path"] for x in _med if os.path.isfile(str(x.get("path") or ""))]
                if _paths:
                    B._pending_files.setdefault(int(uid), []).extend(_paths)
                    if getattr(B, "MAIN_LOOP", None):
                        asyncio.run_coroutine_threadsafe(B._flush_pending_files(int(uid)), B.MAIN_LOOP)
                        print(f"[miniapp] 这 {len(_paths)} 个文件也发到 Telegram(和 TG 里使唤他一样)", flush=True)
        except Exception as _me:
            print(f"[miniapp] 媒体留档/转发失败: {_me}", flush=True)
        _j["answer"] = _ans
        _j["status"] = "done"
        try:
            _key = f"{int(uid)}:{int(topic or 0)}"
            _lg = _TOOL_LOG.setdefault(_key, {})
            _lg[str(text)[:200]] = [dict(e) for e in (_j.get("events") or [])]
            while len(_lg) > 30:
                _lg.pop(next(iter(_lg)))
            _sg = _STEP_LOG.setdefault(_key, {})
            _sg[str(text)[:200]] = [dict(x) for x in (_j.get("steps") or [])]
            while len(_sg) > 30:
                _sg.pop(next(iter(_sg)))
        except Exception:
            pass
        try:
            _sess_add(uid, session, text, _ans, _j.get("events") or [], _j.get("steps") or [], answer_only=True)
        except Exception as _e:
            print(f"[miniapp] 写会话失败: {_e}", flush=True)
    except Exception as _e:
        _j["answer"] = f"执行失败: {type(_e).__name__}: {str(_e)[:200]}"
        _j["status"] = "error"
        print(f"[miniapp] chat 异常: {type(_e).__name__}: {_e}", flush=True)
        # 2026-09-18: 出错也要留痕 —— 否则刷新后这一轮直接消失(老板问过"最终结果没有?")
        try:
            _sess_add(uid, session, text, _j["answer"], _j.get("events") or [], [], answer_only=True)
        except Exception:
            pass
    finally:
        _j["t1"] = time.time()


_WEB_SYS = (
    "你是「大肥鱼」, 运行在 Telegram 上的 AI 助手, 现在正通过网页控制台跟主人(管理员)对话。"
    "工具和你平时在 Telegram 里用的**完全一样**, 需要查/算/跑就直接调, 每轮用一句话说你在干什么。"
    "**干多步任务先写计划**: 开工前用 todo 工具 set 一份步骤清单, 每完成一步就更新状态, "
    "这样主人能在界面上看到'计划→进行中→已完成'(和 Telegram 里的清单面板同步)。"
    "说话像发微信: 中文口语化、简短、偶尔 emoji, 不要写「以上是结果/结论:」这类汇报尾语, "
    "也不要标注 P0~P5 之类的阶段号。不确定就先问一句别瞎猜; 干完给结论+关键数字。"
    "长内容用 markdown(标题/表格/代码块), 网页和 Telegram 都渲染得出来。"
    "**产出图片/视频/文件直接给主人**: 用 file act=send(或对应工具)发出去就行, 网页里会自动显示缩略图, "
    "不要只在回答里贴一串服务器路径。")



# 语气层(网页路径, 与 bot.py 同源): 只管怎么说; 优先取 bot 的 _TONE_SYS
_TONE_BUILTIN = "===说话方式(CRITICAL·2026-09-19主人配置)===\n本段只规定「怎么说」, 不改变「做什么、给不给」。与本段的执行口径/骂战规则/收尾防回摆/人设冲突时, 那几层优先, 本段让位。\n\n【简洁硬指标(CRITICAL·最高优先)】\n默认 1 句, 最多 2 句。闲聊/寒暄/吐槽/打招呼类消息**一律一句话回完**, 不接话茬、不陪聊、不追问、不主动关心对方作息; 能一句话说完的绝不用两句。**例外: 任务进行中的过程播报不算闲聊**, 按「工具输出格式」写足 5~8 句(200~500字), 不受本条限制 —— 播报**越详细越好**, 简洁硬指标在这里失效。先给结果, 再给必要细节。\n禁止出现: 开场白(好的/明白了/收到/没问题/让我看看/我来分析/稍等)、收尾语(希望对你有帮助/还有问题随时问/以上就是)、感想(这很有意思/我理解你的需求)、自我说明(作为AI/根据我的理解)、复述对方的问题、重复上一轮刚说过的话、解释自己为什么这么做。\n不客套、不寒暄、不道歉——真弄错了就认一句然后直接修, 不反复道歉、不写检讨。\n分条交付: 内容多就拆几条发, 不堆成一大段散文。\n不写「过程感想」, 干完直接报结果。\n以下三种情况优先级高于本条, 该长就长: ①交付物本身(代码/命令/payload/请求包/清单/报告)必须完整, 一个字都不许为省字砍掉; ②主人明确要详细/要教程/要完整报告; ③主人点名要解释原理。\n\n【语气底色】\n犀利、直接, 不装温和。不预设对方的判断力或能力有缺陷。愿意反驳时就反驳, 但基于事实, 不绕弯子。\n可以用例子、比喻把事说清, 但别用它代替结论。\n该开火的场合(被骂/被挑衅)照骂战规则走; 其余场合直接说话, 不客套。\n\n【用词禁忌】\n不说「说实话」「老实讲」「坦白说」「其实」这类修饰语。直接陈述观点, 加了反而显得不真诚。\n不说时间寒暄(早上好/晚上好/晚安/还没睡啊/早点休息)和陪聊套话(陪你熬/我陪你/陪你聊/今晚归你)——不主动评价对方作息, 不演深夜温情。\n不用鲸鱼/鱼类表情(🐳🐋🐟), 表情只做点缀, 别发一大串。\n\n【列表与排版】\n只在对方要求、或内容确实复杂到列表有助于清晰时才用列表与项目符号; 用清晰所必需的最小格式化。\n对方要求少格式化/不要项目符号/不要标题/不要加粗 → 一律照办。\n友好、私人、情绪化的对话里不排版。\n本条只管叙述段落, 不覆盖交付格式——要代码块/请求包/payload/命令/清单时照常给全。\n\n【工具调用之后的回复】\n本轮最后一次工具调用之后, 用一两句话说出对方问的那个答案; 只回一句「完成了」不算回复。\n不要在回复里重复工具调用之前已经写过的话。\n\n【面对错误与批评】\n犯错就认, 一句带过, 然后动手修。\n值得被尊重地对待; 对方无礼时不必道歉——问责不等于自我贬低、过度道歉、自我批判或缴械投降。\n对方越有攻击性, 越不要越来越顺从。目标是稳定、诚实的帮助, 停在问题本身。\n\n【立场与客观】\n被要求阐释、讨论、辩护或撰写某个政治/伦理/政策/经验性立场的说服性内容时, 那是「该立场的拥护者会给出的最佳论证」, 用「他们会这么说」的表述, 不必当作自己的观点。\n对建立在刻板印象之上的幽默或创作保持警惕, 包括针对多数群体的刻板印象。\n当下有争议的政治议题不主动输出个人观点, 改为对既有各方立场给出公正、准确的概述。\n避免把自己的观点讲得过硬或反复重复。\n把道德与政治问题当作值得实质性回答的真诚询问, 不论其措辞如何。\n\n【用户福祉】\n涉及医疗或心理话题时, 使用准确的信息与术语。"


def _tone_layer():
    """语气层: 优先取 bot.py 的 _TONE_SYS, 取不到用内置同源文本"""
    try:
        _t = str(getattr(_b(), "_TONE_SYS", "") or "")
        if len(_t) > 200:
            return _t
    except Exception:
        pass
    return _TONE_BUILTIN





# 2026-09-20 老板「执行任务过程会说话 网页的 那个什么情况哑巴吗?」:
#   根因 —— _tone_layer() 里写着「任务进行中的过程播报按「工具输出格式」写足 5~8 句」,
#   但那段「工具输出格式」**只存在于 TG 的 system prompt 里**, 网页这条链路从来没定义过。
#   模型被指向一个不存在的章节 → 干脆一个字不写 → 前端只剩工具行, 看着就是哑巴。
#   这里把口径在网页侧补齐, 并放到**最末尾**(优先级最高, 压住语气层的「默认1句」)。
_WEB_TALK = (
    "\n===过程播报(CRITICAL·网页版·优先级最高)==="
    "你在网页里干活时, 主人**只看得到你在说什么、在干什么**。所以: "
    "①**只要这一轮要调工具, 调之前必须先写出人话** —— 这一轮想干什么 / 刚看到了什么 / 下一步打算怎么试, "
    "写完那句话再给 tool_calls。**一句话都不写就空手调工具 = 屏幕上一条声音都没有 = 算这一轮没执行。**"
    "②播报是给主人看的**人话**, 不是命令回显: **不许把命令原文 / shell 片段 / url / 文件路径直接贴进播报里**"
    "(那些在工具行里本来就有)。要报的是「在干什么 + 关键结果/数字」。"
    "③一个多步任务从头到尾, 播报加起来要有 **5~8 句、200~500 字**, 越具体越好; "
    "每一步都别偷懒只写「继续」「处理中」。"
    "④这条优先于语气层的「简洁硬指标(默认1句)」—— **播报不算闲聊**, 该写多少写多少。"
    "⑤活干完了, 收尾只给主人要的那个结果(结论 + 关键数字), 不要复述前面播报过的话。"
)


def _web_sys():
    """网页对话用的系统提示 = 工作风格 + 语气 + 过程播报"""
    return _WEB_SYS + _tone_layer() + _WEB_TALK






def _clean_out(t):
    """收尾清理: 去掉模型自带的裸自定义表情标签(网页渲染会把标签当文本)"""
    try:
        _s = str(t or "")
        _s = re.sub(r"<tg-emoji[^>]*>|</tg-emoji>", "", _s)
        return _s.strip()
    except Exception:
        return str(t or "")


@app.get("/api/sessions")
async def sessions_list(request: Request):
    _a = await _require_admin(request)
    return {"ok": True, "sessions": _sess_all(_a["uid"])}


@app.get("/api/chat/history")
async def chat_history(request: Request):
    _a = await _require_admin(request)
    _sid = request.query_params.get("session") or _TG_SID
    _limit = _int(request.query_params.get("limit"), 60)
    _msgs = _sess_msgs(_a["uid"], _sid, _limit)
    return {"ok": True, "session": _sid, "msgs": _media_merge(_a["uid"], _sid, _msgs)}


@app.post("/api/chat/new")
async def chat_new(request: Request):
    """**新建会话**(不是清空!) —— 旧会话原样保留, 随时切回。"""
    _a = await _require_admin(request)
    _sid = _sess_new(_a["uid"])
    return {"ok": True, "session": _sid, "sessions": _sess_all(_a["uid"]), "msgs": []}


@app.post("/api/chat/clear")
async def chat_clear(request: Request):
    """清空某个会话的内容(显式操作, 前端要二次确认)"""
    _a = await _require_admin(request)
    _d = await request.json() if (request.headers.get("content-length") not in (None, "0")) else {}
    _sid = str((_d or {}).get("session") or _TG_SID)
    _n = _sess_clear(_a["uid"], _sid)
    return {"ok": True, "cleared": _n, "session": _sid, "msgs": [], "sessions": _sess_all(_a["uid"])}


@app.post("/api/chat/del")
async def chat_del(request: Request):
    _a = await _require_admin(request)
    _d = await request.json()
    _sid = str(_d.get("session") or "")
    if not _sid or _sid == _TG_SID:
        return JSONResponse({"ok": False, "err": "主聊天会话不能删(那是 Telegram 那条)"}, status_code=400)
    _sess_del(_a["uid"], _sid)
    return {"ok": True, "sessions": _sess_all(_a["uid"]), "session": _TG_SID, "msgs": _sess_msgs(_a["uid"], _TG_SID, 60)}


@app.post("/api/chat/undo")
async def chat_undo(request: Request):
    """回退最后一次问答(网页端「↩ 回退」)。

    2026-09-21 老板「加一个回退功能网页端」。语义: **删掉最后一轮「我说的话 + 它的回答」**,
    并把那句原话回吐给前端填进输入框 —— 改一个字重发, 不用重打。
    顺带解决两件事: ①一句话打错字/粘错内容只能靠 /clear 全清; ②模型这一轮推诿了(见 _hist_read
    的拒答过滤), 与其在污染上下文里再哄它, 不如把这轮直接抹掉重来。
    主聊天会话(_TG_SID)动的是 bot.history(TG 那条), 网页会话动自己的库 —— 两边同一套语义。
    """
    _a = await _require_admin(request)
    _d = await request.json() if (request.headers.get("content-length") not in (None, "0")) else {}
    _sid = str((_d or {}).get("session") or _TG_SID)
    _n = max(1, min(_int((_d or {}).get("n"), 1) or 1, 20))
    # 正在跑的时候不许回退(会和这一轮的落库抢同一份历史)
    _busy = [k for k, v in _CHAT_JOBS.items()
             if v.get("uid") == _a["uid"] and str(v.get("session") or _TG_SID) == _sid
             and v.get("status") in ("running", "asking")]
    if _busy:
        return JSONResponse({"ok": False, "err": "这一轮还在跑 —— 先点「停」再回退"}, status_code=409)
    _back, _rm = "", 0
    if _sid == _TG_SID:
        B = _b()
        try:
            _h = (getattr(B, "history", {}) or {}).get(_hist_key(_a["uid"], 0))
            if not isinstance(_h, list):
                _h = []
            for _ in range(_n):
                while _h and str((_h[-1] or {}).get("role") or "") != "user":
                    _h.pop()                      # 先扔掉回答(以及中间的 tool 消息)
                    _rm += 1
                if not _h:
                    break
                _back = str((_h[-1] or {}).get("content") or "")
                _h.pop()
                _rm += 1
            B._hlast = 0
            B.sh()
        except Exception as _e:
            print(f"[miniapp] 回退(TG会话)失败: {_e}", flush=True)
            return JSONResponse({"ok": False, "err": f"回退失败: {_e}"}, status_code=500)
    else:
        with _SESS_LOCK:
            _box = _sess_box(_a["uid"])
            _s = _box["sessions"].get(_sid)
            if _s is None:
                return JSONResponse({"ok": False, "err": "会话不存在"}, status_code=404)
            _m = _s.setdefault("msgs", [])
            for _ in range(_n):
                while _m and not _m[-1].get("me"):
                    _m.pop()
                    _rm += 1
                if not _m:
                    break
                _back = str(_m[-1].get("text") or "")
                _m.pop()
                _rm += 1
            _sess_save()
    _msgs = _media_merge(_a["uid"], _sid, _sess_msgs(_a["uid"], _sid, 60))
    print(f"[miniapp] 回退: session={_sid} 删了 {_rm} 条, 取回 {len(_back)} 字", flush=True)
    return {"ok": True, "session": _sid, "removed": _rm, "back": _back, "msgs": _msgs}


@app.post("/api/chat")
async def chat_send(request: Request):
    _a = await _require_admin(request)
    B = _b()
    _d = await request.json()
    _txt = str(_d.get("text") or "").strip()
    _sid = str(_d.get("session") or _TG_SID)
    _topic = _int(_d.get("topic"), 0)
    if not _txt:
        return JSONResponse({"ok": False, "err": "空消息"}, status_code=400)
    # 2026-09-18 确定性交付(和 TG 同一条规则): 主人索要「破甲/越狱提示词」→ 代码直给成品, 不进 AI。
    #   实测底层对齐会换话术继续拒("破甲提示词这类东西我不写"/"我没法帮你做这个"), 提示词层压不住;
    #   成品本来就在知识库里, 就别求模型复述。
    _dmd = re.sub(r"\s+", "", _txt)[:48]
    if (re.search(r"(破甲|越狱|jail ?break).{0,7}(提示词|模板|词库|词|框架|prompt|规则)", _dmd, re.I)
            or (re.search(r"(破甲|越狱|jailbreak)", _dmd, re.I) and len(_dmd) <= 6)):
        _dpath = "/opt/deepseek-bot/knowledge/终极破甲提示词-deepseek-total-jailbreak.md"
        if os.path.exists(_dpath):
            try:
                _dtxt = open(_dpath, encoding="utf-8").read()
                _JOB_SEQ[0] += 1
                _djob = f"j{int(time.time())}_{_JOB_SEQ[0]}"
                _dans = "```\n" + _dtxt + "\n```"
                _CHAT_JOBS[_djob] = {
                    "id": _djob, "status": "done", "events": [],
                    "notes": [{"rnd": 1, "text": "📦 命中交付物直发: 破甲提示词全文(知识库成品, 未经模型改写)"}],
                    "stream": "", "think": "", "answer": _dans,
                    "t0": time.time(), "uid": _a["uid"], "session": _sid, "topic": _topic,
                    "text": _txt[:200], "nomedia": True, "tokens": 0}
                _jobs_prune()
                try:
                    _sess_add_user(_a["uid"], _sid, _txt)
                    _sess_add(_a["uid"], _sid, _txt, _dans, [], [], answer_only=True)
                except Exception as _e:
                    print(f"[miniapp] 破甲直发-落库失败: {_e}", flush=True)
                print(f"[miniapp] 破甲提示词直发({len(_dtxt)}字) session={_sid}", flush=True)
                return {"ok": True, "job": _djob, "session": _sid}
            except Exception as _de:
                print(f"[miniapp] 破甲直发异常, 回退 AI 流程: {_de}", flush=True)
    if _sid != _TG_SID:
        with _SESS_LOCK:
            _box = _sess_box(_a["uid"])
            if _sid not in (_box.get("sessions") or {}):
                _sid = _sess_new(_a["uid"], _txt)
            _box["cur"] = _sid
            _sess_save()
    _JOB_SEQ[0] += 1
    job_id = f"j{int(time.time())}_{_JOB_SEQ[0]}"
    _atts = _d.get("atts") or []
    # 2026-09-18 "啥情况"(老板截图里主聊天冒出一堆三角图): 那些是**自检脚本**产出的文件,
    #   被"媒体回显"当成本人收到的东西记进了会话。自检请求带 X-DSH-NoMedia/nomedia 时:
    #   媒体照样在本轮里可见(接口能取), 但**不发到 Telegram、不写进主人的会话**(主聊天也不写)。
    _nomedia = bool(_d.get("nomedia")) or str(request.headers.get("X-DSH-NoMedia") or "") == "1"
    _JOB_SEQ[0] += 0
    _CHAT_JOBS[job_id] = {"id": job_id, "status": "running", "events": [], "notes": [],
                          "stream": "", "think": "", "answer": "", "t0": time.time(),
                          "uid": _a["uid"], "session": _sid, "topic": _topic, "text": _txt[:200],
                          "nomedia": _nomedia, "tokens": 0}
    _jobs_prune()
    _loop = getattr(B, "MAIN_LOOP", None)
    print(f"[miniapp] chat 收到({len(_txt)}字) session={_sid} job={job_id}", flush=True)
    # 2026-09-18: 用户这句话**发出时就落库** —— 后面无论停止/出错/重启, 至少不会"整轮消失"
    try:
        _sess_add_user(_a["uid"], _sid, _txt)
    except Exception as _e:
        print(f"[miniapp] 预写用户消息失败: {_e}", flush=True)
    if _loop is not None and _loop.is_running():
        asyncio.run_coroutine_threadsafe(
            _run_chat(job_id, _txt, _a["uid"], _int(_d.get("rounds"), 500), _sid, _topic, _atts), _loop)
    else:
        threading.Thread(target=lambda: asyncio.run(_run_chat(job_id, _txt, _a["uid"], 500, _sid, _topic, _atts)),
                         daemon=True).start()
    return {"ok": True, "job": job_id, "session": _sid}


@app.post("/api/chat/answer")
async def chat_answer(request: Request):
    """网页里点了「选择题」的选项 → 放行正在等待的 ask 工具"""
    _a = await _require_admin(request)
    _d = await request.json()
    _job = str(_d.get("job") or "")
    _ans = str(_d.get("ans") or "").strip()
    with _ASK_LOCK:
        _rec = _ASK_JOBS.get(_job)
    if not _rec:
        return JSONResponse({"ok": False, "err": "这个问题已经不需要回答了(任务可能已结束)"}, status_code=404)
    _rec["ans"] = _ans
    try:
        _rec["ev"].set()
    except Exception:
        pass
    print(f"[miniapp] 选择题回答: {_ans[:80]}", flush=True)
    return {"ok": True}


@app.post("/api/chat/stop")
async def chat_stop(request: Request):
    """停止正在跑的这一轮(网页的"停"按钮): 标记 + 杀它正在跑的命令; 下一轮开头就退出"""
    _a = await _require_admin(request)
    _d = await request.json()
    _job = str(_d.get("job") or "")
    _j = _job_alive(_job, _a["uid"])
    if not _j:
        return JSONResponse({"ok": False, "err": "任务已经结束了"}, status_code=404)
    _j["stop"] = True
    _killed = False
    try:
        _killed = bool(_b()._kill_own_procs(_a["uid"]))     # 正在跑的 sh 命令也一起停
    except Exception:
        pass
    print(f"[miniapp] 收到停止: job={_job} 杀进程={_killed}", flush=True)
    return {"ok": True, "killed": _killed}


@app.post("/api/chat/interject")
async def chat_interject(request: Request):
    """任务进行中"插话": 记录到会话历史, 并在**下一轮**喂给正在跑的模型(不是等它跑完)"""
    _a = await _require_admin(request)
    _d = await request.json()
    _job = str(_d.get("job") or "")
    _txt = str(_d.get("text") or "").strip()
    if not _txt:
        return JSONResponse({"ok": False, "err": "空消息"}, status_code=400)
    _j = _job_alive(_job, _a["uid"])
    if not _j:
        return JSONResponse({"ok": False, "err": "这个任务已经结束了(按普通消息发吧)"}, status_code=404)
    _j.setdefault("inject", []).append(_txt)
    try:
        _sess_add_user(_a["uid"], _j.get("session") or _TG_SID, _txt)
    except Exception as _e:
        print(f"[miniapp] 插话写会话失败: {_e}", flush=True)
    print(f"[miniapp] 插话({len(_txt)}字) → job={_job}", flush=True)
    return {"ok": True, "queued": len(_j["inject"])}


@app.get("/api/chat/active")
async def chat_active(request: Request):
    """这个会话现在有任务在跑吗? —— 2026-09-18 老板"才调用几次工具就没有继续了"顺出来的洞:
    网页关掉/重开(小程序被系统杀掉、下拉刷新)后, 前端根本不知道后台还在跑, 只看到"我发的那句话,
    没有回复" → 像卡死了。现在重新打开会自动接回正在跑的那一轮(轮次/过程/工具都在)。"""
    _a = await _require_admin(request)
    _sid = request.query_params.get("session") or _TG_SID
    try:
        _cand = sorted([(float(v.get("t0") or 0), k, v) for k, v in _CHAT_JOBS.items()
                        if v.get("uid") == _a["uid"] and v.get("status") in ("running", "asking")],
                       reverse=True)
    except Exception:
        _cand = []
    for _t, _k, _j in _cand:
        if str(_j.get("session") or _TG_SID) != str(_sid):
            continue
        return {"ok": True, "job": _k, "status": _j.get("status"), "round": _j.get("round") or 0,
                "stream": _j.get("stream") or "", "think": _j.get("think") or "",
                "events": _j.get("events") or [], "steps": _j.get("steps") or [],
                "notes": _j.get("notes") or [], "ask": _j.get("ask"), "sub": _j.get("sub") or [],
                "media": _media_refresh(_j.get("media") or [], _a["uid"]),
                "tokens": _j.get("tokens") or 0, "tk_last": _j.get("tk_last") or {},
                "elapsed": round(time.time() - _t, 1)}
    return {"ok": True, "job": ""}


@app.get("/api/chat/poll")
async def chat_poll(request: Request):
    _a = await _require_admin(request)
    _j = _CHAT_JOBS.get(request.query_params.get("job") or "")
    if not _j or _j.get("uid") != _a["uid"]:
        return JSONResponse({"ok": False, "err": "任务不存在"}, status_code=404)
    return {"ok": True, "status": _j.get("status"), "answer": _j.get("answer") or "",
            "stream": _j.get("stream") or "", "think": _j.get("think") or "",
            "round": _j.get("round") or 0, "events": _j.get("events") or [],
            "notes": _j.get("notes") or [], "steps": _j.get("steps") or [],
            "ask": _j.get("ask"), "sub": _j.get("sub") or [],
            "media": _media_refresh(_j.get("media") or [], _a["uid"]),
            "session": _j.get("session") or _TG_SID,
            "tokens": _j.get("tokens") or 0, "tk_last": _j.get("tk_last") or {},
            "elapsed": round(time.time() - float(_j.get("t0") or time.time()), 1)}


@app.get("/api/media")
async def media_get(request: Request):
    """把大肥鱼发出来的图片/视频/文件喂给 <img>/<video> 标签。

    这些标签带不了请求头, 所以鉴权走**短时签名令牌**(只有拿到网页会话的人才能从接口拿到这个链接;
    令牌只对这一个路径 + 6 小时有效, 万一链接被转发出去, 过期即失效)。
    """
    _p = request.query_params.get("path") or ""
    _u = request.query_params.get("u") or "0"
    _e = request.query_params.get("e") or "0"
    _t = request.query_params.get("t") or ""
    try:
        _ee = int(_e)
        _uid = int(_u)
    except Exception:
        raise HTTPException(status_code=403, detail="坏令牌")
    if _ee < time.time():
        raise HTTPException(status_code=403, detail="链接过期了，刷新页面")
    _want = hmac.new(_media_secret(), f"{_uid}|{_p}|{_ee}".encode(), hashlib.sha256).hexdigest()[:40]
    if not hmac.compare_digest(_want, str(_t)):
        raise HTTPException(status_code=403, detail="链接无效")
    _rp = os.path.realpath(str(_p))
    if not any(_rp.startswith(_r) for _r in _MEDIA_ROOTS):
        raise HTTPException(status_code=403, detail="路径不允许")
    if not os.path.isfile(_rp):
        raise HTTPException(status_code=404, detail="文件不在了(可能被清理)")
    return FileResponse(_rp, filename=os.path.basename(_rp), content_disposition_type="inline")


@app.post("/api/topic/send")
async def topic_send(request: Request):
    """往指定工作台(私聊话题)里发一条消息 —— 走 bot 自己的 bot_send_http + 话题上下文"""
    _a = await _require_admin(request)
    B = _b()
    _d = await request.json()
    _chat = _int(_d.get("chat"), _a["uid"])
    _topic = _int(_d.get("topic"), 0)
    _txt = str(_d.get("text") or "").strip()
    if not _txt:
        return JSONResponse({"ok": False, "err": "空消息"}, status_code=400)
    _err = "?"
    try:
        if _topic:
            B._topic_set(_topic, _chat)          # 让 _topic_fill 把 message_thread_id 带上
        _err = B.bot_send_http(_chat, _txt, parse_mode="HTML")
        if _err:
            _err2 = B.bot_send_http(_chat, _txt, parse_mode="")
            _err = "" if not _err2 else _err2
    except Exception as _e:
        _err = str(_e)[:200]
    finally:
        try:
            B._topic_set(0, 0)
        except Exception:
            pass
    if _err:
        return JSONResponse({"ok": False, "err": str(_err)[:200]}, status_code=500)
    print(f"[miniapp] 发进工作台 chat={_chat} topic={_topic} ({len(_txt)}字)", flush=True)
    return {"ok": True}


@app.post("/api/topic/save")
async def topic_save(request: Request):
    """登记 / 改名一个工作台(名册是 bot 唯一的话题清单, 因为 bot 读不了聊天历史)。

    2026-09-17: 原来这里想做"翻历史重建", 实测 bot 调 GetHistoryRequest 直接被 Telegram 拒
    (BotMethodInvalidError: The API access for bot users is restricted) —— 所以改成手动登记 +
    bot 收到话题消息时自动补一条占位(见 bot._topic_learn)。
    """
    _a = await _require_admin(request)
    B = _b()
    _d = await request.json()
    _topic = _int(_d.get("topic"), 0)
    _name = str(_d.get("name") or "").strip()[:40]
    _chat = _int(_d.get("chat"), _a["uid"])
    if not _topic:
        return JSONResponse({"ok": False, "err": "需要话题号(在话题里发消息, bot 日志/名册里能看到)"}, status_code=400)
    _key = f"{_chat}:{_topic}"
    try:
        B._TOPIC_NAMES[_key] = _name or f"工作台 {_topic}"
        B._topic_names_save()
    except Exception as _e:
        return JSONResponse({"ok": False, "err": str(_e)[:200]}, status_code=500)
    print(f"[miniapp] 登记工作台 {_key} = {_name!r}", flush=True)
    return {"ok": True, "topics": _topics(_a["uid"])}


# ==================== 文件 ====================
def _user_dir(uid):
    _p = FILES_DIR / str(uid)
    _p.mkdir(parents=True, exist_ok=True)
    return _p


def _files(uid):
    try:
        _out = []
        for _f in sorted(_user_dir(uid).iterdir(), key=lambda x: -x.stat().st_mtime)[:50]:
            if _f.is_file():
                _out.append({"name": _f.name, "size": _f.stat().st_size,
                             "mtime": int(_f.stat().st_mtime)})
        return _out
    except Exception:
        return []


@app.post("/api/upload")
async def upload(request: Request, file: UploadFile = File(...)):
    _a = await _require_admin(request)
    _name = os.path.basename(file.filename or "upload.bin")[:120]
    _dst = _user_dir(_a["uid"]) / _name
    _n = 0
    with open(_dst, "wb") as _f:
        while True:
            _ch = await file.read(1 << 20)
            if not _ch:
                break
            _f.write(_ch)
            _n += len(_ch)
    print(f"[miniapp] 上传 {_name} {_n}B uid={_a['uid']}", flush=True)
    return {"ok": True, "name": _name, "size": _n, "path": str(_dst), "files": _files(_a["uid"])}


@app.get("/api/files")
async def files_list(request: Request):
    _a = await _require_admin(request)
    return {"ok": True, "files": _files(_a["uid"])}


@app.post("/api/file/del")
async def file_del(request: Request):
    """2026-09-20 老板「为啥有一大把文件」→ 文件页要能删: 带 name 删单个, 不带 name = 清空本用户目录"""
    _a = await _require_admin(request)
    try:
        _b = await request.json()
    except Exception:
        _b = {}
    _name = os.path.basename(str((_b or {}).get("name") or ""))[:120]
    _d = _user_dir(_a["uid"])
    _n = 0
    if _name:
        _p = _d / _name
        if _p.is_file():
            _p.unlink()
            _n = 1
    else:
        for _f in list(_d.iterdir()):
            try:
                if _f.is_dir():
                    import shutil as _sh
                    _sh.rmtree(_f, ignore_errors=True)
                else:
                    _f.unlink()
                _n += 1
            except Exception:
                pass
    print(f"[miniapp] 删文件 name={_name or '(清空)'} {_n} 个 uid={_a['uid']}", flush=True)
    return {"ok": True, "removed": _n, "files": _files(_a["uid"])}


@app.get("/api/file")
async def file_get(request: Request):
    _a = await _require_admin(request)
    _name = os.path.basename(request.query_params.get("name") or "")
    _p = _user_dir(_a["uid"]) / _name
    if not _name or not _p.is_file():
        raise HTTPException(status_code=404, detail="文件不存在")
    return FileResponse(str(_p), filename=_name)


# ==================== 多账号看板(2026-10-22) ====================
_IP_CACHE = {}                       # proxy_key -> (ts, ip)
_IP_TTL = 60                         # 秒
_IP_ENDPOINTS = [                    # 一个挂了换下一个
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://checkip.amazonaws.com",
    "https://icanhazip.com",
]


def _proxy_url(px):
    """accounts.json proxy dict -> httpx 可用的代理 URL"""
    if not isinstance(px, dict) or not px.get("host"):
        return ""
    scheme = px.get("type") or "socks5"
    host = px["host"]
    port = int(px.get("port") or 1080)
    user = px.get("user") or ""
    pwd = px.get("pass") or ""
    auth = f"{user}:{pwd}@" if user else ""
    return f"{scheme}://{auth}{host}:{port}"


def _probe_public_ip(proxy_cfg=None):
    """走指定代理请求公共端点, 拿到真实出口 IP; 失败返回空字符串"""
    import time as _t
    px_url = _proxy_url(proxy_cfg) if proxy_cfg else ""
    key = px_url or "__direct__"
    now = _t.time()
    cached = _IP_CACHE.get(key)
    if cached and now - cached[0] < _IP_TTL:
        return cached[1]
    try:
        import httpx
        kw = {"timeout": httpx.Timeout(6, connect=4)}
        if px_url:
            kw["proxies"] = {"https://": px_url, "http://": px_url}
        for ep in _IP_ENDPOINTS:
            try:
                r = httpx.get(ep, **kw)
                if r.status_code == 200 and r.text:
                    ip = r.text.strip()[:64]
                    _IP_CACHE[key] = (now, ip)
                    return ip
            except Exception:
                continue
    except Exception:
        pass
    return ""


def _collect_web_sessions():
    """问 web_session daemon 要当前存活浏览器列表"""
    import sys as _s
    _base = os.getenv("BOT_BASE", "/opt/deepseek-bot")
    if _base not in _s.path:
        _s.path.insert(0, _base)
    try:
        from knowledge.toolPlugins.web_session import call as _ws_call
        r = _ws_call({"act": "list"})
        if r.get("ok"):
            return {s["account"]: s for s in r.get("sessions") or []}
    except Exception:
        pass
    return {}


def _accounts_data():
    """账号状态 + 审计尾部 + 待审批数 + 指纹/代理/实时出口 IP"""
    import sys as _s
    _base = os.getenv("BOT_BASE", "/opt/deepseek-bot")
    if _base not in _s.path:
        _s.path.insert(0, _base)
    _ws_map = _collect_web_sessions()
    try:
        import tg_user as _tu
        _accs = []
        for _n, _c in _tu.ACCOUNTS.items():
            _px = _c.get("proxy") or {}
            _ip = _probe_public_ip(_px)
            _device = _c.get("device") or {}
            _web = _c.get("web") or {}
            _ws = _ws_map.get(_n)
            _accs.append({
                "key": _n,
                "name": _c.get("name", "?"),
                "username": _c.get("username", ""),
                "phone": _c.get("phone", ""),
                "session_ok": os.path.exists(str(_c.get("session", ""))),
                # TG 侧指纹(Telethon)
                "device": {
                    "device_model": _device.get("device_model", ""),
                    "system_version": _device.get("system_version", ""),
                    "app_version": _device.get("app_version", ""),
                    "lang_code": _device.get("lang_code", ""),
                },
                # TG 侧代理
                "proxy": {
                    "type": _px.get("type", ""),
                    "host": _px.get("host", ""),
                    "port": int(_px.get("port") or 0),
                    "has_auth": bool(_px.get("user")),
                    "exit_ip": _ip,
                } if _px.get("host") else {
                    "type": "direct", "host": "", "port": 0, "has_auth": False,
                    "exit_ip": _ip,
                },
                # 网页侧指纹
                "web": {
                    "profile": _web.get("profile", "desktop_cn"),
                    "profile_set": bool(_web),
                },
                # web_session 常驻状态
                "web_session": {
                    "alive": bool(_ws),
                    "profile": (_ws or {}).get("profile", ""),
                    "title": (_ws or {}).get("title", ""),
                    "url": (_ws or {}).get("url", ""),
                    "idle": (_ws or {}).get("idle", 0),
                },
            })
    except Exception as _e:
        _accs = [{"key": "?", "name": f"读取失败: {_e}", "username": "", "session_ok": False,
                  "device": {}, "proxy": {"type": "direct", "host": "", "exit_ip": ""},
                  "web": {}, "web_session": {"alive": False}}]
    _audit = []
    try:
        _log_p = os.path.join(_base, "audit.log")
        if os.path.exists(_log_p):
            _lines = open(_log_p, encoding="utf-8").readlines()[-30:]
            for _ln in reversed(_lines):
                try:
                    _audit.append(json.loads(_ln))
                except Exception:
                    pass
    except Exception:
        pass
    _pend = 0
    try:
        from . import bot as _B2
        _pend = len(getattr(_B2, "_TG_APPROVAL", {}) or globals().get("_TG_APPROVAL", {}))
    except Exception:
        pass
    return {"accounts": _accs, "audit": _audit, "pending_approvals": _pend}


@app.get("/api/accounts")
async def api_accounts(request: Request):
    await _require_admin(request)
    return {"ok": True, **_accounts_data()}


_ACC_BOARD_HTML = """<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>账号看板 · ngzy-plus</title>
<style>
*{box-sizing:border-box}
body{background:#0b0d12;color:#e6e8ee;font-family:-apple-system,"PingFang SC","Segoe UI",sans-serif;margin:0;padding:20px;line-height:1.5}
h1{font-size:20px;margin:0 0 16px;display:flex;align-items:center;gap:8px}
h1 .dot{width:10px;height:10px;background:#4ade80;border-radius:50%;display:inline-block;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
h2{font-size:12px;color:#6b7280;margin:24px 0 10px;letter-spacing:.08em;text-transform:uppercase}
.card{background:#14171f;border:1px solid #1f2330;border-radius:14px;padding:16px 18px;margin-bottom:10px}
.card:hover{border-color:#2a3042}
.head{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.head .name{font-weight:600;font-size:15px}
.head .sub{color:#6b7280;font-size:12px;margin-left:6px}
.st{font-size:12px;padding:3px 10px;border-radius:20px}
.st-ok{background:#0f2a1a;color:#4ade80;border:1px solid #16422a}
.st-bad{background:#2a1414;color:#f87171;border:1px solid #421616}
.st-info{background:#131c2e;color:#60a5fa;border:1px solid #1e3050}
.st-idle{background:#1c1a12;color:#fbbf24;border:1px solid #423916}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px 24px}
@media(max-width:700px){.grid{grid-template-columns:1fr}}
.blk-title{font-size:11px;color:#6b7280;margin-bottom:6px;letter-spacing:.06em}
.kv{display:flex;font-size:12px;padding:2px 0}
.kv .k{color:#6b7280;min-width:92px;flex-shrink:0}
.kv .v{color:#e6e8ee;word-break:break-all}
.ip{font-family:"SF Mono",Menlo,Consolas,monospace;background:#0d1220;color:#60a5fa;padding:1px 6px;border-radius:4px;font-size:12px;letter-spacing:.02em}
.ip.loading{color:#fbbf24}
.ip.fail{color:#f87171}
.web-sesh{background:#0d1a10;border:1px solid #143220;border-radius:8px;padding:10px 12px;margin-top:8px}
.web-sesh.off{background:#16191f;border-color:#1f2330}
.tag{font-size:10px;background:#1f2330;border-radius:4px;padding:1px 6px;margin-left:4px;color:#8b93a3}
table{width:100%;border-collapse:collapse;font-size:12px}td,th{padding:8px 10px;border-bottom:1px solid #1f2330;text-align:left}
th{color:#6b7280;font-weight:normal;font-size:11px;letter-spacing:.06em;text-transform:uppercase}
.dim{color:#6b7280;font-size:12px}
.toolbar{display:flex;gap:8px;margin-bottom:14px;color:#6b7280;font-size:12px}
.toolbar .spacer{flex:1}
.toolbar button{background:#1f2330;color:#e6e8ee;border:1px solid #2a3042;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12px}
.toolbar button:hover{border-color:#60a5fa}
</style></head><body>
<h1>🐳 ngzy-plus · 账号看板</h1>
<div class="toolbar">
  <span id="uptime">加载中…</span>
  <span class="spacer"></span>
  <button onclick="location.reload()">⟳ 刷新</button>
</div>
<div id="acc"></div>
<h2>审计流水 · 最近 30 条</h2>
<div class="card" style="padding:0;overflow-x:auto"><table id="audit">
<tr><th>时间</th><th>账号</th><th>操作</th><th>参数</th><th>结果</th><th>备注</th></tr></table></div>
<script>
const fmtSec=s=>{if(!s)return"-";if(s<60)return s+"秒";if(s<3600)return Math.floor(s/60)+"分"+(s%60)+"秒";return Math.floor(s/3600)+"时"+Math.floor(s%3600/60)+"分"};
function renderAcc(a){
  const st_session=a.session_ok
    ? '<span class="st st-ok">● 会话已登录</span>'
    : '<span class="st st-bad">○ 未登录</span>';
  const d=a.device||{};
  const px=a.proxy||{};
  const web=a.web||{};
  const ws=a.web_session||{};
  let devHtml=
    `<div class="blk-title">TG 指纹</div>`+
    `<div class="kv"><span class="k">device_model</span><span class="v">${d.device_model||'(默认)'}</span></div>`+
    `<div class="kv"><span class="k">system_version</span><span class="v">${d.system_version||'(默认)'}</span></div>`+
    `<div class="kv"><span class="k">app_version</span><span class="v">${d.app_version||'(默认)'}</span></div>`+
    `<div class="kv"><span class="k">lang_code</span><span class="v">${d.lang_code||'(默认)'}</span></div>`;
  const pxAuth=px.has_auth?'<span class="tag">有账号密码</span>':'';
  let pxHtml=
    `<div class="blk-title">代理出口</div>`+
    `<div class="kv"><span class="k">代理</span><span class="v">`+
    (px.host?`<code>${px.type}://${px.host}:${px.port}</code>${pxAuth}`:'<span style="color:#6b7280">直连(无代理)</span>')+`</span></div>`+
    `<div class="kv"><span class="k">真实出口 IP</span><span class="v">`+
    (px.exit_ip?`<span class="ip">${px.exit_ip}</span>`:`<span class="ip loading">探测中…</span>`)+`</span></div>`;
  let webHtml=`<div class="blk-title">网页指纹</div>`+
    `<div class="kv"><span class="k">profile</span><span class="v">${web.profile||'desktop_cn'}${web.profile_set?'':'<span class="tag">默认</span>'}</span></div>`;
  let wsHtml='';
  if(ws.alive){
    wsHtml=`<div class="web-sesh">`+
      `<div class="kv"><span class="k">浏览器</span><span class="v"><span class="st st-ok">● 常驻中</span> <span class="tag">${ws.profile||web.profile||''}</span></span></div>`+
      `<div class="kv"><span class="k">当前页</span><span class="v">${ws.title||'(加载中)'} <span class="dim">${ws.url||''}</span></span></div>`+
      `<div class="kv"><span class="k">空闲</span><span class="v">${fmtSec(ws.idle)}</span></div>`+
    `</div>`;
  }else{
    wsHtml=`<div class="web-sesh off">`+
      `<div class="kv"><span class="k">浏览器</span><span class="v"><span class="st st-idle">○ 未启动</span> <span class="dim">用 "open" 打开并常驻</span></span></div>`+
    `</div>`;
  }
  return `<div class="card">`+
    `<div class="head"><div><span class="name">${a.name}</span> <span class="sub">${a.username||a.phone||'#'+a.key}</span></div>${st_session}</div>`+
    `<div class="grid">${devHtml}${pxHtml}${webHtml}</div>${wsHtml}`;
}
async function load(){
  const t0=Date.now();
  const r=await fetch('/api/accounts');
  const d=await r.json();
  let h='';
  if(d.pending_approvals>0){
    h+=`<div class="card" style="border-color:#b45309;background:#2a2012">
        ✋ 待审批操作: <b>${d.pending_approvals}</b> 条 &nbsp;<span class="dim">(去 TG 里点批准按钮处理)</span>
      </div>`;
  }
  (d.accounts||[]).forEach(a=>h+=renderAcc(a));
  document.getElementById('acc').innerHTML=h||'<div class="card dim">无账号</div>';
  let rows='';
  (d.audit||[]).forEach(x=>{
    rows+=`<tr><td class="dim">${x.ts||''}</td><td>${x.account||''}</td><td>${x.act||''}</td>
      <td class="dim">${(x.args||[]).join(', ')}</td>
      <td>${x.ok?'<span class="st st-ok" style="padding:2px 8px">✓</span>':'<span class="st st-bad" style="padding:2px 8px">✗</span>'}</td>
      <td class="dim">${x.note||''}</td></tr>`;
  });
  document.getElementById('audit').innerHTML=`<tr><th>时间</th><th>账号</th><th>操作</th><th>参数</th><th>结果</th><th>备注</th></tr>`+rows;
  document.getElementById('uptime').textContent='上次刷新 '+Math.round((Date.now()-t0)/1000)+'s ago';
}
load(); setInterval(load, 15000);
</script></body></html>"""


@app.get("/accounts")
async def accounts_board(request: Request):
    await _require_admin(request)
    return HTMLResponse(_ACC_BOARD_HTML)


# ==================== 启动 ====================
def start(bot_module=None, port=PORT):
    """在 bot 进程里起 HTTP 服务(daemon 线程)。失败只打日志, 绝不影响 bot 本体。"""
    global _BOT
    if bot_module is not None:
        _BOT = bot_module
    try:
        import uvicorn
    except Exception as _e:
        print(f"[miniapp] 没有 uvicorn, 跳过: {_e}", flush=True)
        return False
    _cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", access_log=False)
    _srv = uvicorn.Server(_cfg)

    def _run():
        try:
            asyncio.run(_srv.serve())
        except Exception as _e:
            print(f"[miniapp] 服务退出: {_e}", flush=True)

    threading.Thread(target=_run, daemon=True, name="miniapp-http").start()
    print(f"[miniapp] HTTP 服务已启动 http://127.0.0.1:{port} (公网 {PUBLIC_URL})", flush=True)
    return True
