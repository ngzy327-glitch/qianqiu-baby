#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
web_session_daemon — 多账号常驻网页会话(2026-10-22)

干什么:
  每个账号一个独立的 Chromium user_data_dir(profile 目录), 独享 UA/视口/时区/语言/WebGL/代理。
  页面打开后**不关闭**, 常驻在后台; AI 后续用 click/type/see 继续操作, 登录态一直保留。
  浏览器退出后登录态也还在(profile 目录落盘), 下次 open 直接回到已登录状态。

架构:
  plugin(web_session.py) --unix socket--> 本进程(单 worker 线程持有 playwright)
  Playwright sync API 必须同线程调用, 所以所有指令进队列串行执行, 天然避免并发踩踏。

指令(JSON):
  {"act":"open","account":"main","url":"https://..."}
  {"act":"see","account":"main","full":false}
  {"act":"click","account":"main","selector":"#login"}   或 {"text":"登录"}
  {"act":"type","account":"main","selector":"input[name=q]","value":"关键词","enter":true}
  {"act":"press","account":"main","key":"Enter"}
  {"act":"scroll","account":"main","dy":800}
  {"act":"tabs"/"switch"/"close"/"list"...}

环境变量:
  BOT_BASE            默认 /opt/deepseek-bot, 决定 socket/审计/profile 目录位置
  WEB_SESSION_HEADLESS 1=无头(默认); 0=有头(需桌面/Xvfb, 方便肉眼看)
  WEB_SESSION_MAX     同时存活的账号浏览器数, 默认 5(LRU 淘汰, 淘汰只是关进程, 登录态不丢)
  WEB_SESSION_IDLE    空闲多少秒后关掉浏览器省内存, 默认 1800; 0=永不关

合规边界: 仅用于管理你自己拥有的账号与正常网页操作; 不用于绕过金融/支付/风控。
"""
import json
import os
import queue
import socket
import sys
import threading
import time
import traceback

BOT_BASE = os.getenv("BOT_BASE", "/opt/deepseek-bot")
SOCK_F = os.path.join(BOT_BASE, "web_session.sock")
PROFILE_DIR = os.path.join(BOT_BASE, "web_profiles")
AUDIT_F = os.path.join(BOT_BASE, "audit.log")
PROFILES_F = os.path.join(BOT_BASE, "browser_profiles.json")
ACCOUNTS_F = os.path.join(BOT_BASE, "accounts.json")

HEADLESS = os.getenv("WEB_SESSION_HEADLESS", "1") not in ("0", "false", "False")
MAX_SESSIONS = int(os.getenv("WEB_SESSION_MAX", "5") or 5)
IDLE_TTL = int(os.getenv("WEB_SESSION_IDLE", "1800") or 0)

# 写入类操作: 限流 + 审计; 其余只读直通
WRITE_ACTS = {"click", "type", "press", "open"}
W_LIMIT = 10          # 每账号每分钟写操作上限
W_RATE = {}

DEFAULT_PROFILES = {
    "desktop_cn": {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "viewport": [1440, 900], "screen": [1920, 1080],
        "tz": "Asia/Shanghai", "lang": "zh-CN", "platform": "Win32",
        "hardware_concurrency": 8, "device_memory": 8,
        "webgl": ["Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Direct3D11 vs_5_0 ps_5_0, D3D11)"],
    },
    "mobile_cn": {
        "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        "viewport": [390, 844], "screen": [390, 844],
        "tz": "Asia/Shanghai", "lang": "zh-CN", "platform": "iPhone",
        "hardware_concurrency": 4, "device_memory": 4,
        "webgl": ["Apple Inc.", "Apple GPU"],
    },
    "desktop_us": {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "viewport": [1512, 982], "screen": [1728, 1117],
        "tz": "America/New_York", "lang": "en-US", "platform": "MacIntel",
        "hardware_concurrency": 10, "device_memory": 8,
        "webgl": ["Google Inc. (Apple)", "ANGLE (Apple, Apple M2 Pro, OpenGL 4.1)"],
    },
}


# ---------------------------- 配置读取 ----------------------------
def _load_profiles():
    profs = dict(DEFAULT_PROFILES)
    try:
        if os.path.exists(PROFILES_F):
            d = json.loads(open(PROFILES_F, encoding="utf-8").read())
            if isinstance(d, dict):
                profs.update(d)
    except Exception:
        pass
    return profs


def _load_accounts():
    try:
        if os.path.exists(ACCOUNTS_F):
            d = json.loads(open(ACCOUNTS_F, encoding="utf-8").read())
            if isinstance(d, dict) and isinstance(d.get("accounts"), dict):
                return d["accounts"]
    except Exception:
        pass
    return {}


def _resolve_profile(account, req):
    """账号配置 > 请求指定 > 默认; 账号代理始终优先"""
    profs = _load_profiles()
    accts = _load_accounts()
    acct = accts.get(account) or {}
    web = acct.get("web") or {}
    name = req.get("profile") or web.get("profile") or "desktop_cn"
    prof = dict(profs.get(name) or DEFAULT_PROFILES["desktop_cn"])
    for k in ("ua", "viewport", "screen", "tz", "lang", "platform",
              "hardware_concurrency", "device_memory", "webgl"):
        if web.get(k):
            prof[k] = web[k]
        if req.get(k):
            prof[k] = req[k]
    px = acct.get("proxy") or web.get("proxy") or prof.get("proxy")
    prof["proxy"] = px if isinstance(px, dict) and px.get("host") else None
    prof["_name"] = name
    return prof


def _safe(name):
    return "".join(c for c in str(name) if c.isalnum() or c in "-_.")[:40] or "default"


# ---------------------------- 护栏 ----------------------------
def _rate_ok(account):
    now = time.time()
    win = [t for t in W_RATE.get(account, []) if now - t < 60]
    if len(win) >= W_LIMIT:
        W_RATE[account] = win
        return False
    win.append(now)
    W_RATE[account] = win
    return True


def _audit(account, act, args, ok, note=""):
    try:
        os.makedirs(os.path.dirname(AUDIT_F), exist_ok=True)
        rec = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "account": account,
               "act": act, "args": [str(x)[:80] for x in (args or [])][:4],
               "ok": bool(ok), "note": str(note)[:120], "src": "web"}
        with open(AUDIT_F, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


# ---------------------------- 浏览器 ----------------------------
INIT_JS_BASE = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
window.chrome = window.chrome || {runtime: {}};
"""


def _init_script(prof):
    """把配置里的指纹字段注入页面(navigator/WebGL), 与 UA/时区保持同源"""
    js = INIT_JS_BASE
    hc = prof.get("hardware_concurrency")
    dm = prof.get("device_memory")
    pf = prof.get("platform")
    lg = prof.get("lang")
    if hc:
        js += "Object.defineProperty(navigator,'hardwareConcurrency',{get:()=>%d});\n" % int(hc)
    if dm:
        js += "Object.defineProperty(navigator,'deviceMemory',{get:()=>%d});\n" % int(dm)
    if pf:
        js += "Object.defineProperty(navigator,'platform',{get:()=>%s});\n" % json.dumps(pf)
    if lg:
        js += "Object.defineProperty(navigator,'languages',{get:()=>[%s,%s]});\n" % (
            json.dumps(lg), json.dumps(lg.split("-")[0]))
    wg = prof.get("webgl") or []
    if len(wg) == 2:
        js += """
(() => {
  const V = %s, R = %s;
  const patch = (P) => { if (!P || !P.prototype) return;
    const orig = P.prototype.getParameter;
    P.prototype.getParameter = function (p) {
      if (p === 37445) return V;
      if (p === 37446) return R;
      return orig.call(this, p);
    };
  };
  patch(window.WebGLRenderingContext); patch(window.WebGL2RenderingContext);
})();
""" % (json.dumps(wg[0]), json.dumps(wg[1]))
    return js


def _proxy_arg(px):
    if not px or not px.get("host"):
        return None
    scheme = px.get("type") or "socks5"
    d = {"server": "%s://%s:%s" % (scheme, px["host"], int(px.get("port") or 1080))}
    if px.get("user"):
        d["username"] = px["user"]
        d["password"] = px.get("pass") or ""
    return d


def _launch(pw, account, prof):
    os.makedirs(PROFILE_DIR, exist_ok=True)
    udd = os.path.join(PROFILE_DIR, _safe(account))
    vw, vh = (prof.get("viewport") or [1440, 900])[:2]
    kw = dict(
        user_data_dir=udd,
        headless=HEADLESS,
        viewport={"width": int(vw), "height": int(vh)},
        user_agent=prof.get("ua") or None,
        timezone_id=prof.get("tz") or None,
        locale=prof.get("lang") or None,
        color_scheme="light",
        args=["--disable-blink-features=AutomationControlled",
              "--no-first-run", "--no-default-browser-check"],
    )
    if os.geteuid() == 0:                # root 下 Chromium 必须关沙箱, 否则起不来
        kw["args"] += ["--no-sandbox", "--disable-dev-shm-usage"]
    px = _proxy_arg(prof.get("proxy"))
    if px:
        kw["proxy"] = px
    kw = {k: v for k, v in kw.items() if v is not None}
    ctx = pw.chromium.launch_persistent_context(**kw)
    try:
        ctx.add_init_script(_init_script(prof))
    except Exception:
        pass
    return ctx


def _new_page(ctx):
    page = ctx.pages[0] if ctx.pages else ctx.new_page()
    try:
        page.set_default_timeout(15000)
        page.set_default_navigation_timeout(45000)
    except Exception:
        pass
    return page


def _page_state(page):
    try:
        title = page.title()
    except Exception:
        title = ""
    try:
        url = page.url
    except Exception:
        url = ""
    return title, url


def _pages(ctx):
    out = []
    for i, p in enumerate(ctx.pages):
        try:
            out.append({"index": i, "title": (p.title() or "")[:80], "url": p.url})
        except Exception:
            out.append({"index": i, "title": "", "url": ""})
    return out


def _locator(page, req):
    if req.get("selector"):
        loc = page.locator(req["selector"])
    elif req.get("text"):
        t = str(req["text"])
        exact = bool(req.get("exact"))
        loc = None
        # 文字定位优先命中可点元素, 避免 "登录" 误点到 "未登录" 这类包含关系
        for role in ("button", "link"):
            try:
                cand = page.get_by_role(role, name=t, exact=exact)
                if cand.count() > 0:
                    loc = cand
                    break
            except Exception:
                pass
        if loc is None:
            loc = page.get_by_text(t, exact=exact)
    elif req.get("placeholder"):
        loc = page.get_by_placeholder(str(req["placeholder"]))
    else:
        return None
    idx = int(req.get("index") or 0)
    return loc.nth(idx) if idx > 0 else loc.first


# ---------------------------- 指令执行 ----------------------------
def _exec(req, ctx, page):
    act = (req.get("act") or "see").strip().lower()

    if act in ("open", "goto"):
        url = req.get("url") or ""
        if not url:
            return {"ok": False, "error": "需要 url"}
        page.goto(url, wait_until="domcontentloaded",
                  timeout=int(req.get("timeout") or 45) * 1000)
        page.wait_for_timeout(int(req.get("wait") or 1500))
        title, cur = _page_state(page)
        return {"ok": True, "msg": "已打开", "title": title, "url": cur}

    if act == "see":
        page.wait_for_timeout(int(req.get("wait") or 300))
        title, cur = _page_state(page)
        shot = req.get("out") or os.path.join("/tmp", "web_%s.png" % _safe(req.get("account") or "default"))
        try:
            page.screenshot(path=shot, full_page=bool(req.get("full")))
        except Exception:
            shot = ""
        text = ""
        try:
            text = page.inner_text("body")[: int(req.get("chars") or 4000)]
        except Exception:
            pass
        return {"ok": True, "title": title, "url": cur, "screenshot": shot,
                "text": text, "tabs": _pages(ctx)}

    if act == "click":
        hit = ""
        if req.get("x") is not None and req.get("y") is not None:
            page.mouse.click(float(req["x"]), float(req["y"]))
        else:
            el = _locator(page, req)
            if el is None:
                return {"ok": False, "error": "需要 selector / text / x,y"}
            el.wait_for(state="visible", timeout=int(req.get("timeout") or 15) * 1000)
            try:
                hit = el.evaluate(
                    "e => (e.tagName||'') + '|' + ((e.innerText||e.value||'').trim().slice(0,40))")
            except Exception:
                pass
            el.click(timeout=int(req.get("timeout") or 15) * 1000)
        before = len(ctx.pages)
        page.wait_for_timeout(int(req.get("wait") or 1200))
        if len(ctx.pages) > before:          # 点击可能开了新窗口/标签
            page = ctx.pages[-1]
            try:
                page.bring_to_front()
            except Exception:
                pass
        title, cur = _page_state(page)
        return {"ok": True, "msg": "已点击" + (" → %s" % hit if hit else ""),
                "title": title, "url": cur, "tabs": _pages(ctx)}

    if act == "type":
        val = req.get("value")
        if val is None:
            return {"ok": False, "error": "需要 value"}
        el = _locator(page, req)
        if el is None:
            return {"ok": False, "error": "需要 selector / text / placeholder"}
        el.wait_for(state="visible", timeout=int(req.get("timeout") or 15) * 1000)
        if req.get("append"):
            el.click()
            el.press_sequentially(str(val), delay=int(req.get("delay") or 60))
        else:
            el.fill(str(val))
        if req.get("enter"):
            el.press("Enter")
            page.wait_for_timeout(1200)
        title, cur = _page_state(page)
        return {"ok": True, "msg": "已输入", "title": title, "url": cur, "tabs": _pages(ctx)}

    if act == "press":
        key = req.get("key") or "Enter"
        page.keyboard.press(key)
        page.wait_for_timeout(int(req.get("wait") or 800))
        title, cur = _page_state(page)
        return {"ok": True, "msg": "已按键 %s" % key, "title": title, "url": cur}

    if act == "scroll":
        page.mouse.wheel(0, int(req.get("dy") or 800))
        page.wait_for_timeout(int(req.get("wait") or 500))
        title, cur = _page_state(page)
        return {"ok": True, "msg": "已滚动", "title": title, "url": cur}

    if act == "back":
        page.go_back()
        page.wait_for_timeout(1000)
        title, cur = _page_state(page)
        return {"ok": True, "title": title, "url": cur}

    if act == "reload":
        page.reload()
        page.wait_for_timeout(1200)
        title, cur = _page_state(page)
        return {"ok": True, "title": title, "url": cur}

    if act == "wait":
        page.wait_for_timeout(int(req.get("ms") or 2000))
        title, cur = _page_state(page)
        return {"ok": True, "title": title, "url": cur}

    if act == "tabs":
        return {"ok": True, "tabs": _pages(ctx), "current": ctx.pages.index(page) if page in ctx.pages else 0}

    if act == "switch":
        idx = int(req.get("index") or 0)
        if idx < 0 or idx >= len(ctx.pages):
            return {"ok": False, "error": "标签 index 越界, 共 %d 个" % len(ctx.pages), "tabs": _pages(ctx)}
        p = ctx.pages[idx]
        p.bring_to_front()
        title, cur = _page_state(p)
        return {"ok": True, "msg": "已切换", "title": title, "url": cur, "tabs": _pages(ctx), "_page": p}

    if act == "new_tab":
        p = ctx.new_page()
        if req.get("url"):
            p.goto(req["url"], wait_until="domcontentloaded")
        return {"ok": True, "msg": "已新开标签", "tabs": _pages(ctx), "_page": p}

    if act == "close_tab":
        idx = int(req.get("index") or -1)
        if len(ctx.pages) <= 1:
            return {"ok": False, "error": "只剩一个标签, 请用 act=close 关闭整号"}
        p = ctx.pages[idx] if 0 <= idx < len(ctx.pages) else page
        p.close()
        return {"ok": True, "msg": "已关闭标签", "tabs": _pages(ctx), "_page": ctx.pages[0]}

    return {"ok": False, "error": "未知 act '%s'" % act}


# ---------------------------- worker(独占 playwright) ----------------------------
def _worker(q):
    sessions = {}          # account -> {ctx, page, prof, last}
    pw = None
    while True:
        item = q.get()
        if item is None:
            break
        rid, req, box = item
        act = (req.get("act") or "see").strip().lower()
        account = str(req.get("account") or "default")[:40] or "default"
        try:
            # 空闲回收(只关进程, profile 目录保留 → 登录态不丢)
            if IDLE_TTL > 0:
                now = time.time()
                for k in list(sessions):
                    if now - sessions[k]["last"] > IDLE_TTL:
                        try:
                            sessions[k]["ctx"].close()
                        except Exception:
                            pass
                        sessions.pop(k, None)

            if act == "list":
                resp = {"ok": True, "sessions": [
                    {"account": k, "title": v["page"].title() if v["page"] else "",
                     "url": v["page"].url if v["page"] else "",
                     "profile": v["prof"].get("_name"), "idle": int(time.time() - v["last"])}
                    for k, v in sessions.items()]}
                box["resp"] = resp
                box["event"].set()
                continue

            if act == "close":
                s = sessions.pop(account, None)
                if s:
                    try:
                        s["ctx"].close()
                    except Exception:
                        pass
                box["resp"] = {"ok": True, "msg": "已关闭 %s 的浏览器(登录态已保存)" % account}
                box["event"].set()
                continue

            # 写操作护栏
            if act in WRITE_ACTS and not _rate_ok(account):
                _audit(account, act, [req.get("url") or req.get("selector") or req.get("text")], False, "rate_limited")
                box["resp"] = {"ok": False, "error": "操作过于频繁(每账号每分钟 %d 次写操作上限), 请稍后" % W_LIMIT}
                box["event"].set()
                continue

            s = sessions.get(account)
            if s is None:
                if pw is None:
                    from playwright.sync_api import sync_playwright
                    pw = sync_playwright().start()
                if MAX_SESSIONS > 0 and len(sessions) >= MAX_SESSIONS:
                    old = min(sessions, key=lambda k: sessions[k]["last"])
                    try:
                        sessions[old]["ctx"].close()
                    except Exception:
                        pass
                    sessions.pop(old, None)
                prof = _resolve_profile(account, req)
                ctx = _launch(pw, account, prof)
                s = {"ctx": ctx, "page": _new_page(ctx), "prof": prof, "last": time.time()}
                sessions[account] = s
            s["last"] = time.time()
            ctx, page = s["ctx"], s["page"]
            if page.is_closed():
                page = s["page"] = _new_page(ctx)

            res = _exec(req, ctx, page)
            if isinstance(res, dict) and res.get("_page") is not None:
                s["page"] = res.pop("_page")
            res.setdefault("profile", s["prof"].get("_name"))
            res.setdefault("account", account)
            _audit(account, act, [req.get("url") or req.get("selector") or req.get("text")],
                   res.get("ok", True), "write" if act in WRITE_ACTS else "read")
            box["resp"] = res
        except ImportError:
            box["resp"] = {"ok": False, "error": "未安装 playwright: pip install playwright && playwright install chromium"}
            _audit(account, act, [], False, "no_playwright")
        except Exception as e:
            box["resp"] = {"ok": False, "error": "%s: %s" % (type(e).__name__, str(e)[:300])}
            _audit(account, act, [], False, type(e).__name__)
            try:
                traceback.print_exc()
            except Exception:
                pass
        finally:
            box["event"].set()


# ---------------------------- socket 服务 ----------------------------
def _conn(conn, q):
    try:
        conn.settimeout(190)
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buf += chunk
            if len(buf) > 1 << 20:
                return
        req = json.loads(buf.split(b"\n", 1)[0].decode("utf-8") or "{}")
        box = {"event": threading.Event(), "resp": None}
        q.put((0, req, box))
        box["event"].wait(180)
        resp = box["resp"] or {"ok": False, "error": "执行超时"}
        conn.sendall((json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8"))
    except Exception as e:
        try:
            conn.sendall((json.dumps({"ok": False, "error": "daemon: %s" % str(e)[:200]}, ensure_ascii=False) + "\n").encode("utf-8"))
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    os.makedirs(BOT_BASE, exist_ok=True)
    os.makedirs(PROFILE_DIR, exist_ok=True)
    q = queue.Queue()
    threading.Thread(target=_worker, args=(q,), daemon=True).start()
    if os.path.exists(SOCK_F):
        try:
            os.unlink(SOCK_F)
        except Exception:
            pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK_F)
    os.chmod(SOCK_F, 0o600)
    srv.listen(16)
    print("[web_session] daemon 已启动: %s (headless=%s max=%s idle=%s)"
          % (SOCK_F, HEADLESS, MAX_SESSIONS, IDLE_TTL), flush=True)
    while True:
        try:
            conn, _ = srv.accept()
            threading.Thread(target=_conn, args=(conn, q), daemon=True).start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print("[web_session] accept 异常: %s" % e, flush=True)
            time.sleep(0.5)


if __name__ == "__main__":
    main()
