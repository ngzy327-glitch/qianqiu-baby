#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
web_visit — 带指纹隔离的网页访问插件(2026-10-22)
用法(由 bot 框架以 JSON argv[1] 调用):
  {"url": "https://...", "profile": "mobile_cn", "action": "text|html|screenshot", "out": "/tmp/x.png"}

指纹模板: /opt/deepseek-bot/browser_profiles.json
  {"mobile_cn": {"ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X)...",
                 "viewport": [390, 844], "tz": "Asia/Shanghai", "lang": "zh-CN",
                 "proxy": {"type":"socks5","host":"1.2.3.4","port":1080}},
   "desktop_us": {...}}

后端优先级: playwright(装了就用, 指纹控制最全) → obscura(本机 Rust 无头, --stealth)。
合规边界: 本工具用于自有系统测试/隐私保护/多账号各自的正常浏览; 不要用于绕过
金融/支付/限购/投票等网站的反欺诈风控。
"""
import json, os, subprocess, sys

BOT_BASE = os.getenv("BOT_BASE", "/opt/deepseek-bot")
PROFILES_F = os.path.join(BOT_BASE, "browser_profiles.json")

DEFAULT_PROFILES = {
    "mobile_cn": {
        "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        "viewport": [390, 844], "tz": "Asia/Shanghai", "lang": "zh-CN",
    },
    "desktop_us": {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "viewport": [1440, 900], "tz": "America/New_York", "lang": "en-US",
    },
}


def load_profiles():
    try:
        if os.path.exists(PROFILES_F):
            d = json.loads(open(PROFILES_F, encoding="utf-8").read())
            if isinstance(d, dict) and d:
                return d
    except Exception:
        pass
    return dict(DEFAULT_PROFILES)


def via_playwright(url, prof, action, out, timeout):
    """playwright 后端: 完整指纹控制(UA/视口/时区/语言/代理 + webdriver 隐藏)"""
    from playwright.sync_api import sync_playwright
    vw, vh = (prof.get("viewport") or [1440, 900])[:2]
    ctx_kw = dict(
        user_agent=prof.get("ua") or None,
        viewport={"width": int(vw), "height": int(vh)},
        timezone_id=prof.get("tz") or None,
        locale=prof.get("lang") or None,
    )
    px = prof.get("proxy") or {}
    if px.get("host"):
        ctx_kw["proxy"] = {"server": f"{px.get('type','socks5')}://{px['host']}:{int(px.get('port',1080))}"}
        if px.get("user"):
            ctx_kw["proxy"]["username"] = px["user"]
            ctx_kw["proxy"]["password"] = px.get("pass", "")
    ctx_kw = {k: v for k, v in ctx_kw.items() if v}
    with sync_playwright() as p:
        b = p.chromium.launch(args=["--disable-blink-features=AutomationControlled"])
        ctx = b.new_context(**ctx_kw)
        # 隐藏 webdriver 痕迹
        ctx.add_init_script("Object.defineProperty(navigator,'webdriver',{get:()=>undefined})")
        pg = ctx.new_page()
        pg.goto(url, timeout=int(timeout) * 1000)
        pg.wait_for_timeout(2500)
        if action == "screenshot":
            pg.screenshot(path=out, full_page=False)
            print(f"OK 截图已存 {out}")
        elif action == "html":
            print(pg.content()[:8000])
        else:
            print(pg.inner_text("body")[:6000])
        b.close()


def via_obscura(url, prof, action, out, timeout):
    """obscura 后端(本机 Rust 无头, 自带 --stealth): 指纹参数尽力映射"""
    act = "text" if action not in ("html", "screenshot") else action
    cmd = ["obscura", "--stealth", "fetch", url]
    if prof.get("ua"):
        cmd += ["--user-agent", prof["ua"]]
    if act == "screenshot":
        cmd += ["-s", out]
    else:
        cmd += ["--dump", act]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=int(timeout))
    print(r.stdout[-6000:] if r.stdout else r.stderr[-2000:])


def main():
    try:
        argv = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
    except Exception:
        argv = {}
    url = argv.get("url") or ""
    if not url:
        print("需要 url")
        return
    profiles = load_profiles()
    pname = argv.get("profile") or ""
    if pname == "list":
        for k, v in profiles.items():
            print(f"· {k}: ua={(v.get('ua') or '')[:50]}… tz={v.get('tz','-')} lang={v.get('lang','-')} proxy={'有' if v.get('proxy') else '直连'}")
        print("\n编辑 browser_profiles.json 增删模板")
        return
    prof = profiles.get(pname) or {}
    if pname and not prof:
        print(f"未知 profile '{pname}', 可用: {' / '.join(profiles.keys())} (或用 list 查看)")
        return
    action = argv.get("action", "text")
    out = argv.get("out", "/tmp/web_visit.png")
    timeout = int(argv.get("timeout", 45))
    try:
        via_playwright(url, prof, action, out, timeout)
        return
    except ImportError:
        pass
    except Exception as e:
        print(f"playwright 失败({type(e).__name__}: {str(e)[:150]}), 回退 obscura")
    try:
        via_obscura(url, prof, action, out, timeout)
    except FileNotFoundError:
        print("无可用后端: pip install playwright && playwright install chromium, 或安装 obscura")
    except Exception as e:
        print(f"obscura 失败: {str(e)[:200]}")


if __name__ == "__main__":
    main()
