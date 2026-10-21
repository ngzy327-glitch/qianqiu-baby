# -*- coding: utf-8 -*-
"""目标白名单闸门 (2026-10-21)

作用: 所有出站请求前先过这里 —— 只允许名单内的 host, 其余一律拦在本机,
      不发包、不重放、不扫描。防止模型/用户把工具指向未授权目标。

配置文件(默认 /opt/deepseek-bot/target_allowlist.json, 可用 TARGET_ALLOWLIST_FILE 覆盖):
    {
      "mode": "strict",                  # strict 拦截 | warn 只告警放行 | off 关闭
      "allow": ["example.com", "*.example.org", "10.0.0.0/8", "1.2.3.4"],
      "allow_private": true              # 回环/私网是否放行(本地靶机自测用)
    }

allow 支持三种写法:
    域名精确匹配      example.com
    子域通配          *.example.com   (含 example.com 本身)
    IP / CIDR         1.2.3.4        10.0.0.0/8

改完配置无需重启: 文件 mtime 变了就自动重载(最多 10 秒生效)。
"""
import ipaddress
import json
import os
import threading
from pathlib import Path
from urllib.parse import urlsplit

CFG_FILE = Path(os.getenv("TARGET_ALLOWLIST_FILE", "/opt/deepseek-bot/target_allowlist.json"))
_DEFAULT = {"mode": "strict", "allow": [], "allow_private": True}
_LOCK = threading.Lock()
_CACHE = {"stamp": None, "cfg": dict(_DEFAULT)}
_PRIVATE_NETS = [
    ipaddress.ip_network(x) for x in (
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
    )
]


def _norm(cfg):
    out = {"mode": str(cfg.get("mode") or "strict").lower(),
           "allow": [str(x).strip().lower() for x in (cfg.get("allow") or []) if str(x).strip()],
           "allow_private": bool(cfg.get("allow_private", True))}
    if out["mode"] not in ("strict", "warn", "off"):
        out["mode"] = "strict"
    return out


def _cfg():
    """读配置; 文件 mtime 变了才重读, 失败回落默认(严格模式)"""
    try:
        stamp = (CFG_FILE.stat().st_mtime, CFG_FILE.stat().st_size) if CFG_FILE.exists() else None
    except Exception:
        stamp = None
    with _LOCK:
        if stamp == _CACHE["stamp"] and _CACHE["cfg"] is not None:
            return _CACHE["cfg"]
        cfg = dict(_DEFAULT)
        if stamp is not None:
            try:
                cfg = json.loads(CFG_FILE.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"[guard] 白名单配置解析失败, 按严格模式处理: {e}", flush=True)
        cfg = _norm(cfg)
        env_mode = (os.getenv("TARGET_ALLOWLIST_MODE") or "").strip().lower()
        if env_mode in ("strict", "warn", "off"):
            cfg["mode"] = env_mode
        env_allow = (os.getenv("TARGET_ALLOWLIST") or "").strip()
        if env_allow:
            cfg["allow"] = [x.strip().lower() for x in env_allow.split(",") if x.strip()]
        _CACHE.update({"stamp": stamp, "cfg": cfg})
        return cfg


def host_of(target):
    """从 URL / host:port / 裸域名里取 host(小写, 去 IPv6 方括号)"""
    t = str(target or "").strip()
    if not t:
        return ""
    if "://" not in t:
        t = "http://" + t.lstrip("/")
    try:
        h = urlsplit(t).hostname or ""
    except Exception:
        h = ""
    return h.strip().strip("[]").lower()


def _is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except Exception:
        return False


def _ip_allowed(h, allow):
    try:
        ip = ipaddress.ip_address(h)
    except Exception:
        return False
    for item in allow:
        try:
            if "/" in item and ip in ipaddress.ip_network(item, strict=False):
                return True
        except Exception:
            pass
    return h in allow


def _is_private(h):
    try:
        ip = ipaddress.ip_address(h)
    except Exception:
        return h in ("localhost", "localhost.localdomain")
    return any(ip in n for n in _PRIVATE_NETS)


def _domain_allowed(h, allow):
    for item in allow:
        if item.startswith("*."):
            base = item[2:]
            if h == base or h.endswith("." + base):
                return True
        elif h == item:
            return True
    return False


def check(target):
    """返回 (放行?, host, 原因)。放行时原因为空。"""
    cfg = _cfg()
    h = host_of(target)
    mode = cfg["mode"]
    if mode == "off":
        return True, h, ""
    if not h:
        return False, "", "无法识别目标主机"
    if _is_ip(h):
        hit = _ip_allowed(h, cfg["allow"])
    else:
        hit = _domain_allowed(h, cfg["allow"])
    if hit:
        return True, h, ""
    if cfg["allow_private"] and _is_private(h):
        return True, h, ""
    why = f"目标 {h} 不在白名单"
    if mode == "warn":
        print(f"[guard] 告警(未拦截): {why}", flush=True)
        return True, h, why
    print(f"[guard] 已拦截: {why}", flush=True)
    return False, h, why


def deny(target):
    """给模块用的便捷入口: 放行返回 None; 拦截返回一句可直接回给用户的提示。"""
    ok, h, why = check(target)
    if ok:
        return None
    return (f"⛔ 已按目标白名单拦截: {why}。\n"
            f"如需允许, 把该域名/IP 加进 {CFG_FILE} 的 allow 列表 (支持 *.example.com、10.0.0.0/8)。")
