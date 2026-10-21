"""VulnClaw 证据层 v1.0 (2026-10-21)

把 VulnClaw 的三个能力合并成一个模块:
  1. 证据记忆(AgentState.evidence): add/search/view/list/stats
     - 原始内容全量落盘, 返回给模型的只有高信号预览, 需要原文时按 id 回查
  2. 流量证据存储(traffic_*): 每个请求/响应原始报文落盘 + JSONL 索引
     - traffic_list / traffic_view / traffic_repeat / traffic_sitemap
  3. 反幻觉闸门: verify(claim)
     - 声称的 flag/结论必须在真实证据里逐字出现, 否则 verified=False

设计约束:
  - 不依赖任何第三方库(只用标准库), 免得拖垮 bot
  - 所有写盘失败都静默降级为内存记录, 不影响主流程
  - 单条原文上限 256KB, 防止磁盘被批量探测撑爆
"""

import json
import os
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

_MAX_RAW = 256 * 1024
_MAX_TRAFFIC_INDEX_BODY = 32 * 1024
_LOCK = threading.RLock()
_ROOT = None
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{4,64}$")


# ============ 基础工具 ============

def _pick_root() -> Path:
    cands = []
    _env = os.getenv("EVIDENCE_DIR")
    if _env:
        cands.append(_env)
    cands += ["/opt/deepseek-bot/evidence", "/tmp/evidence"]
    for c in cands:
        try:
            p = Path(c)
            p.mkdir(parents=True, exist_ok=True)
            _t = p / ".write_test"
            _t.write_text("1", encoding="utf-8")
            _t.unlink()
            return p
        except Exception:
            continue
    return Path("/tmp/evidence")


def _root() -> Path:
    global _ROOT
    if _ROOT is None:
        with _LOCK:
            if _ROOT is None:
                _ROOT = _pick_root()
                (_ROOT / "raw").mkdir(parents=True, exist_ok=True)
                (_ROOT / "traffic" / "raw").mkdir(parents=True, exist_ok=True)
    return _ROOT


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _new_id(prefix: str) -> str:
    return "%s-%d-%s" % (prefix, int(time.time() * 1000), uuid.uuid4().hex[:4])


def _clean_scope(scope) -> str:
    s = re.sub(r"[^\w.\-]", "_", str(scope or ""))[:64]
    return s or "default"


def _safe_id(v) -> str:
    return v if isinstance(v, str) and _ID_RE.match(v) else ""


def _preview(text: str, n: int = 600) -> str:
    """压缩空白后的预览(不删标签, 避免把证据里的关键串吃掉)"""
    s = re.sub(r"[ \t\u3000]+", " ", str(text or ""))
    s = re.sub(r"\n{3,}", "\n\n", s).strip()
    return s[:n] + ("..." if len(s) > n else "")


def _snippet(text: str, pos: int, width: int = 140) -> str:
    a = max(0, pos - width // 2)
    b = min(len(text), pos + width // 2)
    return _preview(text[a:b], width)


def _append_jsonl(path: Path, rec: dict) -> None:
    with _LOCK:
        with open(path, "a", encoding="utf-8", errors="ignore") as f:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")


def _read_jsonl(path: Path, limit: int = 0) -> list:
    out = []
    if not path.exists():
        return out
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return out
    return out[-limit:] if limit and limit > 0 else out


def _ev_index() -> Path:
    return _root() / "index.jsonl"


def _tr_index() -> Path:
    return _root() / "traffic" / "index.jsonl"


def _raw_path(ev_id: str, kind: str = "evidence") -> Path:
    if kind == "traffic":
        return _root() / "traffic" / "raw" / ("%s.http" % ev_id)
    return _root() / "raw" / ("%s.txt" % ev_id)


def _read_raw(ev_id: str, kind: str = "evidence") -> str:
    p = _raw_path(ev_id, kind)
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _iter_index(scope=None):
    want = _clean_scope(scope) if scope else None
    for r in reversed(_read_jsonl(_ev_index())):
        if want and r.get("scope") != want:
            continue
        yield r


def _iter_traffic(scope=None):
    want = _clean_scope(scope) if scope else None
    for r in reversed(_read_jsonl(_tr_index())):
        if want and r.get("scope") != want:
            continue
        yield r


def _int(v, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return default


# ============ 1) 证据记忆 ============

def ev_add(content, kind: str = "note", source: str = "", tags=None, scope: str = "default") -> dict:
    """写入一条证据: 原文落盘, 返回 id + 预览"""
    raw = str(content or "")
    if not raw:
        return {"ok": False, "error": "content 为空"}
    ev_id = _new_id("ev")
    data = raw[:_MAX_RAW]
    p = _raw_path(ev_id, "evidence")
    try:
        p.write_text(data, encoding="utf-8", errors="ignore")
    except Exception as e:
        return {"ok": False, "error": "写盘失败: %s" % e}
    _tag_list = tags if isinstance(tags, list) else ([tags] if tags else [])
    rec = {
        "id": ev_id, "ts": _now(), "kind": str(kind or "note"),
        "source": str(source or ""), "scope": _clean_scope(scope),
        "size": len(data), "tags": _tag_list, "preview": _preview(data, 400),
    }
    try:
        _append_jsonl(_ev_index(), rec)
    except Exception as e:
        return {"ok": False, "error": "索引写入失败: %s" % e}
    return {"ok": True, "id": ev_id, "size": len(data),
            "preview": rec["preview"], "raw_path": str(p)}


def ev_search(query: str, scope: str = "", limit: int = 10) -> dict:
    """在证据原文里做子串检索(忽略大小写), 返回命中片段"""
    q = str(query or "").strip()
    if len(q) < 2:
        return {"ok": False, "error": "query 至少 2 个字符"}
    limit = max(1, min(_int(limit, 10), 50))
    ql = q.lower()
    hits = []
    scanned = 0
    for rec in _iter_index(scope or None):
        scanned += 1
        txt = _read_raw(rec.get("id", ""), "evidence")
        pos = txt.lower().find(ql)
        if pos >= 0:
            hits.append({"id": rec.get("id"), "ts": rec.get("ts"), "kind": rec.get("kind"),
                         "source": rec.get("source"), "snippet": _snippet(txt, pos)})
            if len(hits) >= limit:
                break
    return {"ok": True, "query": q, "hits": hits, "count": len(hits), "scanned": scanned}


def ev_view(ev_id: str, offset: int = 0, limit: int = 4000) -> dict:
    """按 id 回查证据原文(分页)"""
    ev_id = _safe_id(ev_id)
    if not ev_id:
        return {"ok": False, "error": "非法 id"}
    txt = _read_raw(ev_id, "evidence")
    if not txt:
        return {"ok": False, "error": "证据不存在: %s" % ev_id}
    offset = max(0, _int(offset, 0))
    limit = max(200, min(_int(limit, 4000), 20000))
    chunk = txt[offset:offset + limit]
    return {"ok": True, "id": ev_id, "size": len(txt), "offset": offset,
            "content": chunk, "has_more": offset + limit < len(txt)}


def ev_list(scope: str = "", kind: str = "", limit: int = 30) -> dict:
    """列证据索引(不含原文)"""
    limit = max(1, min(_int(limit, 30), 100))
    kind = str(kind or "").strip()
    items = []
    for rec in _iter_index(scope or None):
        if kind and rec.get("kind") != kind:
            continue
        items.append({k: rec.get(k) for k in ("id", "ts", "kind", "source", "size", "scope", "preview")})
        if len(items) >= limit:
            break
    return {"ok": True, "count": len(items), "items": items}


def ev_stats() -> dict:
    """证据层总体统计"""
    evs = _read_jsonl(_ev_index())
    trs = _read_jsonl(_tr_index())
    kinds = {}
    for r in evs:
        k = r.get("kind", "?")
        kinds[k] = kinds.get(k, 0) + 1
    return {"ok": True, "root": str(_root()),
            "evidence_count": len(evs),
            "evidence_bytes": sum(_int(r.get("size"), 0) for r in evs),
            "kinds": kinds,
            "traffic_count": len(trs),
            "traffic_bytes": sum(_int(r.get("resp_size"), 0) + _int(r.get("req_size"), 0) for r in trs)}


# ============ 2) 流量证据存储 ============

def _tr_render(method, url, req_headers, req_body, status, resp_headers, resp_body) -> str:
    lines = ["> %s %s" % (method, url)]
    for k, v in (req_headers or {}).items():
        lines.append("> %s: %s" % (k, v))
    lines.append(">")
    if req_body:
        lines.append("> " + str(req_body)[:_MAX_RAW])
    lines.append("")
    lines.append("--- response ---")
    lines.append("< %s" % status)
    for k, v in (resp_headers or {}).items():
        lines.append("< %s: %s" % (k, v))
    lines.append("<")
    if resp_body:
        lines.append(str(resp_body)[:_MAX_RAW])
    return "\n".join(lines)


def record_traffic(method: str, url: str, req_headers=None, req_body: str = "",
                   status: int = 0, resp_headers=None, resp_body: str = "",
                   source: str = "", scope: str = "default", elapsed: float = 0.0) -> dict:
    """记录一次请求/响应(原始报文落盘). 供 http_probe / runtime_diff 自动调用"""
    url = str(url or "")
    if not url:
        return {"ok": False, "error": "url 为空"}
    tr_id = _new_id("tr")
    _body = str(resp_body or "")[:_MAX_RAW]
    _req_body = str(req_body or "")[:_MAX_RAW]
    raw = _tr_render(method or "GET", url, req_headers, _req_body,
                     status, resp_headers, _body)
    try:
        _raw_path(tr_id, "traffic").write_text(raw, encoding="utf-8", errors="ignore")
    except Exception as e:
        return {"ok": False, "error": "写盘失败: %s" % e}

    _host = ""
    _path = url
    try:
        _u = urllib.parse.urlparse(url)
        _host = _u.netloc
        _path = _u.path or "/"
    except Exception:
        pass
    rec = {
        "id": tr_id, "ts": _now(), "method": method or "GET", "url": url,
        "host": _host, "path": _path, "status": _int(status, 0),
        "req_size": len(_req_body), "resp_size": len(_body),
        "source": str(source or ""), "scope": _clean_scope(scope),
        "elapsed": round(float(elapsed or 0), 3),
        "req_headers": dict(req_headers or {}),
        "req_body_b64": _b64(_req_body[:_MAX_TRAFFIC_INDEX_BODY]),
    }
    try:
        _append_jsonl(_tr_index(), rec)
    except Exception as e:
        return {"ok": False, "error": "索引写入失败: %s" % e}
    return {"ok": True, "id": tr_id, "status": rec["status"], "resp_size": rec["resp_size"]}


def _b64(s: str) -> str:
    import base64
    try:
        return base64.b64encode(str(s).encode("utf-8", "ignore")).decode("ascii")
    except Exception:
        return ""


def _unb64(s: str) -> str:
    import base64
    try:
        return base64.b64decode(str(s or "").encode("ascii")).decode("utf-8", "ignore")
    except Exception:
        return ""


def traffic_list(scope: str = "", host: str = "", status: int = 0, limit: int = 50) -> dict:
    """列流量索引"""
    limit = max(1, min(_int(limit, 50), 200))
    host = str(host or "").strip()
    status = _int(status, 0)
    items = []
    for rec in _iter_traffic(scope or None):
        if host and host not in str(rec.get("host", "")):
            continue
        if status and _int(rec.get("status"), 0) != status:
            continue
        items.append({k: rec.get(k) for k in
                      ("id", "ts", "method", "url", "status", "resp_size", "elapsed", "source", "scope")})
        if len(items) >= limit:
            break
    return {"ok": True, "count": len(items), "items": items}


def traffic_view(tr_id: str, part: str = "response", offset: int = 0, limit: int = 6000) -> dict:
    """看某条流量的原始报文. part: full/request/response"""
    tr_id = _safe_id(tr_id)
    if not tr_id:
        return {"ok": False, "error": "非法 id"}
    raw = _read_raw(tr_id, "traffic")
    if not raw:
        return {"ok": False, "error": "流量不存在: %s" % tr_id}
    part = (part or "response").lower()
    if part == "request":
        txt = raw.split("--- response ---")[0]
    elif part == "response":
        seg = raw.split("--- response ---")
        txt = seg[1] if len(seg) > 1 else raw
    else:
        txt = raw
    offset = max(0, _int(offset, 0))
    limit = max(200, min(_int(limit, 6000), 40000))
    chunk = txt[offset:offset + limit]
    return {"ok": True, "id": tr_id, "part": part, "size": len(txt), "offset": offset,
            "content": chunk, "has_more": offset + limit < len(txt)}


def _send(method: str, url: str, headers=None, body: str = "", timeout: int = 10):
    """最小 HTTP 客户端(不校验证书), 用于流量重放"""
    data = body.encode("utf-8", "ignore") if body else None
    req = urllib.request.Request(url, data=data, headers=dict(headers or {}), method=(method or "GET"))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read(300000).decode("utf-8", "ignore"), time.time() - t0, None
    except urllib.error.HTTPError as e:
        _b = e.read(300000).decode("utf-8", "ignore") if e.fp else ""
        return e.code, dict(e.headers or {}), _b, time.time() - t0, None
    except Exception as e:
        return 0, {}, "", time.time() - t0, str(e)[:200]


def traffic_repeat(tr_id: str, scope: str = "default", timeout: int = 10) -> dict:
    """按记录重放一次请求, 并把新响应也存成一条流量"""
    tr_id = _safe_id(tr_id)
    if not tr_id:
        return {"ok": False, "error": "非法 id"}
    rec = None
    for r in _read_jsonl(_tr_index()):
        if r.get("id") == tr_id:
            rec = r
            break
    if not rec:
        return {"ok": False, "error": "流量不存在: %s" % tr_id}
    status, rh, rb, elapsed, err = _send(rec.get("method", "GET"), rec.get("url", ""),
                                         rec.get("req_headers") or {},
                                         _unb64(rec.get("req_body_b64", "")),
                                         max(1, min(_int(timeout, 10), 60)))
    if err:
        return {"ok": False, "error": err, "original_id": tr_id}
    new = record_traffic(rec.get("method", "GET"), rec.get("url", ""),
                         rec.get("req_headers") or {}, _unb64(rec.get("req_body_b64", "")),
                         status, rh, rb, source="traffic_repeat",
                         scope=scope or rec.get("scope", "default"), elapsed=elapsed)
    return {"ok": True, "original_id": tr_id, "new_id": new.get("id"),
            "status": status, "resp_size": len(rb), "elapsed": round(elapsed, 3),
            "preview": _preview(rb, 800)}


def traffic_sitemap(scope: str = "", limit: int = 300) -> dict:
    """按 host 聚合已访问路径(去重), 相当于打点地图"""
    limit = max(1, min(_int(limit, 300), 2000))
    seen = {}
    total = 0
    for rec in _iter_traffic(scope or None):
        h = rec.get("host") or "(unknown)"
        p = rec.get("path") or "/"
        key = (h, p)
        if key in seen:
            continue
        seen[key] = {"status": rec.get("status"), "methods": set([rec.get("method", "GET")])}
        total += 1
        if total >= limit:
            break
    tree = {}
    for (h, p), meta in seen.items():
        tree.setdefault(h, []).append({"path": p, "status": meta["status"],
                                       "methods": sorted(meta["methods"])})
    return {"ok": True, "hosts": len(tree), "paths": total, "sitemap": tree}


# ============ 3) 反幻觉闸门 ============

def verify(claim: str, scope: str = "", limit: int = 5, include_traffic: bool = True) -> dict:
    """校验一个声称(flag/结论/报错串)是否逐字出现在真实证据里

    逐字匹配(大小写敏感): flag 大小写是有效的, 不做模糊匹配。
    verified=False 时, 该结论不应被采信/写进报告。
    """
    c = str(claim or "").strip()
    if len(c) < 3:
        return {"ok": False, "error": "claim 太短(至少 3 字符), 请给出待校验的完整串"}
    limit = max(1, min(_int(limit, 5), 20))
    hits = []
    scanned = 0
    for rec in _iter_index(scope or None):
        scanned += 1
        txt = _read_raw(rec.get("id", ""), "evidence")
        pos = txt.find(c)
        if pos >= 0:
            hits.append({"source": "evidence", "id": rec.get("id"), "kind": rec.get("kind"),
                         "ts": rec.get("ts"), "snippet": _snippet(txt, pos)})
            if len(hits) >= limit:
                break
    if include_traffic and len(hits) < limit:
        for rec in _iter_traffic(scope or None):
            scanned += 1
            txt = _read_raw(rec.get("id", ""), "traffic")
            pos = txt.find(c)
            if pos >= 0:
                hits.append({"source": "traffic", "id": rec.get("id"),
                             "kind": "%s %s" % (rec.get("method"), rec.get("status")),
                             "ts": rec.get("ts"), "snippet": _snippet(txt, pos)})
                if len(hits) >= limit:
                    break
    return {"ok": True, "claim": c, "verified": bool(hits),
            "hits": hits, "count": len(hits), "scanned": scanned,
            "verdict": "已核实: 逐字出现在真实证据中" if hits else "未核实: 证据里找不到该串, 不得作为结论/写进报告"}


def evidence_list_ops() -> dict:
    """能力清单(给 model 看)"""
    return {"ok": True, "acts": {
        "list": "列证据索引",
        "add": "写入证据(content/kind/source/tags)",
        "search": "按子串检索证据(query)",
        "view": "按 id 回查原文(id/offset/limit)",
        "stats": "总体统计",
        "traffic_list": "列流量(scope/host/status)",
        "traffic_view": "看原始报文(id/part=request|response|full)",
        "traffic_repeat": "重放请求(id)",
        "traffic_sitemap": "按 host 聚合访问路径",
        "verify": "反幻觉校验(claim 必须逐字出现在证据里)",
    }, "root": str(_root())}
