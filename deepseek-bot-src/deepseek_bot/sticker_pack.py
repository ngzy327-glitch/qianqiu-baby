"""
表情包管理 — 保存/搜索/发送 GIF 表情包
存储: {DSB_DATA_DIR}/stickers/  (gif/webp/mp4)
索引: {DSB_DATA_DIR}/stickers/index.json  [{name, path, tags, source, saved_at}]
"""
import json
import os
import time
import random
import hashlib
from pathlib import Path

DATA_DIR = os.getenv("DSB_DATA_DIR", "/opt/deepseek-bot").rstrip("/")
STICKER_DIR = Path(DATA_DIR) / "stickers"
INDEX_FILE = STICKER_DIR / "index.json"
# 2026-10-25 只收真正的表情包格式: 之前把 png/jpg 也收进来, 随机发送时会把普通照片当表情包发出去
ALLOWED_EXT = (".gif", ".webp", ".mp4")
MAX_SIZE = 12 * 1024 * 1024  # 超过 12MB 的不当表情包(多半是视频/长图)

try:
    STICKER_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass


def _load_index() -> list:
    try:
        if INDEX_FILE.exists():
            return json.loads(INDEX_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return []


def _save_index(idx: list):
    try:
        INDEX_FILE.write_text(json.dumps(idx, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def _file_hash(path: Path) -> str:
    try:
        h = hashlib.sha1()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(262144), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def save_sticker(file_path: str, name: str = "", tags: str = "", source: str = "") -> dict:
    """保存一个表情包到本地库, 返回记录(同内容去重)"""
    src = Path(file_path)
    if not src.exists():
        return {"ok": False, "error": f"文件不存在: {file_path}"}
    ext = src.suffix.lower()
    if ext not in ALLOWED_EXT:
        return {"ok": False, "error": f"不支持的格式: {ext}(只收 {', '.join(ALLOWED_EXT)})"}
    try:
        if src.stat().st_size > MAX_SIZE:
            return {"ok": False, "error": f"文件过大({src.stat().st_size}B), 不当表情包保存"}
    except Exception:
        pass
    fh = _file_hash(src)
    idx = _load_index()
    # 同内容已存过 → 直接返回旧记录, 不再重复占空间(修"同一张表情反复存一堆")
    if fh:
        for s in idx:
            if s.get("hash") == fh:
                return {"ok": True, "sticker": s, "deduped": True}
    ts = int(time.time())
    fname = name or f"sticker_{ts}_{random.randint(1000,9999)}"
    if not fname.endswith(ext):
        fname += ext
    dst = STICKER_DIR / fname
    n = 1
    while dst.exists():
        dst = STICKER_DIR / f"{Path(fname).stem}_{n}{ext}"
        n += 1
    try:
        dst.write_bytes(src.read_bytes())
    except Exception as e:
        return {"ok": False, "error": f"保存失败: {e}"}
    rec = {
        "name": dst.stem,
        "path": str(dst),
        "tags": [t.strip() for t in tags.split(",") if t.strip()] if tags else [],
        "source": source or "unknown",
        "saved_at": ts,
        "hash": fh,
    }
    idx.append(rec)
    _save_index(idx)
    return {"ok": True, "sticker": rec}


def _alive(idx: list) -> list:
    """只留真实存在且格式合法的条目(旧版收进来的 png/jpg 照片在这里被挡掉)"""
    out = []
    for s in idx:
        try:
            p = Path(s.get("path", ""))
            if p.suffix.lower() in ALLOWED_EXT and p.exists():
                out.append(s)
        except Exception:
            continue
    return out


def list_stickers(keyword: str = "", limit: int = 50) -> list:
    idx = _alive(_load_index())
    if keyword:
        kw = keyword.lower()
        idx = [s for s in idx if kw in s.get("name", "").lower()
               or any(kw in t.lower() for t in s.get("tags", []))]
    idx.sort(key=lambda x: x.get("saved_at", 0), reverse=True)
    return idx[:limit]


def cleanup() -> dict:
    """清掉索引里不是表情包的东西(png/jpg等)和已丢失的文件, 返回删了多少"""
    idx = _load_index()
    keep, junk = [], []
    for s in idx:
        try:
            p = Path(s.get("path", ""))
            ok = p.suffix.lower() in ALLOWED_EXT and p.exists()
        except Exception:
            ok = False
        if ok:
            keep.append(s)
        else:
            junk.append(s)
    for s in junk:
        try:
            Path(s.get("path", "")).unlink(missing_ok=True)
        except Exception:
            pass
    if junk:
        _save_index(keep)
    return {"removed": len(junk), "left": len(keep)}


def get_sticker(name_or_id: str) -> dict | None:
    idx = _load_index()
    for s in idx:
        if s.get("name") == name_or_id or s.get("path", "").endswith(name_or_id):
            return s
    for s in idx:
        if name_or_id.lower() in s.get("name", "").lower():
            return s
    return None


def random_sticker(keyword: str = "") -> dict | None:
    pool = list_stickers(keyword, limit=1000)
    if not pool:
        return None
    return random.choice(pool)


def delete_sticker(name: str) -> bool:
    idx = _load_index()
    new_idx = []
    removed = False
    for s in idx:
        if s.get("name") == name:
            try:
                Path(s["path"]).unlink(missing_ok=True)
            except Exception:
                pass
            removed = True
        else:
            new_idx.append(s)
    if removed:
        _save_index(new_idx)
    return removed


def stats() -> dict:
    idx = _load_index()
    return {
        "total": len(idx),
        "by_ext": {},
        "latest": idx[-1]["name"] if idx else None,
    }
