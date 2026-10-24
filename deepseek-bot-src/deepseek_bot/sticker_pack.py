"""
表情包管理 — 保存/搜索/发送 GIF 表情包
存储: {DSB_DATA_DIR}/stickers/  (gif/webp/mp4)
索引: {DSB_DATA_DIR}/stickers/index.json  [{name, path, tags, source, saved_at}]
"""
import json
import os
import time
import random
from pathlib import Path

DATA_DIR = os.getenv("DSB_DATA_DIR", "/opt/deepseek-bot").rstrip("/")
STICKER_DIR = Path(DATA_DIR) / "stickers"
INDEX_FILE = STICKER_DIR / "index.json"
ALLOWED_EXT = (".gif", ".webp", ".mp4", ".png", ".jpg", ".jpeg")

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


def save_sticker(file_path: str, name: str = "", tags: str = "", source: str = "") -> dict:
    """保存一个表情包到本地库, 返回记录"""
    src = Path(file_path)
    if not src.exists():
        return {"ok": False, "error": f"文件不存在: {file_path}"}
    ext = src.suffix.lower()
    if ext not in ALLOWED_EXT:
        return {"ok": False, "error": f"不支持的格式: {ext}(支持 {', '.join(ALLOWED_EXT)})"}
    ts = int(time.time())
    fname = name or f"sticker_{ts}_{random.randint(1000,9999)}"
    if not fname.endswith(ext):
        fname += ext
    dst = STICKER_DIR / fname
    # 重名处理
    n = 1
    while dst.exists():
        dst = STICKER_DIR / f"{Path(fname).stem}_{n}{ext}"
        n += 1
    try:
        dst.write_bytes(src.read_bytes())
    except Exception as e:
        return {"ok": False, "error": f"保存失败: {e}"}
    rec = {
        "name": Path(fname).stem,
        "path": str(dst),
        "tags": [t.strip() for t in tags.split(",") if t.strip()] if tags else [],
        "source": source or "unknown",
        "saved_at": ts,
    }
    idx = _load_index()
    idx.append(rec)
    _save_index(idx)
    return {"ok": True, "sticker": rec}


def list_stickers(keyword: str = "", limit: int = 50) -> list:
    """列出表情包, 可按关键词过滤(匹配 name/tags)"""
    idx = _load_index()
    if keyword:
        kw = keyword.lower()
        idx = [s for s in idx if kw in s.get("name", "").lower()
               or any(kw in t.lower() for t in s.get("tags", []))]
    idx.sort(key=lambda x: x.get("saved_at", 0), reverse=True)
    return idx[:limit]


def get_sticker(name_or_id: str) -> dict | None:
    """按名字取一个表情包"""
    idx = _load_index()
    for s in idx:
        if s.get("name") == name_or_id or s.get("path", "").endswith(name_or_id):
            return s
    # 模糊匹配
    for s in idx:
        if name_or_id.lower() in s.get("name", "").lower():
            return s
    return None


def random_sticker(keyword: str = "") -> dict | None:
    """随机取一个表情包, 可带关键词过滤"""
    pool = list_stickers(keyword, limit=1000)
    if not pool:
        return None
    return random.choice(pool)


def delete_sticker(name: str) -> bool:
    """删除一个表情包"""
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
    """统计信息"""
    idx = _load_index()
    return {
        "total": len(idx),
        "by_ext": {},
        "latest": idx[-1]["name"] if idx else None,
    }
