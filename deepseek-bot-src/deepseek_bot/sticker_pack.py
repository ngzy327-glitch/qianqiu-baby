"""
贴纸包管理 — 抓取 Telegram 贴纸集的贴纸 ID，让账号能发这些贴纸
存储: {DATA_DIR}/sticker_packs.json
"""
import json
import os
import time
from pathlib import Path

DATA_DIR = os.getenv("DSB_DATA_DIR", "/opt/deepseek-bot").rstrip("/")
STICKER_FILE = Path(DATA_DIR) / "sticker_packs.json"

# 本地贴纸库: pack_name -> [document_id, ...]
_sticker_db = {}


def _load():
    global _sticker_db
    try:
        if STICKER_FILE.exists():
            _sticker_db = json.loads(STICKER_FILE.read_text(encoding="utf-8"))
    except Exception:
        _sticker_db = {}


def _save():
    try:
        tmp = str(STICKER_FILE) + ".tmp"
        Path(tmp).write_text(json.dumps(_sticker_db, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, str(STICKER_FILE))
    except Exception:
        STICKER_FILE.write_text(json.dumps(_sticker_db, ensure_ascii=False, indent=2), encoding="utf-8")


def get_pack_stickers(pack_name: str) -> list:
    """获取某个贴纸集的所有贴纸 document_id"""
    _load()
    return _sticker_db.get(pack_name, [])


def list_packs() -> list:
    """列出所有已安装的贴纸集"""
    _load()
    return [{"pack": k, "count": len(v)} for k, v in _sticker_db.items()]


def add_pack(pack_name: str, sticker_ids: list):
    """添加/更新一个贴纸集"""
    _load()
    _sticker_db[pack_name] = sticker_ids
    _save()


def remove_pack(pack_name: str):
    """删除一个贴纸集"""
    _load()
    if pack_name in _sticker_db:
        del _sticker_db[pack_name]
        _save()
        return True
    return False


def get_random_sticker(pack_name: str = None) -> str:
    """随机返回一个贴纸的 document_id"""
    _load()
    if pack_name:
        stickers = _sticker_db.get(pack_name, [])
    else:
        # 从所有贴纸集里随机选
        all_stickers = []
        for s_list in _sticker_db.values():
            all_stickers.extend(s_list)
        stickers = all_stickers
    
    if not stickers:
        return None
    
    import random
    return random.choice(stickers)


def stats() -> dict:
    """统计信息"""
    _load()
    total = sum(len(v) for v in _sticker_db.values())
    return {"packs": len(_sticker_db), "total_stickers": total}


# 初始化加载
_load()
