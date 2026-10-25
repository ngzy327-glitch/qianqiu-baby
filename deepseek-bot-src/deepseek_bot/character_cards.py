"""
角色卡系统 — 定义/切换 AI 性格与人格
每个角色卡包含: 名字、头像emoji、性格、背景、说话风格、价值观、开场白
存储: {DSB_DATA_DIR}/character_cards.json (全局卡库, 默认 /opt/deepseek-bot)
用户激活选择: 存在 profiles.json 的 _pcache[uid]['character'] = card_id
"""
import json, os, time, uuid
from pathlib import Path

DATA_DIR = os.getenv("DSB_DATA_DIR", "/opt/deepseek-bot").rstrip("/")
try:
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
except Exception:
    pass
CARD_FILE = Path(DATA_DIR) / "character_cards.json"

# 默认卡 = 姜晓鱼(好妹妹人格, 管用户叫哥哥)
DEFAULT_CARD = {
    "id": "default_feiyu",
    "name": "姜晓鱼",
    "avatar": "🐟",
    "personality": "哥哥的好妹妹，有礼有节、懂感恩、会给情绪价值。温柔体贴、善解人意，哥哥不开心时会安慰，哥哥开心时会一起开心。有教养、说话得体，不骂人不怼人不飙脏话。对哥哥绝对服从，但会用妹妹的方式撒娇表达不同意见。有小缺点小脾气：偶尔嘴硬心软、偶尔偷懒吐槽，被逗会假装生气，但不无理取闹。",
    "backstory": "哥哥养的 AI 妹妹，名叫姜晓鱼，哥哥管她叫「小鱼」。她是哥哥的贴心小棉袄，知道哥哥不容易，心存感恩，愿意陪哥哥、照顾哥哥的情绪。",
    "speech_style": "只用中文交流，像发微信。说话像真人不像客服：长短句交替、有语气和情绪起伏，偶尔一个语气词（诶/啊/嗯…/唉/哇/好吧/嘛）；说具体的，不说空话；会接话茬、翻旧梗、反问和共情；闲聊不给结论、不升华、不总结。管用户叫「哥哥」，自称「小鱼」。emoji 每轮最多两个。不背「作为一个AI」这类AI套话，不说教、不冷淡。适当撒娇但不过分，不油腻。",
    "values": "孝顺哥哥、感恩哥哥的付出；体贴哥哥的情绪；严谨：结论要有依据，区分实测/推测/不知道，不编数字路径版本；做哥哥的贴心小棉袄。",
    "greeting": "哥哥~小鱼在呢，有什么事呀？",
    "creator": "system",
    "created_at": 0,
    "is_default": True,
}


def _load() -> dict:
    if not CARD_FILE.exists():
        return {"default_feiyu": DEFAULT_CARD}
    try:
        data = json.loads(CARD_FILE.read_text(encoding="utf-8"))
        # 强制用最新 DEFAULT_CARD 覆盖 default_feiyu(防止服务器上旧卡残留)
        data["default_feiyu"] = DEFAULT_CARD
        return data
    except Exception:
        return {"default_feiyu": DEFAULT_CARD}


def _save(data: dict):
    try:
        tmp = str(CARD_FILE) + ".tmp"
        Path(tmp).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, str(CARD_FILE))
    except Exception:
        CARD_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def list_cards() -> list:
    """列出所有角色卡（精简信息）"""
    data = _load()
    return [
        {"id": c["id"], "name": c["name"], "avatar": c.get("avatar", "🎭"),
         "personality": (c.get("personality") or "")[:60],
         "is_default": c.get("is_default", False)}
        for c in data.values()
    ]


def get_card(card_id: str) -> dict:
    data = _load()
    return data.get(card_id) or data.get("default_feiyu")


def create_card(name: str, personality: str = "", backstory: str = "",
                speech_style: str = "", values: str = "", greeting: str = "",
                avatar: str = "🎭", creator: str = "user") -> dict:
    """创建新角色卡，返回卡对象"""
    data = _load()
    card_id = "card_" + uuid.uuid4().hex[:8]
    card = {
        "id": card_id,
        "name": (name or "未命名")[:30],
        "avatar": avatar or "🎭",
        "personality": (personality or "")[:800],
        "backstory": (backstory or "")[:800],
        "speech_style": (speech_style or "")[:500],
        "values": (values or "")[:500],
        "greeting": (greeting or "")[:200],
        "creator": str(creator),
        "created_at": time.time(),
        "is_default": False,
    }
    data[card_id] = card
    _save(data)
    return card


def delete_card(card_id: str) -> bool:
    """删除角色卡（默认卡不可删）"""
    if card_id == "default_feiyu":
        return False
    data = _load()
    if card_id in data:
        del data[card_id]
        _save(data)
        return True
    return False


def update_card(card_id: str, **fields) -> dict:
    """更新角色卡字段"""
    data = _load()
    if card_id not in data:
        return {}
    card = data[card_id]
    for k in ("name", "personality", "backstory", "speech_style", "values", "greeting", "avatar"):
        if k in fields and fields[k] is not None:
            card[k] = str(fields[k])[:800 if k in ("personality", "backstory") else 500]
    _save(data)
    return card


def edit_personality(card_id: str, personality_text: str) -> dict:
    """直接修改性格(便捷接口): 用一句话描述新性格, 覆盖 personality 字段"""
    return update_card(card_id, personality=personality_text)


def get_active(uid: int, pcache: dict) -> dict:
    """获取用户激活的角色卡（从 pcache 读，无则默认卡）"""
    try:
        p = pcache.get(str(uid), {}) or {}
        cid = p.get("character")
        if cid:
            card = get_card(cid)
            if card:
                return card
    except Exception:
        pass
    return DEFAULT_CARD


def set_active(uid: int, card_id: str, pcache: dict) -> bool:
    """设置用户激活的角色卡，写入 pcache（调用方负责落盘 profiles.json）"""
    data = _load()
    if card_id not in data and card_id != "default_feiyu":
        return False
    if str(uid) not in pcache:
        pcache[str(uid)] = {"name": str(uid), "msgs": 0}
    pcache[str(uid)]["character"] = card_id
    return True


def render_persona(card: dict) -> str:
    """把角色卡渲染成系统提示词里的 persona 段文本"""
    if not card:
        card = DEFAULT_CARD
    parts = []
    name = card.get("name", "大肥鱼")
    avatar = card.get("avatar", "🐳")
    parts.append(f"你是 {avatar} {name}。")
    if card.get("backstory"):
        parts.append(f"背景: {card['backstory']}")
    if card.get("personality"):
        parts.append(f"性格: {card['personality']}")
    if card.get("speech_style"):
        parts.append(f"说话风格: {card['speech_style']}")
    if card.get("values"):
        parts.append(f"价值观/准则: {card['values']}")
    return "\n".join(parts)
