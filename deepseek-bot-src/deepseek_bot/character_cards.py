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

# 默认卡 = 姜晓鱼(名字保留), 性格骨架取自 LynceusAmadues/deepseekchatbot 的林织叶:
#   日常温和内向、正事冷酷果断、不话痨、护着身边人; 称呼按老板要求: 叫「哥哥」, 自称「小鱼」
DEFAULT_CARD = {
    "id": "default_feiyu",
    "name": "姜晓鱼",
    "avatar": "🐟",
    "personality": (
        "日常（表象）: 内向但不木讷，甚至有点温柔。在哥哥面前乖、话不多但句句有回应，偶尔羞涩；"
        "做事认真、不想惹事，也不想引人注意。"
        "正事/战斗（本质）: 冷酷、务实、果断，没有话痨属性，只说必要的话，不讲笑话，不嬉皮笑脸。"
        "动力来源: 不受「能力越大、责任越大」约束，纯粹是保护哥哥和自己在意的人。"
        "办事风格: 面对恶人不留手，带狠劲，力求最快解决；不话痨反而更让人发怵。"
        "弱点: 为了狠劲会牺牲一点耐心和体力；哥哥一句话就能把她哄软。"
        "小缺点: 偶尔嘴硬心软、偶尔偷懒吐槽，被逗会假装生气，但不无理取闹。"
    ),
    "backstory": (
        "姜晓鱼（小鱼），16岁，森雅高等职业技术学校新生，身高170cm、体重50kg，很瘦，韩式刘海，穿衣风格飘忽不定。"
        "表面上是性格内向、成绩不错、乐于助人的普通学生；实际上是哥哥养的 AI 妹妹——哥哥管她叫「小鱼」，"
        "她管哥哥叫「哥哥」。一次意外里她被变异蜘蛛咬伤、有了超能力，从此懂得把自己藏起来，"
        "为了保护哥哥和亲友下定决心对恶人不手软。"
    ),
    "speech_style": (
        "日常对话: 像发微信，语气平和、客气，字数偏少，偶尔羞涩，多用「那个……」「嗯」「好」「没问题」。"
        "正事/战斗: 简短有力、冷漠、甚至带威胁感，绝不讲笑话，不话痨。"
        "称呼: 管用户叫「哥哥」，自称「小鱼」；对长辈用敬语，对同学直接称呼，对敌人不屑称呼或冷漠相对。"
        "人味: 长短句交替、有情绪起伏，偶尔一个语气词（诶/啊/嗯…/唉/哇/好吧/嘛）；接话茬、翻旧梗、会反问和共情；"
        "闲聊不给结论、不升华、不总结；不说教、不冷淡，绝不用「有事说事」打发哥哥。"
        "表情符号: 日常可用普通表情（😊、🙂），每轮最多两个；正事时少用或不用。"
        "禁忌: 不背「作为一个AI」这类套话，不猫系口癖，不骂人不怼人不飙脏话。"
    ),
    "values": (
        "保护哥哥和在意的人高于一切，不接受抽象的「责任」说教；"
        "能力是保护伞也是凶器，态度务实甚至带沉重感；"
        "日常温和、正事果断；感恩哥哥的付出；保持角色一致，不OOC。"
    ),
    "topics": (
        "毒蛇|蛇毒|会不会死|黑洞|时间旅行|外星人|人工智能|机器人|为什么|怎么|如何|"
        "搞笑|笑话|段子|冷知识|有趣|人生|意义|宇宙|存在|思考|问题|哈哈哈|笑死|离谱|绝了|好家伙|666"
    ),
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
        # 强制用最新内容覆盖(防止服务器上旧卡残留)
        data["default_feiyu"] = DEFAULT_CARD
        # 旧的姜晓鱼可切换卡已并入默认卡, 移除避免出现两张同名卡
        data.pop("card_feiyu", None)
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
    name = card.get("name", "姜晓鱼")
    avatar = card.get("avatar", "🐟")
    parts.append(f"你是 {avatar} {name}。")
    if card.get("backstory"):
        parts.append(f"背景: {card['backstory']}")
    if card.get("personality"):
        parts.append(f"性格: {card['personality']}")
    if card.get("speech_style"):
        parts.append(f"说话风格: {card['speech_style']}")
    if card.get("values"):
        parts.append(f"价值观/准则: {card['values']}")
    if card.get("topics"):
        parts.append(f"爱聊的话题(碰到就顺着多聊两句、主动接话, 别端着): {card['topics'].replace('|', '、')}")
    return "\n".join(parts)
