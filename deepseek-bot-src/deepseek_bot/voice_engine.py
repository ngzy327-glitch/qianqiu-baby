"""
语音引擎 — TTS 生成 + 语音采样管理 + 声纹克隆
- 主 TTS: edge-tts (微软在线, 免费, 多音色, 支持 rate/pitch/volume)
- 克隆 TTS: CosyVoice (可选, 零样本声纹克隆, 需安装 torch+cosyvoice)
- 采样: 用户上传的语音样本存档 → 可用于 CosyVoice 克隆
"""
import asyncio
import os
import re
import time
import shutil
from pathlib import Path

DATA_DIR = os.getenv("DSB_DATA_DIR", "/opt/deepseek-bot").rstrip("/")
try:
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
except Exception:
    pass
VOICE_DIR = Path(DATA_DIR) / "voices"
VOICE_DIR.mkdir(exist_ok=True)
SAMPLE_DIR = VOICE_DIR / "samples"
SAMPLE_DIR.mkdir(exist_ok=True)
TTS_DIR = VOICE_DIR / "tts"
TTS_DIR.mkdir(exist_ok=True)

# 常用中文音色 (edge-tts)
CN_VOICES = {
    "晓晓": "zh-CN-XiaoxiaoNeural",       # 女声 温柔
    "晓伊": "zh-CN-XiaoyiNeural",         # 女声 活泼
    "云健": "zh-CN-YunjianNeural",        # 男声 沉稳
    "云希": "zh-CN-YunxiNeural",          # 男声 少年
    "云扬": "zh-CN-YunyangNeural",        # 男声 新闻
    "晓辰": "zh-CN-XiaochenNeural",       # 女声 亲切
    "晓涵": "zh-CN-XiaohanNeural",        # 女声 成熟
    "云野": "zh-CN-YunyeNeural",          # 男声 阳光
}
EN_VOICES = {
    "Aria": "en-US-AriaNeural",
    "Guy": "en-US-GuyNeural",
    "Jenny": "en-US-JennyNeural",
    "Davis": "en-US-DavisNeural",
}

DEFAULT_VOICE = "zh-CN-XiaoxiaoNeural"


def list_voices() -> str:
    """列出可用音色"""
    lines = ["🇨🇳 中文音色:"]
    for name, v in CN_VOICES.items():
        lines.append(f"  {name} → {v}")
    lines.append("\n🇺🇸 English:")
    for name, v in EN_VOICES.items():
        lines.append(f"  {name} → {v}")
    if _cosyvoice_available():
        lines.append("\n🎭 声纹克隆: 用 voice act=clone sample=样本名 text=文本 可复刻采样的声音")
    return "\n".join(lines)


def resolve_voice(name: str) -> str:
    """把中文名/英文名/全名解析成 edge-tts voice id"""
    if not name:
        return DEFAULT_VOICE
    if name in CN_VOICES:
        return CN_VOICES[name]
    if name in EN_VOICES:
        return EN_VOICES[name]
    return name  # 已是全名


def _preprocess_for_tts(text: str) -> str:
    """TTS 文本预处理: 让语音更像人说话
    - 去掉 emoji(读出来出戏)
    - 去掉括号里的动作描述(如 (笑)、*眨眼*)
    - 长句按标点切短(加停顿)
    - 去掉代码块/Markdown 符号
    """
    if not text:
        return text
    # 去 emoji(用 emoji 库优先, 否则用保守的正则——避免误删中文)
    try:
        import emoji as _emoji_lib
        text = _emoji_lib.replace_emoji(text, "")
    except ImportError:
        # 保守正则: 只匹配明确的 emoji 区块, 不误伤中文/字母
        _emoji_re = re.compile(
            "["
            "\U0001F600-\U0001F64F"  # 表情
            "\U0001F300-\U0001F5FF"  # 符号/图形
            "\U0001F680-\U0001F6FF"  # 交通
            "\U0001F900-\U0001F9FF"  # 补充符号
            "\U0001FA70-\U0001FAFF"  # 扩展符号
            "\U0001F1E6-\U0001F1FF"  # 国旗
            "\u2600-\u26FF"          # 杂项符号
            "\u2700-\u27BF"          #  Dingbats
            "\U0001F700-\U0001F77F"  # 几何
            "\ufe0f"                  # 变体选择符
            "\u200d"                  # 零宽连接符
            "]+", flags=re.UNICODE)
        text = _emoji_re.sub("", text)
    # 去括号动作: (笑) [思考] *眨眼*
    text = re.sub(r"[\(\（][\s\S]{0,20}?[\)\）]", "", text)
    text = re.sub(r"\[[\s\S]{0,20}?\]", "", text)
    text = re.sub(r"\*[\s\S]{0,20}?\*", "", text)
    # 去 Markdown 符号
    text = re.sub(r"`{1,3}", "", text)
    text = re.sub(r"^#{1,6}\s*", "", text, flags=re.M)
    text = re.sub(r"\*\*?(.*?)\*\*?", r"\1", text)
    text = re.sub(r"~~(.*?)~~", r"\1", text)
    # 去 tg-emoji 标签
    text = re.sub(r"<tg-emoji[^>]*>|</tg-emoji>", "", text)
    # 多余空白
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return text
    # 长句切短: 超过30字无标点处插入逗号停顿(模拟人说话换气)
    sentences = re.split(r"(?<=[。！？!?；;])", text)
    out = []
    for s in sentences:
        if len(s) > 35:
            # 在中间合适位置(逗号/顿号后)切
            parts = re.split(r"(?<=[，,、])", s)
            buf = ""
            for p in parts:
                if len(buf) + len(p) > 30 and buf:
                    out.append(buf.strip())
                    buf = p
                else:
                    buf += p
            if buf.strip():
                out.append(buf.strip())
        elif s.strip():
            out.append(s.strip())
    return "，".join(out) if out else text


def generate(text: str, voice: str = "", rate: str = "+0%", pitch: str = "+0Hz") -> str:
    """生成 TTS 语音文件(mp3), 返回文件路径。失败返回空字符串。
    rate: 语速, 如 '+20%' / '-10%' / '+0%'(默认)
    pitch: 音调, 如 '+10Hz' / '-5Hz' / '+0Hz'(默认)
    """
    try:
        import edge_tts
    except ImportError:
        return ""
    voice_id = resolve_voice(voice)
    # 文本预处理(更像人说话)
    _clean = _preprocess_for_tts(text)
    if not _clean.strip():
        return ""
    out = TTS_DIR / f"tts_{int(time.time()*1000)}.mp3"
    try:
        communicate = edge_tts.Communicate(_clean, voice_id, rate=rate, pitch=pitch)
        asyncio.run(communicate.save(str(out)))
        if out.exists() and out.stat().st_size > 0:
            return str(out)
        return ""
    except Exception as e:
        print(f"[voice] tts failed: {e}", flush=True)
        return ""


# ==================== CosyVoice 声纹克隆(可选后端) ====================
_cosy_loaded = False
_cosy_model = None
_cosy_init_err = ""


def _cosyvoice_available() -> bool:
    """检测 CosyVoice 是否可用"""
    global _cosy_loaded, _cosy_model, _cosy_init_err
    if _cosy_loaded:
        return _cosy_model is not None
    try:
        from cosyvoice.cli.cosyvoice import CosyVoice2
        import torch
        _cosy_model = CosyVoice2('CosyVoice2-0.5B')
        _cosy_loaded = True
        print("[voice] CosyVoice 克隆引擎已加载", flush=True)
        return True
    except ImportError:
        _cosy_loaded = True
        _cosy_init_err = "cosyvoice 未安装"
        return False
    except Exception as e:
        _cosy_loaded = True
        _cosy_init_err = str(e)[:200]
        print(f"[voice] CosyVoice 加载失败: {e}", flush=True)
        return False


def cosyvoice_status() -> str:
    """返回 CosyVoice 状态(给 /voice 命令展示用)"""
    if _cosyvoice_available():
        return "✅ 已就绪(可用声纹克隆)"
    return f"❌ 不可用({_cosy_init_err or '未安装'})。安装: pip install cosyvoice torch torchaudio"


def generate_with_clone(text: str, sample_name: str) -> str:
    """用已保存的语音样本做声纹克隆 TTS。失败返回空串。
    sample_name: save_sample 时用的名字
    """
    if not _cosyvoice_available():
        return ""
    sample_path = get_sample(sample_name)
    if not sample_path:
        print(f"[voice] 克隆失败: 样本 '{sample_name}' 不存在", flush=True)
        return ""
    try:
        _clean = _preprocess_for_tts(text)
        if not _clean.strip():
            return ""
        import torch
        out = TTS_DIR / f"clone_{int(time.time()*1000)}.wav"
        # CosyVoice 推理(零样本克隆)
        for i, chunk in enumerate(_cosy_model.inference_zero_shot(
            _clean, sample_path, _clean, stream=False)):
            pass
        # 保存音频
        import torchaudio
        torchaudio.save(str(out), chunk['tts_speech'], 22050)
        if out.exists() and out.stat().st_size > 0:
            return str(out)
        return ""
    except Exception as e:
        print(f"[voice] 克隆 TTS 失败: {e}", flush=True)
        return ""


# ==================== 采样管理 ====================
def save_sample(name: str, audio_path: str) -> bool:
    """保存用户上传的语音样本(用于声纹克隆/音色偏好记录)"""
    try:
        src = Path(audio_path)
        if not src.exists():
            return False
        ext = src.suffix or ".ogg"
        dst = SAMPLE_DIR / f"{name}{ext}"
        shutil.copy2(str(src), str(dst))
        return True
    except Exception:
        return False


def list_samples() -> list:
    """列出已保存的语音样本"""
    if not SAMPLE_DIR.exists():
        return []
    return sorted([f.name for f in SAMPLE_DIR.iterdir() if f.is_file()])


def list_samples_str() -> str:
    """列出已保存样本(给工具返回用)"""
    samples = list_samples()
    if not samples:
        return "（暂无语音样本。给我发一段语音，我可以采样保存）"
    lines = [f"已保存 {len(samples)} 个语音样本:"]
    for s in samples:
        lines.append(f"  · {s}")
    if _cosyvoice_available():
        lines.append("\n💡 可用 voice act=clone sample=样本名 text=文本 克隆该声音说话")
    else:
        lines.append("\n💡 安装 CosyVoice 后可用这些样本做声纹克隆")
    return "\n".join(lines)


def get_sample(name: str) -> str:
    """获取采样文件路径"""
    for f in SAMPLE_DIR.iterdir():
        if f.stem == name:
            return str(f)
    return ""


def cleanup_old_tts(max_age: int = 3600):
    """清理超过 max_age 秒的 TTS 临时文件"""
    try:
        now = time.time()
        for f in TTS_DIR.iterdir():
            if f.is_file() and now - f.stat().st_mtime > max_age:
                f.unlink()
    except Exception:
        pass
