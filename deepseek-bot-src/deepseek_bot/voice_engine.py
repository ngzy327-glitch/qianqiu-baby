"""
语音引擎 — TTS 生成 + 语音采样管理
- TTS: edge-tts (微软在线, 免费, 多音色)
- 采样: 用户上传的语音样本存档(用于记录用户偏好的音色/声纹参考)
- 发送: 生成 ogg 后由调用方走 Bot API sendVoice
"""
import asyncio
import os
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


def generate(text: str, voice: str = "") -> str:
    """生成 TTS 语音文件(ogg), 返回文件路径。失败返回空字符串。"""
    try:
        import edge_tts
    except ImportError:
        return ""
    voice_id = resolve_voice(voice)
    out = TTS_DIR / f"tts_{int(time.time()*1000)}.ogg"
    try:
        communicate = edge_tts.Communicate(text, voice_id)
        # edge-tts 默认输出 mp3, Telegram sendVoice 接受 ogg/opus, 但 mp3 也能发
        # 这里输出 .mp3, 调用方用 sendVoice 或 sendAudio 均可
        out = TTS_DIR / f"tts_{int(time.time()*1000)}.mp3"
        asyncio.run(communicate.save(str(out)))
        return str(out)
    except Exception as e:
        print(f"[voice] tts failed: {e}", flush=True)
        return ""


def save_sample(name: str, audio_path: str) -> bool:
    """保存用户上传的语音样本(用于声纹参考/音色偏好记录)"""
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
