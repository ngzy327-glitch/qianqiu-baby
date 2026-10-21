"""
DeepSeek-Bot · AI 账号管家
───────────────────────────────────────────
Telegram 多账号/群组管理 + AI 编排助手。

模块导览:
  编排层:
    bot.py             - 核心(工具schema/执行器/提示词/心跳/面板/回调)
    state_engine       - 项目现场固化(state.md)
    memory_engine      - 长期记忆 + 对话检索
    group_memory       - 群聊记忆/画像
    rag_engine         - 知识库检索
  TG 层:
    tg_daemon.py       - 多账号常驻服务(stdin/stdout JSON 协议)
    rich_msg           - Telegram 富文本
    group_mod          - 群管(违规识别/处置)
    emoji_manager      - 自定义表情
  面板:
    miniapp_server     - TG 小程序后端(管理面板)

注: 安全测试/攻击类模块已于 2026-10-22 全部移除(转型 AI 账号管家)。
"""

from .db import init as db_init, project_create, project_list
