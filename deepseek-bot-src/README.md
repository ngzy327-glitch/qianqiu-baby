# 大肥鱼 · AI 账号管家

Telegram 多账号/群组管理 + AI 编排助手。你用自然语言下指令，AI 调用工具替你完成：读消息、代回复、整理会话、群组运营、定时提醒、信息检索。

## 目录
```
deepseek_bot/          主程序(引擎层 + 工具层 + 多AI编排)
  bot.py               核心(工具schema/执行器/提示词/心跳/面板/回调)
  rich_msg.py          富文本(Telegram Rich Message: 表格/自定义表情/实体)
  db.py / scheduler.py 数据与定时
  memory_engine / group_memory / rag_engine  记忆与知识库
  state_engine.py      项目现场固化(state.md)
  group_mod.py         群管(违规识别/处置)
  monitor.py           值守巡检
  miniapp_server.py    TG 小程序后端(管理面板)
tg_daemon.py           多账号常驻服务(本地 socket, 避免 session 锁)
tg_user.py             多账号操作
grok_secrets.py        密钥脱敏
assistant_api.py       OpenAI 兼容 API 服务(可选)
knowledge/toolPlugins/ 声明式插件(免改核心扩展工具)
selftest.py            自检
```

## 快速开始
```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env      # 填 DEEPSEEK_API_KEY / DEEPSEEK_BOT_TOKEN / OWNER_ID
mkdir -p sessions && .venv/bin/python -m deepseek_bot.run
```
- 首次运行登录 bot token(无需手机号); 多账号功能需在 tg_user.py 配置各账号 session
- 健康检查: `.venv/bin/python selftest.py`
- 管理命令: `/start` 菜单 → 🧠模型/推理 · 📋后台任务 · /bg · /watch · /model

## ⚠️ 必改(不改跑不起来 / 没有管理员)
```python
deepseek_bot/bot.py      OK = {None, None}          → OK = {你的TG_ID}
deepseek_bot/bot.py      _handle_queued(None, ...)  → _handle_queued(你的TG_ID, ...)
assistant_api.py         _ADMINS = {None, None}     → _ADMINS = {你的TG_ID}
tg_user.py               ACCOUNTS 里的 "tg_id": None → 你的账号 TG ID
```
`None` 永不等于任何真实 chat_id, 忘了改也不会把管理权限误给陌生人。
查自己的 ID: 找任意 userinfo bot, 或看机器人启动日志里的 `chat_id`。

## 操作护栏(内置)
- **只读类**(读消息/搜索/统计/整理): AI 直接执行
- **写入类**(代发/踢人/改群设置/删消息): AI 先向你确认再执行
- **硬禁区**(代码里不存在): 批量私信陌生人 / 批量加群拉人 / 抓取成员用于外联

## 定制点
| 要改什么 | 改哪里 |
|---|---|
| 管理员名单(必改) | `bot.py` 顶部 `OK = {...}` 或 ok_ids.json |
| 人格/语气 | `bot.py` 里 `sp=` 段落 |
| 模型 | `MODEL / MODEL_PRO / MODEL_BETA` 常量 + `/model` 按钮 |
| 工具能力 | 优先加 `knowledge/toolPlugins/*.json`(声明式, 免改核心) |

## 合规说明
本项目用于管理**你自己拥有**的 Telegram 账号与群组。多账号自动化请遵守 Telegram 服务条款: 低频、自用、不群发、不抓取。攻击类功能模块已于 2026-10-22 全部移除。
