# SPECTRE · 多智能体红队框架 — 源码交付包

作者 / 联系: @eexse   ·   框架版本: v1.0

Telegram 智能体机器人(渗透/情报/群管/多AI协作/自进化)完整源码。

## 目录
```
deepseek_bot/          机器人主程序(引擎层 + 工具层 + 多AI编排)
  bot.py               核心(工具schema/执行器/提示词/心跳/面板/回调)
  rich_msg.py          富文本(Telegram Rich Message: 表格/自定义表情/实体)
  atk_meta.py          自进化(制胜链蒸馏/回灌)
  db.py / scheduler.py 数据与定时
  waf_evasion / parallel / playbook / adaptive_chain / api_attack /
  credential_attack / privesc / lateral_movement / c2_integration  渗透引擎
tg_daemon.py           双号常驻守护(本地 socket, 避免 session 锁)
tg_user.py             双号操作脚本
grok_secrets.py        密钥脱敏(11类)
assistant_api.py       OpenAI 兼容 API 服务(可选)
knowledge/toolPlugins/ 声明式插件示例(免改核心扩展工具)
selftest.py            自检(52项)
watchdog.py            值守模式模块
```

## 快速开始
```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env      # 填 DEEPSEEK_API_KEY 与 DEEPSEEK_BOT_TOKEN
mkdir -p sessions && .venv/bin/python -m deepseek_bot.run
```
- 首次运行会登录 bot token(无需手机号); 双号功能需自行准备两个 user session
- 健康检查: `.venv/bin/python selftest.py`
- 管理命令: `/start` 菜单 → 🧠模型/推理 · 📋后台任务 · /bg · /watch · /model

## ⚠️ 必改(不改跑不起来 / 没有管理员)
交付包里所有真实 TG ID 已替换为 `None` 占位, 共 4 处, 请改成你自己的数字 ID:
```python
deepseek_bot/bot.py      OK = {None, None}          → OK = {你的TG_ID}
deepseek_bot/bot.py      _handle_queued(None, ...)  → _handle_queued(你的TG_ID, ...)
assistant_api.py         _ADMINS = {None, None}     → _ADMINS = {你的TG_ID}
tg_user.py               ACCOUNTS 里的 "tg_id": None → 你的双号 TG ID
```
`None` 永不等于任何真实 chat_id, 所以**忘了改也不会把管理权限误给陌生人**; 但也就没人能下管理指令。
查自己的 ID: 找任意 userinfo bot, 或看机器人启动日志里的 `chat_id`。

## 定制点
| 要改什么 | 改哪里 |
|---|---|
| 管理员名单(必改) | `bot.py` 顶部 `OK = {...}` 或 `ok_ids.json` |
| 人格/语气 | `bot.py` 里 `sp=` 的"自身身份/多重人格/表达"段落 |
| 模型 | `MODEL / MODEL_PRO / MODEL_BETA` 常量 + `/model` 按钮 |
| 工具能力 | 优先加 `knowledge/toolPlugins/*.json`(声明式, 免改核心) |
| 定价/套餐 | `bot.py` 计费段落（收款模块不随包，自行对接） |
