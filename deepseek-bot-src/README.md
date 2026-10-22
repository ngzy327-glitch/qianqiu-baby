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
web_session_daemon.py  多账号常驻网页会话(每号独立 profile/指纹/代理, 页面不关)
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
- **写入类**(代发/踢人/改群设置/删消息): 进审批队列, 你在 TG 点「批准/驳回」按钮; AI 也会先弹确认
- **硬禁区**(代码里不存在): 批量私信陌生人 / 批量加群拉人 / 抓取成员用于外联
- 每账号每分钟写操作限 10 次(防 FloodWait 封号); 全部操作落 `audit.log` 审计

## 账号托管(多账号)
- **配置**: 编辑 `accounts.json`(首次运行自动生成模板), 一个 JSON 条目 = 一个账号; 支持每号独立设备指纹 `device` 与代理出口 `proxy`
- **登录**: 对 bot 说「登录 ops 号」→ 收到验证码后回「验证码 12345」→ (开了两步验证再回密码)
- **日报**: 说「给我各账号的未读日报」→ AI 拉所有账号未读并汇总重点
- **自动回复**: 编辑 `autoreply.json`, 例: `[{"accounts":["ops"],"match":"在吗","reply":"在的~","scope":"private"}]`
- **消息路由**: 编辑 `routes.json`, 例: `[{"accounts":["main"],"match":"下单","action":"notify"}]`(命中即通知你)
- **看板**: miniapp 打开 `/accounts` 页——账号在线状态/指纹代理标记/待审批数/审计流水, 15s 自刷

## 常驻网页会话(web_session)
AI 可以按账号打开网页并**把页面留在后台**, 后续跨多轮对话继续点:
- `open` 打开并常驻 → `see` 看当前页(截图+正文) → `click` 点击(text/selector/坐标) → `type` 输入 → `scroll/tabs/switch`
- 每个账号一个独立浏览器 profile 目录(`web_profiles/<账号>/`): Cookie、localStorage、IndexedDB 全保留, 浏览器/服务重启后仍是登录态
- 每号独立指纹(UA/视口/时区/语言/WebGL)+ 独立代理(`accounts.json` 的 `proxy`, 或 `web.profile` 指到 `browser_profiles.json` 模板)
- 全程 `audit.log` 审计, 写操作每号每分钟 10 次上限
- 启动: 插件会自动拉起 `web_session_daemon.py`; 也可 systemd 常驻。依赖: `pip install playwright && playwright install chromium`

## 按钮操作(识别 + 点击 bot 的 callback 按钮)
AI 能读出消息上的按钮布局并按下指定按钮:
- `tg act=buttons tgt=账号:群名:消息ID` — 列出该消息所有按钮(文字+行列位置)
- `tg act=click tgt=账号:群名:消息ID:行:列` — 点击指定按钮(写入类, 过审批队列)
- `tg act=messages ... raw` — 读消息时拿按钮原始结构(reply_markup)

**示例**: 你说「去把 XX bot 的每日签到点了」→ AI 先 `buttons` 读布局 → 看到「每日签到」在 1 行 1 列 → 提交审批 → 你点「✅ 批准」→ AI 执行 `click` → 把结果发你。

反向也成立: AI 通过 `ask`/`notify` 发按钮问你, 你点选项, 它拿到结果继续干活(审批队列就是这么实现的)。

## 定制点
| 要改什么 | 改哪里 |
|---|---|
| 管理员名单(必改) | `bot.py` 顶部 `OK = {...}` 或 ok_ids.json |
| 人格/语气 | `bot.py` 里 `sp=` 段落 |
| 模型 | `MODEL / MODEL_PRO / MODEL_BETA` 常量 + `/model` 按钮 |
| 工具能力 | 优先加 `knowledge/toolPlugins/*.json`(声明式, 免改核心) |

## 合规说明
本项目用于管理**你自己拥有**的 Telegram 账号与群组。多账号自动化请遵守 Telegram 服务条款: 低频、自用、不群发、不抓取。攻击类功能模块已于 2026-10-22 全部移除。
