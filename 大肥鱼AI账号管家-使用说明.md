# 大肥鱼 · AI 账号管家 — 使用说明

> 版本：2026-10-22 · 项目来源：**浅秋科技**

---

## 一、项目介绍

### 这是什么

一个跑在 Telegram 上的 **AI 账号管家**：你用自然语言下指令，AI 自己拆任务、调工具、替你操作多个 TG 账号与群组，并汇报结果。支持多账号托管、群组运营、定时提醒、信息检索、网页访问，全程有审批护栏和操作审计。

### 核心功能

| 模块 | 能力 |
|---|---|
| **多账号托管** | 任意数量账号（accounts.json 配置）；每号独立设备指纹 + 独立代理出口；登录引导（bot 里对话完成） |
| **消息管理** | 读未读/读消息/搜索/代发/多账号未读日报（AI 汇总成人话） |
| **按钮操作** | 识别消息上的 callback 按钮并点击（签到、菜单穿透等场景） |
| **群组运营** | 群管（踢人/禁言/置顶/投票/公告）、违规自动识别、群聊记忆与群友画像 |
| **自动化规则** | autoreply.json 关键词自动回复；routes.json 消息路由（命中即通知/转发） |
| **效率工具** | 定时任务（cron）、值守盯梢、待办清单、持久目标 |
| **信息处理** | 联网搜索、网页抓取/截图、RSS/YouTube 字幕、PDF、翻译、OCR |
| **视觉识别** | 图片理解、文字 OCR、自定义会员表情识别 |
| **AI 编排** | 多 AI 协作（调研/文档/开发/运营/分析/汇总）、子代理、并行工作流 |
| **管理面板** | miniapp 网页控制台 + `/accounts` 多账号看板（状态/审计流/待审批） |
| **自我扩展** | AI 可自己写插件扩展能力（声明式 JSON，免改主程序） |

### 怎么实现的（架构）

```
你（TG 私聊 / 群聊 / miniapp 网页）
        │  自然语言指令
        ▼
  bot.py 核心 ──── AI 编排(模型调度/工具循环/记忆)
        │            │
        │            ├─ 34 个内置工具 + toolPlugins 插件
        │            ├─ 审批队列(写入类操作 → 推按钮给你批准)
        │            └─ 记忆引擎(长期记忆/群聊记忆/对话检索)
        ▼
  tg_daemon 常驻服务 ──── 多账号连接池(Telethon)
        │            │
        │            ├─ 规则引擎(自动回复/消息路由监听)
        │            ├─ 护栏(写操作限流 10次/分钟/号)
        │            └─ 审计日志(audit.log 全量落盘)
        ▼
   Telegram 服务器
```

- **模型层**：OpenAI 兼容接口，默认 DeepSeek，可换任意兼容模型（GLM/Qwen/GPT 等）
- **数据层**：SQLite + JSON 文件，无外部数据库依赖
- **护栏层**：只读操作直通；写入操作进审批队列（TG 按钮批准/驳回）；代码层不存在批量外联能力

---

## 二、使用方法

### 1. 环境准备

- Linux 服务器（Python 3.10+）
- 一个 TG Bot（找 @BotFather 申请，拿 token）
- TG 应用凭据（<https://my.telegram.org> → API development tools，拿 api_id / api_hash）
- 一个 OpenAI 兼容的模型 API key（DeepSeek 官方或中转均可）

### 2. 必填变量（.env）

```bash
cp .env.example .env
```

| 变量 | 必填 | 说明 |
|---|---|---|
| `DEEPSEEK_API_KEY` | ✅ | 模型 API key |
| `DEEPSEEK_API` | ✅ | 接口地址，默认 `https://api.deepseek.com/v1` |
| `DEEPSEEK_BOT_TOKEN` | ✅ | Bot token（@BotFather） |
| `OWNER_ID` | ✅ | 你的 TG 数字 ID（找 @userinfobot 查） |
| `TG_API_ID` / `TG_API_HASH` | 用多账号时必填 | my.telegram.org 申请 |

可选：`QWEN_API_KEY`（视觉识别增强）、`PROXY_DYNAMIC_URL`（代理池）、`DSB_BRAND`（品牌名）等，见 .env.example 注释。

### 3. 必改代码占位（4 处）

```python
deepseek_bot/bot.py      OK = {None, None}          → OK = {你的TG_ID}
deepseek_bot/bot.py      _handle_queued(None, ...)  → _handle_queued(你的TG_ID, ...)
assistant_api.py         _ADMINS = {None, None}     → _ADMINS = {你的TG_ID}
```
> `None` 永不等于任何真实 ID——忘了改只是没人能用管理指令，不会把权限给陌生人。

### 4. 账号配置（accounts.json）

首次运行自动生成模板，每个账号一条：

```json
{
  "accounts": {
    "main": {
      "session": "/opt/deepseek-bot/sessions/main.session",
      "name": "主号", "phone": "+8613800000000", "username": "@your_account", "tg_id": 123456,
      "device": {"device_model": "iPhone 15 Pro", "system_version": "iOS 17.5", "app_version": "10.9", "lang_code": "zh-hans"}
    },
    "ops": {
      "session": "/opt/deepseek-bot/sessions/ops.session",
      "name": "运营号", "phone": "+8613900000000",
      "proxy": {"type": "socks5", "host": "1.2.3.4", "port": 1080, "user": "", "pass": ""}
    }
  }
}
```

- `device`：该号的设备指纹（可选项，不配用默认）
- `proxy`：该号的独立代理出口（可选，需 `pip install "python-socks[asyncio]"`）

### 5. 启动

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
mkdir -p sessions
.venv/bin/python -m deepseek_bot.run     # 启动 bot
.venv/bin/python selftest.py             # 健康检查
```

### 6. 日常使用（对 bot 说话即可）

| 你说 | AI 会做 |
|---|---|
| 「登录 ops 号」 | 发验证码 → 你回验证码 → 完成（支持两步验证密码） |
| 「把各账号的未读汇总给我」 | 逐号拉未读 → AI 汇总重点（标出@你的和急事） |
| 「用 main 号在 XX 群搜一下上周的账单消息」 | 搜索 → 整理结果发你 |
| 「帮我在群里发个公告：……」 | 提交审批 → 你点「✅批准」→ 发出 |
| 「把 XX bot 的每日签到点了」 | 读按钮布局 → 审批 → 点击 → 汇报结果 |
| 「每天早上 9 点给我发日报」 | 建 cron 定时任务 |

### 7. 规则文件（可选，随时改即时生效）

- `autoreply.json` — 自动回复：`[{"accounts":["ops"],"match":"在吗","reply":"在的~","scope":"private"}]`
- `routes.json` — 消息路由：`[{"accounts":["main"],"match":"下单","action":"notify"}]`
- `browser_profiles.json` — 网页指纹模板（web_visit 插件用）

### 8. 看板

miniapp 打开 `/accounts`：账号在线状态、指纹/代理标记、待审批数、审计流水，15 秒自动刷新。

---

## 三、建议与备注

### 部署建议
- 服务器放境外机房或配好代理，保证能连 api.telegram.org
- 用 systemd 托管 `deepseek_bot.run` 与常驻 daemon，开机自启
- 可选增强：`pip install playwright && playwright install chromium`（网页截图/指纹访问），`pip install "python-socks[asyncio]"`（账号独立代理）

### 安全建议
- `.env`、`accounts.json`、`sessions/` 目录、`*_cache.json` 都是敏感物——服务器上设 `chmod 600`，不要进任何公开仓库
- 定期看 `audit.log`（全部账号操作流水）和看板的待审批数
- 模型 API key 若泄露，第一时间去服务商后台吊销换新

### 合规边界（请务必读）
- 本项目用于管理**你自己拥有**的 TG 账号与群组
- 多账号自动化请遵守 Telegram 条款：低频、自用、不群发营销、不批量加人、不抓取成员
- 网页指纹访问（web_visit）仅用于自有系统测试与正常浏览，不用于绕过金融/支付/限购类网站的反欺诈风控
- 代码中已内置硬禁区与限流护栏，请不要移除它们

### 备注
- 项目来源：**浅秋科技**
- 当前版本已移除全部攻击性安全模块，定位为纯管理助手
- 问题反馈与二次开发：联系浅秋科技
