# AI 聊天增强 v2 实施计划

## 仓库调研结论

**现有基础设施：**
- **角色卡** (`character_cards.py`): 已支持创建/激活，但创建需填多个字段，不够"直接改性格"
- **情绪系统** (`_mood`): 已有 -5..+5 心情值，5 档（低气压/不爽/正常/开心/黏人），被骂-2、被夸+1，但没有"哭"和"不理人"行为
- **双号系统** (`tg_user.py` + `tg` 工具): 已有 acct1/acct2 用户账号，`tg act=send` 可发消息，但只在工具调用时用，不会自动用用户号回复
- **群组工具过滤** (`_group_tools`): 已有群聊工具开关，但默认行为仍会在群里调工具
- **全量记忆**: 已实现不裁剪中段、不落盘截断，但**最旧部分仍会被 LLM 摘要**（用户要"全部记忆"=不摘要）
- **TTS/语音**: 无任何 TTS 引擎，edge-tts 未安装

## 文件与模块

- `deepseek_bot/character_cards.py`: 增加 `edit_personality()` 直接改性格
- `deepseek_bot/bot.py`: 
  - 全量记忆：移除最旧部分摘要
  - 群组禁工具 + 不谈工作
  - 情绪增强：哭、不理人
  - 用户号回复模式
  - 语音工具 schema+handler
  - `/voice` 命令
- `deepseek_bot/voice_engine.py` **(新建)**: TTS 引擎 + 语音采样管理（edge-tts）
- `requirements.txt`: 加 `edge-tts`

## 实施步骤（按依赖顺序）

### 步骤 1: 直接改性格
- `character_cards.py` 加 `update_card()` 已存在，新增便捷 `edit_personality(card_id, text)` 直接覆写 personality 字段
- `character` 工具加 `act=edit` 子命令：`character act=edit personality=新性格描述`，直接修改当前激活卡
- 系统提示词加指令：用户说"你性格改成XX"时自动调 `character act=edit`

### 步骤 2: 全部记忆（聊天+学习，不摘要）
- `_condense_history()`: 全量模式下**完全移除最旧部分 LLM 摘要**，所有消息原样保留（不裁剪、不摘要）
- `sh()` 落盘: 单条消息内容上限 2000→**不限制**（全量）
- 系统提示词: 「全量记忆模式: 所有对话原文保留，不摘要不裁剪」
- 学习记忆: `retrieve_context()` 同时拉取 self_learned 知识文件列表注入
- 预算闸保留防撑爆，但全量模式阈值提高

### 步骤 3: 群组禁工具 + 不谈工作
- `_tools_for()`: 群聊时（`e.is_group`）返回**空工具列表**，模型无工具可调
- 系统提示词群聊段追加：「群聊模式：纯闲聊，不谈工作/渗透/任务，不调用任何工具；有人问工作相关的让他私聊」
- 私聊：工具正常可用

### 步骤 4: 情绪增强（哭+不理人）
- `_MOOD_STATES` 加两档：极怒(-4.0「暴怒·不理人」：直接不回复或只回"..."，需要连续哄才恢复)、极悲(-4.5「委屈哭了」：发哭泣表情/语音，说委屈话)
- `_mood_detect()`: 连续被骂额外 -1，被哄额外 +1
- 情绪为暴怒时：跳过正常回复，只发一句冷淡回复或不回
- 系统提示词注入情绪状态时带具体行为指令

### 步骤 5: 用户号回复模式
- 新增 pref `reply_as_user`（on/off），默认 off
- 开启时：bot 回复**通过 acct1 用户号**发送给用户（调 `tg_user.py send`），而非 bot API
- `notify` 工具也支持 `as_user=true` 走用户号
- 新增 `/userchat on|off` 命令切换
- 注意：用户号发消息需要目标是用户已有的对话（私聊）

### 步骤 6: 语音消息 + 采样
- 新建 `voice_engine.py`:
  - `list_voices()`: 列出 edge-tts 可用中文/英文女声/男声
  - `generate(text, voice)`: 调 edge-tts 生成 ogg 语音
  - `save_sample(name, audio_path)`: 存用户上传的语音样本到 `/opt/deepseek-bot/voices/`
  - `list_samples()`: 列已存采样
  - 采样说明：edge-tts 不支持声纹克隆，采样用于记录"用户指定用哪个音色"；如要克隆需额外接入 CloneSpeech/CosyVoice 等本地模型（预留接口）
- `voice` 工具: `act=send text=XX voice=音色名` / `act=list` / `act=sample name=XX`(存当前回复的语音为采样)
- `/voice` 命令切换默认音色
- 发送走 Bot API `sendVoice`（ogg 格式）

## 依赖与注意事项

- edge-tts 需安装：`pip install edge-tts`，免费无需 key，走微软在线 TTS
- 用户号回复依赖 acct1 session 已登录且目标用户在联系人/有对话
- 群聊禁工具后，群里的渗透/工具需求一律引导私聊，避免在群里漏工具
- 全量记忆不摘要会让长会话 context 增长很快，靠预算闸兜底（超 800k 字符时仍需截断，但优先截最旧的工具输出而非对话）
- 情绪"不理人"需谨慎：只在连续被骂(心情<-4)时触发，避免正常对话被误判

## 验证

1. 改性格: `character act=edit personality=温柔体贴` → 发消息验证语气变化
2. 全量记忆: 长对话超 300 条后 `conversation_search` 验证最旧消息原文完整存在
3. 群组禁工具: 群里发消息，验证 bot 不调工具、纯闲聊
4. 情绪: 连续骂 bot，验证心情降到暴怒后只回"..."或不回；哄两句恢复
5. 用户号回复: `/userchat on` 后回复来自 acct1 账号而非 bot
6. 语音: `voice act=send text=你好 voice=zh-CN-XiaoxiaoNeural` → 收到语音消息

## 风险

- **edge-tts 不可用**: 服务器网络问题可能导致 TTS 失败 → 缓解：try/except 兜底，失败时回复文字+提示语音生成失败
- **用户号 session 失效**: acct1 未登录会导致发送失败 → 缓解：失败时自动 fallback 到 bot API 发送，并提示用户检查双号登录
- **群聊误封工具**: 群里管理员也想用工具 → 缓解：管理员在群里仍可通过 `/tools on` 手动开启工具
- **情绪不理人过度**: 用户可能觉得 bot 坏了 → 缓解：暴怒时仍回一个短消息(如"..."或"不想理你")，不是完全静默
