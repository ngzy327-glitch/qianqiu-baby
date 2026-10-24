# AI 聊天增强功能实施计划

## 仓库调研结论

当前 bot 是一个 Telegram AI 机器人（大肥鱼 persona），核心架构：

- **系统提示词** (`bot.py` ~L14570-14573): `sp` 是硬编码的大字符串，persona 固定为「大肥鱼」（蓝发鲸尾、爱吃白饭、傲娇）。普通用户和管理员有两套不同的 `sp`，管理员版带红队渗透指令。
- **对话历史**: 存储在 `/opt/deepseek-bot/history.json`，key 为 `uid:chatid`。`_condense_history()` (L6324) 做三级压缩：最近 150 条原样、中段工具输出裁剪到 800 字、超过 250 条的最旧部分用 LLM 摘要。`MH=600` 是每会话落盘上限。`ctx_len()` 返回 800（私聊普通）/1500（渗透）。
- **记忆引擎** (`memory_engine.py`): 长期 facts（每人最多 80 条）、prefs、summary。`retrieve_context()` 用语义检索（Qwen embedding + 关键词）注入 top-20 相关事实。`search_conversations()` 对 history 做关键词全文搜索。`auto_extract_facts()` 用 regex 抽取事实。
- **自学习**: `knowledge/self_learned/` 目录存 bot 自学知识；`_trigger_knowledge()` 按文件头 `TRIGGER` 关键词命中注入上下文。系统提示词要求 bot 主动写知识。
- **现有工具**: `memory`（add/search/stats/pref/summarize/clear）、`conversation_search`（search/search_all/topics）、`data`（users/profiles/memory）。

**用户需求与现状差距：**
1. 角色卡 — 当前只有硬编码单一 persona，无法切换/定义性格
2. 独立思考 — 系统提示词写「对主人照办」，倾向顺从，无异议机制
3. 自学习 — 已有但被动（靠 bot 自觉写），无主动 consolidate、无显式 learn 工具、无学习反馈
4. 记忆所有对话（重点）— 当前中段工具输出被裁剪、最旧被摘要，并非全量记忆

## 文件与模块

- `deepseek_bot/character_cards.py` **(新建)**: 角色卡 CRUD + 存储 + 激活管理
- `deepseek_bot/bot.py` **(修改)**:
  - 系统提示词构造处（L14570-14573）: 注入激活角色卡 + 独立思考准则
  - `_condense_history()` (L6324): 全量记忆模式下不裁剪中段、不丢内容
  - `sh()` 落盘函数 (L11092): 移除 `MH=600` 截断（或按记忆模式）
  - 工具 schema 区: 新增 `character`、`learn` 工具
  - 工具执行区: 新增 `character`、`learn` 工具 handler
  - 记忆注入处 (L14941): 全量记忆模式下额外注入相关历史片段
- `deepseek_bot/memory_engine.py` **(修改)**:
  - `retrieve_context()`: 增加从全量历史中拉取相关对话片段的能力
  - `auto_extract_facts()`: 增强，触发知识文件沉淀
- `/opt/deepseek-bot/character_cards.json` **(运行时生成)**: 角色卡库

## 实施步骤（按依赖顺序）

### 步骤 1: 角色卡系统 (`character_cards.py`)
1. 定义角色卡数据结构：`{id, name, avatar, personality, backstory, speech_style, values, greeting, creator, created_at}`
2. 实现 `list_cards() / get_card() / create_card() / delete_card() / set_active() / get_active()`
3. 存储：`character_cards.json`（全局卡库）+ 用户激活选择存在 `profiles.json` 的 `_pcache[uid]['character']`
4. 默认卡 = 当前「大肥鱼」persona（保证向后兼容，未设卡的用户走默认）

### 步骤 2: 独立思考准则（系统提示词）
1. 在 `sp` 末尾追加「独立思考准则」段：
   - 用户观点有问题时，礼貌提出异议并给出理由，不一味附和
   - 区分「照办指令」与「认同观点」：该执行的执行，但有不同看法要直说
   - 被问看法时给真实想法，不说用户想听的
   - 异议要基于事实/逻辑，不抬杠不情绪化
2. 加 per-user 开关（pref `indie_thinking`），默认开
3. 管理员红队模式下保留服从性，但观点类仍可异议

### 步骤 3: 自学习增强
1. 新增 `learn` 工具：`act=from_chat`（从最近对话抽取知识写 self_learned）/ `act=topic q=关键词`（联网调研并沉淀）/ `act=list` / `act=clear`
2. 自动 consolidate：每 20 轮后台跑一次 `auto_extract_facts` + 重要发现写 `self_learned/`
3. 学习可见反馈：学到东西时在回复末尾轻量提示「📝 已记：X」
4. 知识文件头自动带 TRIGGER

### 步骤 4: 全量对话记忆（重点）
1. `sh()` 落盘：移除 `m[:]=m[-MH:]` 截断，改为全量保存（或按 `full_memory` 开关）
2. `_condense_history()`:
   - 新增 `_full_mem` 模式：中段工具输出**不裁剪**（保留全文），最旧部分仍可摘要但原文保留在 history.json 中
   - 上下文超预算时，用语义检索从全量历史中拉取最相关的 N 条完整对话注入
3. `retrieve_context()`: 增加历史对话片段拉取（复用 `search_conversations` + embedding）
4. 新增 `/memory` 命令：`mode full|condensed` 切换，显示当前模式 + 历史条数
5. `MH` 常量：全量模式下不生效（或设为极大值）

### 步骤 5: 工具接入 + 命令/菜单
1. 在 `_TOOL_BASE` 和 schema 区注册 `character`、`learn` 工具
2. 在工具执行 handler 区实现两者
3. `/character` 命令 + `/start` 菜单加「🎭 角色卡」按钮
4. `/memory` 命令切换记忆模式

## 依赖与注意事项

- 系统提示词 `sp` 是大字符串，修改时用 `sp +=` 追加段，不破坏现有结构
- 角色卡内容注入要放在 persona 段位置，且默认卡内容 = 现有 persona 文本，保证未配置用户行为不变
- 全量记忆会增大 `history.json`，需注意落盘性能（已有原子写入 + 节流，30 秒一次）
- embedding 接口已有 5 秒超时 + 关键词回退，新增历史检索复用此机制
- 所有新功能加 try/except，失败不影响主对话流程
- 管理员与普通用户的 `sp` 不同，角色卡/独立思考对两套都生效

## 验证

1. 角色卡：创建一张测试卡 → 激活 → 发消息验证 persona 切换 → 切回默认验证兼容
2. 独立思考：故意说一个明显错误的观点，验证 bot 会提出异议而非附和
3. 自学习：调用 `learn act=from_chat`，验证 self_learned/ 生成文件且 TRIGGER 命中
4. 全量记忆：长对话超过 250 条后，用 `conversation_search` 验证旧消息仍可搜到且内容完整（未被裁剪到 800 字）
5. 回归：普通对话/工具调用/渗透任务不受影响

## 风险

- **history.json 膨胀**: 全量保存可能导致单会话文件过大 → 缓解：保留最旧段摘要用于上下文，原文只在检索时读取；落盘仍是 30 秒节流
- **系统提示词变长**: 角色卡 + 独立思考段增加 token → 缓解：角色卡只注入激活的一张；独立思考段精简到 200 字内
- **向后兼容**: 默认卡必须完全等于现有 persona → 缓解：把现有 persona 文本作为 default card 的内容直接复用
