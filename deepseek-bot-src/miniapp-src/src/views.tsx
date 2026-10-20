/** 八个板块: 概览 / 任务 / 对话 / 工作台 / 值守 / 设置 / 文件 / 账单 */
import * as React from 'react'
import { Paperclip, Send, Square, Play, Pause, Trash, Upload, Download, RefreshCw, MessageSquare, Terminal, Eye, Settings2, Folder, CreditCard, Plus, Undo2, Zap, ListChecks, Check, Circle, Loader2, Brain, Megaphone, Globe, Search, FileText, FilePen, Image as ImageIcon, CircleDollarSign, Bell, Users, Send as SendIcon, Target, Bot, Shield, BarChart3, KeyRound, Link2, X, Activity } from 'lucide-react'
import { api, fmt, ME, BOT_AVATAR, type Session, type State, type Step, type ToolEvent } from './api'
import { Markdown } from './md'
import { M, I } from './morph'
import { DisclosureRow } from './dsh/DisclosureRow'
import { Btn, Card, Empty, Input, Row, Select, Spinner, Stats, Switch, Tag, cx } from './ui'
import { SpringIn, SpringGrow, setMotionFrameHook } from './motion'

type Ctx = { S: State; reload: (quiet?: boolean) => Promise<void>; toast: (t: string) => void }

/* ---------------- 概览 ---------------- */
export function Overview({ S }: Ctx) {
  const cur = S.topics.find((t) => t.current)
  const running = S.tasks.length
  const mood = (S.mood || '').replace(/\s+/g, ' ')
  return (
    <>
      <Card title="当前状态" right={<Tag tone={running ? 'warn' : 'ok'}>{running ? `${running} 个在跑` : '空闲'}</Tag>}>
        <Stats items={[
          ['工作台', cur ? cur.name : '主聊天', cur ? `话题 ${cur.topic}` : '未在话题里'],
          ['模型', S.model.mode || '-', `推理 ${S.model.think || '-'}`],
          ['剩余额度', `${S.quota.balance ?? '-'} 次`, '管理员不限'],
          ['今日条数', String(S.quota.today ?? 0), `${S.quota.tokens ?? 0} tokens`],
        ]} />
      </Card>
      {!!(mood || S.goal || S.queue) && (
        <Card title="状态">
          {!!S.goal && <Row k="目标" sub={S.goal} />}
          {!!S.queue && <Row k="排队" v={`${S.queue} 条`} />}
          {!!mood && <Row k="心情" sub={mood.slice(0, 160) + (mood.length > 160 ? '…' : '')} />}
        </Card>
      )}
      <Card title="运行时">
        <Row k="模型池" v={`${S.model.light || ''}${S.model.pro ? ' / ' + S.model.pro : ''}`} mono />
        <Row k="开关" v={`播报 ${S.switches.talk ? '开' : '关'} · 打字机 ${S.switches.typewriter ? '开' : '关'} · 表情 ${S.switches.emoji ? '开' : '关'}`} />
      </Card>
    </>
  )
}

/* ---------------- 任务 ---------------- */
export function Tasks({ S, reload, toast }: Ctx) {
  return (
    <>
      <TodoPanel S={S} reload={reload} toast={toast} />
      {!S.tasks.length
        ? <Card title="后台任务"><Empty>现在没有在跑的后台活儿</Empty></Card>
        : (
          <Card title={`后台任务 · ${S.tasks.length}`}>
            {S.tasks.map((t) => (
              <div key={t.uid + t.kind} className="flex items-start gap-3 border-b border-lineweak py-2.5 last:border-b-0">
                <div className="minw0 flex-1">
                  <div className="flex items-center gap-2">
                    <Tag tone={t.kind === 'dl' ? undefined : 'ok'}>{t.kind === 'dl' ? '下载' : '命令'}</Tag>
                    <span className="minw0 truncate font-mono text-[12.5px]">{t.title}</span>
                  </div>
                  <div className="mt-1 text-[12px] text-fg3">
                    已跑 {fmt.sec(t.elapsed)}
                    {t.idle && t.idle > 25 ? <span className="text-warn"> · {fmt.sec(t.idle)} 无输出</span> : null}
                  </div>
                  {!!t.line && <div className="mt-1 break-any font-mono text-[11.5px] text-fg3">{t.line.slice(-200)}</div>}
                </div>
                <Btn variant="danger" onClick={async () => {
                  try { const r = await api.stopTask(t.uid, t.kind); toast(r.killed ? '已停止' : '没找到进程'); await reload(true) }
                  catch (e: any) { toast(e.message) }
                }}><Square size={13} />停止</Btn>
              </div>
            ))}
          </Card>
        )}
    </>
  )
}

/** 计划/任务清单(和 TG 面板同一份数据): DSH 那种"计划→进行中→已完成"的勾选列表 */
export function TodoPanel({ S }: Ctx) {
  const items = S.todo?.items || []
  if (!items.length) return null
  const done = items.filter((i) => i.state === 'done').length
  return (
    <Card title={`计划 · ${done}/${items.length}`}>
      {items.map((it, i) => (
        <div key={i} className="flex items-start gap-2 py-0.5 text-[13px]">
          <span className={cx('mt-[2px] inline-flex shrink-0', it.state === 'done' ? 'text-ok' : it.state === 'doing' ? 'text-accent' : 'text-fg4')}>
            {it.state === 'done' ? <Check size={13} /> : it.state === 'doing' ? <Loader2 size={13} className="animate-spin" /> : <Circle size={10} />}
          </span>
          <span className={cx('minw0 break-any', it.state === 'done' && 'text-fg3 line-through')}>{it.text}</span>
        </div>
      ))}
    </Card>
  )
}

/** 折叠行给人话, 不甩命令原文(2026-09-20 对齐 TG 口径: 播报/行标题不许贴 cmd) */
function argHint(e: ToolEvent): string {
  const a = String(e.args || '').replace(/\s+/g, ' ').trim()
  if (!a) return ''
  const pick = (k: string) => {
    const m = a.match(new RegExp(k + '=([^,]{1,70})'))
    return m ? m[1].trim() : ''
  }
  const cmd = pick('cmd')
  if (cmd) {
    if (/python3?\b/.test(cmd)) return '跑了一段 python'
    if (/\bcurl\b|\bwget\b/.test(cmd)) return '发了 HTTP 请求'
    if (/\b(nmap|masscan|naabu)\b/.test(cmd)) return '扫端口'
    if (/\b(nuclei|ffuf|gobuster|dirb|sqlmap|hydra)\b/.test(cmd)) return '跑扫描器'
    if (/\b(grep|rg|awk|sed)\b/.test(cmd)) return '文本检索'
    if (/\b(cat|head|tail|less|more)\b/.test(cmd)) return '看文件内容'
    if (/\b(nc|ssh|scp|rsync)\b/.test(cmd)) return '网络搬运'
    if (/\b(pip|npm|apt|git)\b/.test(cmd)) return '装/拉东西'
    return '跑了一条命令'
  }
  const p = pick('path') || pick('file')
  if (p) return p
  const q = pick('q') || pick('query') || pick('keyword') || pick('pattern')
  if (q) return q
  // 2026-09-23 老板「有点乱」→ URL 只留 host+path(去掉 url= 前缀、协议、www.):
  //   原来一行里 "url=https://www.toum.com/hot.html" 这种前缀纯噪音, 缩掉一半字数。
  const u = pick('url') || (a.match(/https?:\/\/[^\s,)"']{4,90}/) || [''])[0]
  if (u) return String(u).replace(/^url=/, '').replace(/^https?:\/\//, '').replace(/^www\./, '').slice(0, 78)
  return pick('name')
}

/** 一条工具行: 用 DSH 的 DisclosureRow(点开看输出), 跑的时候图标位置是转圈; write/edit 带 diff 统计 */
function ToolRow({ e }: { e: ToolEvent }) {
  const [open, setOpen] = React.useState(false)
  const label = toolMeta(e.tool)[1]
  const stat = diffStat(e)
  // 2026-09-20 老板「点展开了还要再点一次看全文本」→ 输出不再截断, 长内容交给 pre 自己滚
  const _shown = e.out || ''
  // 2026-09-23 老板「折叠开有点卡」→ 卡的另一半在**首帧渲染**: 一次展开要把整段输出扔进 <pre>
  //   (工具输出经常几万字), 浏览器要先排版这么大一块文本才让步给高度动画 → 前几帧直接卡住。
  //   做法: 短输出照旧立刻渲染; 长输出(>4000 字)把正文挪到动画起步之后 90ms 再挂上去,
  //   让 340ms 的展开动画先跑起来(内容本来就有 240ms 淡入, 看不出这块是后到的)。
  const [paintBody, setPaintBody] = React.useState(false)
  React.useEffect(() => {
    if (!open) return
    if (_shown.length <= 4000) { setPaintBody(true); return }
    const t = window.setTimeout(() => setPaintBody(true), 90)
    return () => window.clearTimeout(t)
  }, [open, _shown.length])
  return (
    // 2026-09-30 老板「动画不行 我要求和他一样」→ 行进场交给 <SpringIn>(= Compose 的
    //   AnimatedVisibility(slideInVertically { it/2 } + fadeIn())): 高度从 0 弹簧撑开 + 位移量取自身高度一半。
    //   原来那条 anim-step 是 max-height 0→1200→2400 的"障眼法"(高度不是真值, 靠猜的数撑), 换掉。
    <SpringIn>
    <DisclosureRow
      icon={e.status === 'run' ? <Spinner className="mr-0" /> : <ToolIcon tool={e.tool} />}
      title={label}
      open={open}
      expandable={!!e.out}
      onToggle={() => setOpen(!open)}
      expandOnRowClick
      collapsedContent={
        <span className="minw0 flex items-baseline gap-2 overflow-hidden">
          <span className={cx('truncate arg-hint', e.status === 'run' && 'shimmer')}>{argHint(e)}</span>
          {stat ? <span className="shrink-0 font-mono text-[11px] text-ok">{stat}</span> : null}
          <span className={cx('shrink-0 font-mono text-[11px]', e.status === 'err' ? 'text-err' : 'text-fg4')}>
            {e.status === 'err' ? '✗ ' : ''}{e.ms != null ? `${(e.ms / 1000).toFixed(1)}s` : ''}
          </span>
        </span>
      }
      className={cx('glass-row glass-tool',
        e.status === 'run' && 'run-live',
        // 2026-09-23 老板「这样显示我感觉 有点乱」→ 跑完又没收起的工具行**不再是卡片**(透明无框),
        //   跑着/出错/展开才用玻璃卡。一屏十几条就不会全是同宽的亮条了。
        e.status === 'ok' && !open && 'tool-slim')}
    >
      {/* 折叠态只给人话(口径同 TG), 但展开态直接给全 —— 不再套 <details> 让老板点第三次 */}
      {!!e.args && (
        <div className="mb-1.5">
          <div className="mb-0.5 text-[11px] text-fg4">命令 / 参数</div>
          <pre className="max-h-[180px] overflow-auto whitespace-pre-wrap break-any rounded-[8px] border border-lineweak px-2 py-1.5 font-mono text-[11px] leading-[1.5] text-fg3">{e.args}</pre>
        </div>
      )}
      {/* 2026-09-18 "AI 浏览了什么"要看得到: URL 单独列成可点链接 + 输出可展开全文 */}
      {!!e.urls?.length && (
        <div className="mb-1 space-y-0.5">
          {e.urls.map((u, i) => (
            <a key={i} href={u} target="_blank" rel="noreferrer"
              className="flex items-center gap-1 truncate font-mono text-[11.5px] text-accent underline decoration-dotted">
              <Link2 size={11} className="shrink-0" /><span className="truncate">{u}</span>
            </a>
          ))}
        </div>
      )}
      {/* 2026-09-23: 长输出等展开动画起步后再挂(见上面 paintBody) —— 首帧不再为几万字排版 */}
      {paintBody ? (
        <pre className="max-h-[420px] overflow-auto whitespace-pre-wrap break-any rounded-[8px] border border-lineweak bg-muted px-2 py-1.5 font-mono text-[11.5px] leading-[1.5] text-fg2">
          {_shown || '(无输出)'}
        </pre>
      ) : (
        <div className="rounded-[8px] border border-lineweak bg-muted px-2 py-1.5 font-mono text-[11.5px] text-fg4">
          正在渲染输出（{_shown.length.toLocaleString()} 字）…
        </div>
      )}
    </DisclosureRow>
    </SpringIn>
  )
}

/** 打字机: 把已拿到的文字**逐字**吐出来。
 *  2026-09-20 老板「网页版和bot不一样 打字机可以一个字一个字的打」→ 加了它;
 *  紧接着「弹的太快了 动画不行 打字怎么这么快」→ 改成**按字/秒**推进的常驻 rAF 循环:
 *    · 默认 20 字/秒(50ms 一个字), 是人能看进去的速度, 不再是"糊上去"
 *    · 后端积压越多越加速(>120字→40/秒, >400字→70/秒), 免得长播报追不上
 *    · 用 requestAnimationFrame 按**时间差**算该出几个字, 比 setTimeout 稳(不掉帧、不并帧)
 *    · 循环常驻空转(一帧判断一次), 后端推新字就自己接着打; 换轮(stream 变短)从头打 */
function Typewriter({ text, cps = 10, cursor }: { text: string; cps?: number; cursor?: boolean }) {
  const [vis, setVis] = React.useState('')
  const target = React.useRef('')
  const shown = React.useRef(0)
  const acc = React.useRef(0)
  const prev = React.useRef(0)
  const raf = React.useRef(0)

  // 2026-09-22 呼吸动效交给 CSS(.breathe) —— 这里不再跑 600ms 的 setInterval 翻转,
  //   少一个每秒重渲染的定时器, 动画还更顺(纯合成层动画)。

  React.useEffect(() => {
    if (text.length < target.current.length) {   // 后端把 stream 清了 → 新一段, 从头打
      shown.current = 0
      acc.current = 0
      setVis('')
    }
    target.current = text
  }, [text])

  React.useEffect(() => {
    prev.current = performance.now()
    const step = (now: number) => {
      const dt = now - prev.current
      prev.current = now
      const t = target.current
      const backlog = t.length - shown.current
      if (backlog > 0) {
        // 2026-09-22 老板「打字改成10/s」→ 基准 10 字/秒; 只有积压很猛(>400字)才提到 20, 免得长播报追不上
        const _cps = backlog > 400 ? 20 : cps
        acc.current += dt * _cps / 1000
        if (acc.current >= 1) {
          const add = Math.min(Math.floor(acc.current), backlog)
          acc.current -= add
          shown.current += add
          setVis(t.slice(0, shown.current))
        }
      } else {
        acc.current = 0
      }
      raf.current = requestAnimationFrame(step)
    }
    raf.current = requestAnimationFrame(step)
    return () => { if (raf.current) cancelAnimationFrame(raf.current) }
  }, [cps])

  // 没有 markdown 语法的普通句子直接出纯文本 —— 打字机每秒要重渲染几十次,
  //   每次都全量解析一遍 markdown 会掉帧(老板「动画不行」), 走快路径就顺了。
  const _hasMd = /[*`_#>|\[\]]/.test(vis) || vis.includes('\n')
  return (
    <>
      {_hasMd
        ? <Markdown text={vis} />
        : <span className="tw whitespace-pre-wrap break-any">{vis}</span>}
      {/* 2026-09-22 老板「没有呼吸动效」→ 光标不再是 ⌛️/⏳ 两帧硬切(那是"闪", 不是"呼吸"),
          改成一颗**会呼吸的** ⌛️: 幅度很小的缩放 + 透明度起伏, 一眼看出"它正在写"。 */}
      {cursor && shown.current < target.current.length
        ? <span className="breathe ml-1 inline-block align-[-2px] text-[13px] leading-none">⌛️</span>
        : null}
    </>
  )
}


/** 一轮的过程行 —— 2026-09-20 老板「播报过程怎么在思考里面」「思考还打不开」:
 *  原来播报(note)被当成折叠摘要挂在「思考」这一行上 → 看着就是"播报混进思考"。
 *  现在拆成两条独立行:
 *    ① 🗣 播报行: 每轮那句"在干什么", 只有一句话, 不折叠, 一眼扫过去就是过程
 *    ② 💭 思考行: 单独一行, **点一下展开看全文**(默认收起, 不挡着过程往下追加) */
function ThinkRow({ st }: { st: Step }) {
  const [open, setOpen] = React.useState(false)
  return (
    <SpringIn>
      {st.note ? (
        // 2026-09-20 老板「这个过程播报文字太小了 而且没有富文本」:
        //   原来是一颗 12.5px 的纯文本 span —— 比正文还小, 加粗/代码/emoji 全不认。
        //   现在走 <Markdown>(和正文同一个渲染器), 字号在 index.css 的 .glass-note .md 里给到 15px。
        <div className="glass-row glass-note anim-step flex items-start gap-1.5">
          <span className="mt-[3px] shrink-0 text-accent"><Megaphone size={13} /></span>
          <div className="minw0 flex-1"><Markdown text={st.note} /></div>
        </div>
      ) : null}
      {st.think ? (
        <DisclosureRow
          icon={<span className="inline-flex items-center text-fg3"><Brain size={12} /></span>}
          title={`看思考 · ${st.think.length} 字`}
          open={open}
          expandable
          onToggle={() => setOpen(!open)}
          expandOnRowClick
          className="glass-row glass-think anim-step"
        >
          <div className="max-h-[340px] overflow-y-auto whitespace-pre-wrap break-any rounded-[8px] bg-muted px-2 py-1.5 text-[11.5px] leading-[1.55] text-fg3">
            {st.think}
          </div>
        </DisclosureRow>
      ) : null}
    </SpringIn>
  )
}

/** 执行过程: **扁平的行列表** —— 每轮先一条"思考", 后面跟着这一轮的工具行(都点得开看细节) */
export function Steps({ steps, events, live }: { steps: Step[]; events: ToolEvent[]; live?: boolean }) {
  if (!steps?.length) return null
  // 2026-09-20 老板「为什么是结果出来 所有追加才显示」: 正在跑的那一轮后端把 to 写成 null,
  //   `st.to ?? 0` 会把它吃成 0 → slice(from, 0) 恒为空, 这一轮的工具**一条都不显示**,
  //   非得等这一轮结束、to 被补上才一次性冒出来。null 应该是"到最新"。
  return (
    <div className="steps mt-1.5">
      {steps.map((st, i) => {
        // 2026-09-23 老板「这样显示我感觉 有点乱」→ 每轮加一条极淡的分组头(第 N 轮 · 工具数 · 本轮耗时),
        //   后面跟一条细线。一屏里能立刻看出"这是第几轮、哪几条工具属于它", 不再是十几条平铺的亮条。
        const _ev = events.slice(st.from ?? 0, st.to ?? events.length)
        const _ms = _ev.reduce((a, e) => a + (e.ms || 0), 0)
        return (
          <div key={i} className="mb-2 space-y-1 last:mb-0">
            <div className="round-head">
              <span>第 {st.rnd || i + 1} 轮</span>
              <span>· {_ev.length} 个工具</span>
              {_ms > 0 ? <span>· {( _ms / 1000).toFixed(1)}s</span> : null}
            </div>
            <ThinkRow st={st} />
            {_ev.map((e, j) => <ToolRow key={`${i}-${j}`} e={e} />)}
          </div>
        )
      })}
    </div>
  )
}

/** 网页的「选择题」: ask 工具的问题渲染成可点选项(TG 那边是按钮, 网页原来收不到) */
function AskCard({ q, opts, multi, onPick, busy }: { q: string; opts: string[]; multi: boolean; onPick: (a: string) => void; busy?: boolean }) {
  const [sel, setSel] = React.useState<number[]>([])
  const pick = (i: number) => {
    if (multi) setSel((s) => (s.includes(i) ? s.filter((x) => x !== i) : [...s, i]))
    else onPick(opts[i])
  }
  return (
    <div className="anim-pop mt-1.5 rounded-[10px] border border-line bg-muted px-2.5 py-2">
      <div className="break-any text-[13px] font-medium">❔ {q}{multi ? <span className="ml-1 text-[11px] text-fg3">（多选）</span> : null}</div>
      <div className="mt-1.5 flex flex-wrap gap-1.5">
        {opts.map((o, i) => (
          <button key={i} type="button" disabled={busy} onClick={() => pick(i)}
            className={cx('rounded-full border px-2.5 py-1 text-[12.5px] tap',
              sel.includes(i) ? 'border-accent bg-soft2 text-fg' : 'border-line bg-card text-fg2 hover:bg-muted')}>
            {multi ? (sel.includes(i) ? '☑ ' : '☐ ') : ''}{o}
          </button>
        ))}
      </div>
      <div className="mt-2 flex gap-1.5">
        {multi && (
          <Btn size="sm" variant="primary" disabled={busy || !sel.length}
            onClick={() => onPick(sel.sort((a, b) => a - b).map((i) => opts[i]).join('、'))}>提交选择</Btn>
        )}
        <Btn size="sm" variant="outline" disabled={busy} onClick={() => onPick('')}>你自己定</Btn>
      </div>
    </div>
  )
}

/** 子代理/团队进度: 网页里也看得到它跑到第几轮、用了几个工具 */
function SubPanel({ sub }: { sub: { idx: number; task: string; role?: string; rnd: number; tools: number; done: boolean }[] }) {
  if (!sub?.length) return null
  return (
    <div className="mt-1 space-y-0.5">
      {sub.map((s) => (
        <div key={s.idx} className="anim-step flex items-center gap-1.5 text-[11.5px] text-fg3">
          <span className="shrink-0">🤖</span>
          <span className="shrink-0 rounded-full bg-muted px-1.5 font-mono">#{s.idx}</span>
          <span className="minw0 flex-1 truncate">{s.task || s.role || '子任务'}</span>
          <span className="shrink-0 font-mono text-fg4">
            {s.done ? '✓ ' : ''}{s.rnd ? `第${s.rnd}轮` : ''}{s.tools ? ` · ${s.tools}工具` : ''}
          </span>
        </div>
      ))}
    </div>
  )
}

/** 头像: 大肥鱼用老板给的图, 我用 Telegram 头像(initData 里的 photo_url); 拿不到就退回 emoji */
function Av({ me, size = 24 }: { me: boolean; size?: number }) {
  const s = { width: size, height: size }
  if (me) {
    return ME.photo
      ? <img src={ME.photo} style={s} className="shrink-0 rounded-[7px] border border-lineweak object-cover" alt="" />
      : <span style={s} className="grid shrink-0 place-items-center rounded-[7px] border border-lineweak bg-muted text-[12px]">🙋</span>
  }
  return <img src={BOT_AVATAR} style={s} className="shrink-0 rounded-[7px] border border-lineweak object-cover" alt="大肥鱼" />
}

/** 会话选择: **自己的下拉, 不用原生 <select>**。
 *  2026-09-20 老板第二张截图: 原生 select 在 iOS 上弹的是系统选择器 —— 每行左边空一大格
 *  (系统给勾选标记留的位置)、右边一个空心圆, 跟网页主题完全两张皮。这里改成普通按钮 + 自绘列表。 */
function SessPicker({ value, items, onPick }: { value: string; items: Session[]; onPick: (v: string) => void }) {
  const [open, setOpen] = React.useState(false)
  const cur = items.find((s) => s.id === value)
  const label = cur ? `${cur.title}${cur.n ? ` (${cur.n})` : ''}` : '会话'
  return (
    <div className="relative min-w-0 flex-1">
      <button type="button" onClick={() => setOpen(!open)}
        className="flex h-9 w-full items-center gap-1.5 rounded-[10px] border border-line bg-muted px-2.5 text-[13px] tap">
        <span className="minw0 flex-1 truncate text-left">{label}</span>
        <M icon={open ? I.chevDown : I.chevRight} size={13} className="shrink-0 opacity-60" />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-30" onClick={() => setOpen(false)} />
          <div className="absolute left-0 top-[calc(100%+4px)] z-40 max-h-[52vh] w-[min(78vw,320px)] overflow-y-auto rounded-[12px] border border-line bg-card p-1 shadow-xl">
            {items.length ? items.map((s) => (
              <button key={s.id} type="button" onClick={() => { onPick(s.id); setOpen(false) }}
                className={cx('flex w-full items-center gap-2 rounded-[8px] px-2.5 py-2 text-left text-[13px] tap',
                  s.id === value ? 'bg-soft2 font-semibold text-fg' : 'text-fg2 hover:bg-muted')}>
                <span className="minw0 flex-1 truncate">{s.title}{s.n ? ` (${s.n})` : ''}</span>
                {s.id === value ? <M icon={I.check} size={13} className="shrink-0 text-accent" /> : null}
              </button>
            )) : <div className="px-2.5 py-2 text-[13px] text-fg3">没有别的会话</div>}
          </div>
        </>
      )}
    </div>
  )
}

/* ---------------- 对话 ---------------- */
/* fresh: 刚追加进来的(要播入场动画)。历史消息/切会话时**不播** —— 否则一打开就满屏乱动。
   DOM 复用后动画本来也不会重播, 但首屏渲染时它们是同一批新挂载的, 所以必须显式区分。 */
type Msg = { me: boolean; text: string; events?: ToolEvent[]; steps?: Step[]; inject?: boolean; fresh?: boolean }
/** 工具中文名+图标(跟 TG 心跳里那套一致, 网页也这么显示) */
const TOOL_META: Record<string, [string, string]> = {
  sh: ['💻', '执行命令'], url: ['🌐', '抓取网页'], search: ['🔍', '联网搜索'], read: ['📖', '读取文件'],
  write: ['📝', '写入文件'], file: ['📁', '生成文件'], edit: ['📝', '编辑代码'], img: ['🖼', '看图'],
  coin: ['💰', '查币价'], notify: ['📢', '发送通知'], group: ['👥', '群管理'], pdf: ['📄', '生成PDF'],
  tg: ['📨', 'TG双号'], watch: ['👁', '值守'], todo: ['✅', '任务清单'], goal: ['🎯', '目标'],
  subagent: ['🤖', '子代理'], team: ['👥', '多AI协作'], sys: ['⚙️', '系统操作'], memory: ['🧠', '记忆'],
  conversation_search: ['🔍', '搜历史'], captcha: ['🔐', '打码'], proxy: ['🛡', '代理'], data: ['📊', '数据'],
}
const toolMeta = (n: string): [string, string] => TOOL_META[n] || ['🔧', n]

/** 2026-09-22 老板「图标也不好看」→ 工具图标从 emoji 换成 lucide 线性图标(和顶部工具栏同一套),
 *  没映射到的工具回落到通用 Terminal, 语义清楚又不会五种字体混排。 */
const TOOL_ICON: Record<string, any> = {
  sh: Terminal, url: Globe, search: Search, read: FileText, write: FilePen, file: Folder, edit: FilePen,
  img: ImageIcon, coin: CircleDollarSign, notify: Bell, group: Users, pdf: FileText, tg: SendIcon,
  watch: Eye, todo: ListChecks, goal: Target, subagent: Bot, team: Users, sys: Settings2, memory: Brain,
  conversation_search: Search, captcha: KeyRound, proxy: Shield, data: BarChart3,
}

function ToolIcon({ tool, size = 13 }: { tool: string; size?: number }) {
  const C = TOOL_ICON[tool] || Terminal
  return <span className="inline-flex shrink-0 items-center text-fg3"><C size={size} /></span>
}

/** 工具的 diff 统计(write/edit 才有): DSH 轨迹里那种 `+33 -6` */
function diffStat(e: ToolEvent): string {
  try {
    const a: any = (e as any).argsRaw || {}
    const lines = (s: any) => String(s || '').split('\n').length
    if (e.tool === 'write' && a.text) return `+${lines(a.text)}`
    if (e.tool === 'edit' && (a.new || a.old)) {
      const add = a.new ? lines(a.new) : 0
      const del = a.old ? lines(a.old) : 0
      return `+${add} -${del}`
    }
  } catch { /* ignore */ }
  return ''
}

/** 工具执行: **默认折叠**成一行摘要(老板反馈"显示太大了"), 点开才看每条; 跑的时候只显示当前那一条 */
function ToolFold({ ev, live }: { ev: ToolEvent[]; live?: boolean }) {
  const [open, setOpen] = React.useState(false)
  if (!ev?.length) return null
  const total = ev.reduce((a, e) => a + (e.ms || 0), 0)
  const bad = ev.filter((e) => e.status === 'err').length
  const running = ev.filter((e) => e.status === 'run')
  const cur = running.length ? running[running.length - 1] : ev[ev.length - 1]

  if (live) {
    const label = toolMeta(cur.tool)[1]
    return (
      <div className="anim-step mt-1 flex items-center gap-1.5 text-[12.5px] text-fg3">
        <ToolIcon tool={cur.tool} />
        <span className="minw0 flex-1 truncate">
          <span className={cx(live && 'shimmer')}>{label}</span>
          {cur.args ? <span className="font-mono text-[11.5px] text-fg4"> · {cur.args}</span> : null}
        </span>
        <Spinner className="mr-0 shrink-0" />
        {ev.length > 1 ? <span className="shrink-0 font-mono text-[11px] text-fg4">+{ev.length - 1}</span> : null}
      </div>
    )
  }
  return (
    <div className="mt-1">
      <button type="button" onClick={() => setOpen(!open)}
        className="anim-pop flex items-center gap-1.5 rounded-full border border-lineweak px-2 py-0.5 text-[11.5px] text-fg3 tap">
        <M icon={open ? I.chevDown : I.chevRight} size={13} />
        <span>{ev.length} 个工具</span>
        {total > 0 && <span className="font-mono text-fg4">{(total / 1000).toFixed(1)}s</span>}
        {bad > 0 && <span className="text-err">{bad} 失败</span>}
      </button>
      <div className="fold" data-open={open ? '1' : '0'}>
        <div className="fold-in">
          <div className="mt-1 space-y-0.5 border-l border-lineweak pl-2">
            {ev.map((e, i) => {
              const label = toolMeta(e.tool)[1]
              return (
                <div key={i} className="flex items-start gap-1.5 text-[12px] leading-[1.5] text-fg3"
                  style={{ ['--d' as any]: `${Math.min(i, 6) * 32}ms` }}>
                  <ToolIcon tool={e.tool} size={12} />
                  <span className="minw0 flex-1 break-any">
                    {label}{e.args ? <span className="font-mono text-[11px] text-fg4"> · {e.args}</span> : null}
                  </span>
                  <M icon={e.status === 'err' ? I.x : I.check} size={12} className={e.status === 'err' ? 'shrink-0 text-err' : 'shrink-0 text-fg4'} />
                  <span className={cx('shrink-0 font-mono text-[11px]', e.status === 'err' ? 'text-err' : 'text-fg4')}>
                    {e.ms != null ? `${(e.ms / 1000).toFixed(1)}s` : ''}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}

/** 消息正文: **直接给全文**。
 *  2026-09-20 老板「我不是已经默认显示全部了吗 为啥还要点击展开」—— 原来 >420 字会截成 300 字
 *  再挂一个「展开全部 (N 字)」按钮(上一轮只清掉了工具行里全角括号那个, 漏了这里)。长文交给消息区自己滚。 */
function Bubble({ text }: { text: string }) {
  return <Markdown text={text} />
}

export function Chat({ S, toast, reload }: Ctx) {
  const [topic, setTopic] = React.useState<number>(0)
  const [sess, setSess] = React.useState<string>('tg')
  const [sessions, setSessions] = React.useState<Session[]>([])
  const [msgs, setMsgs] = React.useState<Msg[]>([])
  // 2026-09-20 老板「为什么是结果出来 所有追加才显示」: job 里原来**没有 steps 字段**,
  //   轮询只存了 events, 渲染却读 (job as any).steps —— 恒为 undefined →
  //   过程区全程空白, 一直等到 done 那一刻才从 msgs 里一次性冒出来。加上 steps 就实时了。
  const [job, setJob] = React.useState<{ status: string; stream: string; think: string; round: number; events: ToolEvent[]; steps: Step[]; elapsed: number; ask?: { q: string; opts: string[]; multi: boolean } | null; sub?: any[]; tokens?: number } | null>(null)
  // 2026-09-21 老板「显示token消耗量」: 跑的时候显示实时累计, 跑完把数字留下来(否则一 setJob(null) 就没了)。
  const [lastTok, setLastTok] = React.useState<{ total: number; p: number; c: number } | null>(null)
  const [planOpen, setPlanOpen] = React.useState(false)   // 底部任务清单: 默认收起, 点一下展开
  const [text, setText] = React.useState('')
  const [busy, setBusy] = React.useState(false)
  const [atts, setAtts] = React.useState<{ name: string; size: number; path: string }[]>([])
  const [uploading, setUploading] = React.useState(false)
  async function onPickFiles(e: React.ChangeEvent<HTMLInputElement>) {
    const fs = Array.from(e.target.files || [])
    e.target.value = ''
    if (!fs.length) return
    setUploading(true)
    for (const f of fs) {
      try {
        const r = await api.upload(f)
        setAtts((a) => [...a, { name: r.name, size: r.size, path: r.path }])
        toast(`已上传 ${r.name}`)
      } catch (er: any) { toast('上传失败: ' + er.message) }
    }
    setUploading(false)
  }
  const [showThink, setShowThink] = React.useState(false)
  const [curJob, setCurJob] = React.useState<string>('')   // 当前任务 id(回答"选择题"要用)
  const curJobRef = React.useRef<string>('')
  const busyRef = React.useRef(false)
  async function answerAsk(ans: string) {
    try {
      await api.answer(curJobRef.current, ans)
      toast(ans ? `已选：${ans.slice(0, 20)}` : '交给大肥鱼自己定')
      setJob((j) => (j ? { ...j, ask: null, status: 'running' } : j))
      setTimeout(() => { if (curJobRef.current) pollJob() }, 600)
    } catch (e: any) { toast(e.message) }
  }
  async function pollJob() {
    try {
      const j = await api.poll(curJobRef.current)
      if (j.status === 'running' || (j.status as string) === 'asking') {
        setJob({ status: j.status, stream: j.stream || '', think: j.think || '', round: j.round || 1, events: j.events || [], steps: (j as any).steps || [], elapsed: j.elapsed || 0, ask: (j as any).ask || null, sub: (j as any).sub || [], tokens: j.tokens || 0 })
        setTimeout(pollJob, j.status === 'asking' ? 1200 : 700)
      } else {
        if (j.tokens) setLastTok({ total: j.tokens, p: j.tk_last?.p || 0, c: j.tk_last?.c || 0 })
        setJob(null); setBusy(false)
        setMsgs((m) => [...m, { me: false, text: j.answer || '(无输出)', events: j.events || [], steps: (j as any).steps || [], fresh: true }])
        loadSess()
      }
    } catch (e: any) { setJob(null); setBusy(false); setMsgs((m) => [...m, { me: false, text: '出错: ' + e.message, fresh: true }]) }
  }
  /** 2026-09-20 老板「我把页面关了 重新打开 怎么看不到他继续跑」根因:
   *  服务端 `/api/chat/active` 早就写好了(它自己的注释: "重新打开会自动接回正在跑的那一轮"),
   *  但前端 api.ts 从来没有 active 这个方法、views.tsx 也从来没调过 ——
   *  重开时 curJobRef 是空的 → 轮询根本不启动 → job 恒为 null,
   *  于是只看到"我发的那句话, 没有回复", 像卡死。现在把它接回来。 */
  const attachJob = React.useCallback(async (sid: string): Promise<boolean> => {
    try {
      const r = await api.active(sid)
      if (!r || !r.job) return false
      curJobRef.current = r.job; setCurJob(r.job)
      busyRef.current = true; setBusy(true); setShowThink(false)
      setJob({ status: r.status || 'running', stream: r.stream || '', think: r.think || '',
               round: r.round || 1, events: r.events || [], steps: r.steps || [],
               elapsed: r.elapsed || 0, ask: r.ask || null, sub: r.sub || [], tokens: r.tokens || 0 })
      pollJob()
      return true
    } catch { return false }
  }, [])
  const boxRef = React.useRef<HTMLDivElement>(null)
  const taRef = React.useRef<HTMLTextAreaElement>(null)   // 2026-09-21 点输入条空白处就聚焦(见 composer 的 onClick)
  const stickRef = React.useRef(true)          // 是否"贴着底部"(用户往上滑了就 false)
  const [atBottom, setAtBottom] = React.useState(true)

  const scroll = (force = false) => {
    const b = boxRef.current
    if (!b) return
    if (force || stickRef.current) b.scrollTop = b.scrollHeight
  }
  const onScroll = () => {
    const b = boxRef.current
    if (!b) return
    // 2026-09-18 修"往上滑突然跳到底": 只有本来就在底部附近才自动跟随; 用户翻旧消息时不打扰
    const _at = (b.scrollHeight - b.scrollTop - b.clientHeight) < 48
    stickRef.current = _at
    setAtBottom(_at)
  }

  const firstLoadRef = React.useRef(true)
  const loadSess = React.useCallback(async () => {
    try {
      const r = await api.sessions()
      const list = r.sessions || []
      setSessions(list)
      const cur = list.find((x) => x.cur)?.id || 'tg'
      setSess((now) => {
        if (firstLoadRef.current) {            // 首次打开: 回到"上次用的会话"(后端记的 cur)
          firstLoadRef.current = false
          return cur
        }
        return list.some((x) => x.id === now) ? now : cur
      })
    } catch { /* ignore */ }
  }, [])
  const loadHist = React.useCallback(async (sid: string) => {
    try {
      const r = await api.history(sid)
      // 正在跑的时候别用服务器历史覆盖本地(服务器要等这轮完才写入, 否则会出现"我说的话消失又出现")
      if (!busyRef.current) setMsgs((r.msgs || []) as Msg[])
    } catch (e: any) { toast('历史加载失败: ' + e.message) }
  }, [toast])
  React.useEffect(() => { busyRef.current = busy }, [busy])
  React.useEffect(() => { loadSess() }, [loadSess])
  // 打开/切会话: ① 先铺服务器历史(/api/chat 收到消息时就落库了, 所以"我刚发的那句"在里面)
  //   ② 再接回正在跑的那一轮 —— 重开页面也能看到过程播报实时往下追加
  React.useEffect(() => {
    let alive = true
    busyRef.current = false
    ;(async () => {
      await loadHist(sess)
      if (!alive) return
      const back = await attachJob(sess)
      if (!alive || back) return
      curJobRef.current = ''; setCurJob(''); setJob(null); setBusy(false)
    })()
    stickRef.current = true
  }, [sess])
  React.useEffect(() => { scroll() }, [msgs, job?.stream, job?.events, job?.steps, job?.round, S.todo?.items?.length, planOpen, atts.length])

  // 2026-09-23 老板「任务多了 下面弹出来的 就会在屏幕外面 然后突然又正常显示」:
  //   上面那个自动跟随只在 msgs/stream/events 变时触发 —— 但**高度也会被别的东西改掉**:
  //   计划清单突然冒出来(占了输入区的上沿)、轮次分组头插入、附件行变高、手机键盘顶起来……
  //   这些都不触发它, 于是刚追加的内容先落到屏幕外, 等下一次轮询(最快 1 秒后)才"啪"地拉回视野。
  //   现在用 ResizeObserver 同时盯**滚动容器**(容器被压矮 → 底部内容被挤出屏幕)和**内容容器**
  //   (内容变高 → 贴底位置变了), 只要还在"贴底"状态就同帧重新贴底, 用户看不到那一下跳动。
  React.useEffect(() => {
    const b = boxRef.current
    if (!b || typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(() => { if (stickRef.current) b.scrollTop = b.scrollHeight })
    try {
      ro.observe(b)
      if (b.firstElementChild) ro.observe(b.firstElementChild)
    } catch { /* ignore */ }
    return () => ro.disconnect()
  }, [])

  // 2026-09-30 老板「新信息出来弹在太底下了」: 上面那条 ResizeObserver 只盯"容器/第一个子元素"的尺寸 ——
  //   但**新内容追加在末尾**, 它变高时容器和首元素都没变, RO 不响 → 弹簧那 400ms 里没人重钉底部,
  //   新行就一路长到输入条下面去了, 等下一条数据才被拉回来。
  //   现在挂上 motion 的「动效帧钩子」: 任何一个弹簧在跑的每一帧都回调这里,
  //   只要还在贴底状态就把 scrollTop 钉死 —— 底边固定, 内容从底边长出来, 中间不露馅。
  React.useEffect(() => {
    setMotionFrameHook(() => {
      const b = boxRef.current
      if (b && stickRef.current) b.scrollTop = b.scrollHeight
    })
    return () => setMotionFrameHook(null)
  }, [])

  async function send() {
    // 附件拼进消息(带服务器绝对路径), 让 bot 能直接读/解析
    const _attTxt = atts.length
      ? atts.map((a) => `【网页上传文件】${a.name}（${fmt.size(a.size)}）服务器路径: ${a.path}`).join('\n')
      : ''
    const t = [text.trim(), _attTxt].filter(Boolean).join('\n')
    if (!t) return
    setText(''); setAtts([])
    const _sentAtts = atts
    // 2026-09-18 任务跑着时发话 = 插话(插进正在跑的那一轮), 不是新开一轮
    if (job && (job.status === 'running' || job.status === 'asking')) {
      try {
        await api.interject(curJobRef.current, t)
        setMsgs((m) => [...m, { me: true, text: t, inject: true, fresh: true }])
        toast('已插话，大肥鱼下一轮就看到')
        stickRef.current = true; scroll(true)
      } catch (e: any) { toast('插话失败: ' + e.message) }
      return
    }
    if (busy) return
    setMsgs((m) => [...m, { me: true, text: t, fresh: true }]); setBusy(true); setShowThink(false)
    stickRef.current = true; scroll(true)        // 自己发消息 → 一定跟到底部
    try {
      const r = await api.chat(t, sess, topic, _sentAtts)
      if (r.session && r.session !== sess) setSess(r.session)
      curJobRef.current = r.job; setCurJob(r.job)
      setJob({ status: 'running', stream: '', think: '', round: 1, events: [], steps: [], elapsed: 0, ask: null, sub: [] })
      pollJob()
    } catch (e: any) { setMsgs((m) => [...m, { me: false, text: '出错: ' + e.message, fresh: true }]); setBusy(false) }
  }

  async function stopRun() {
    if (!curJobRef.current) return
    if (!confirm('停止这一轮？正在跑的命令也会一起停。')) return
    try {
      const r = await api.stop(curJobRef.current)
      toast(r.killed ? '已停止（含正在跑的命令）' : '已停止')
    } catch (e: any) { toast(e.message) }
  }
  async function newChat() {
    try {
      const r = await api.chatNew()
      setSessions(r.sessions || []); setSess(r.session); setMsgs([]); setJob(null)
      toast('已新建会话（旧的都留着，可切回）')
    } catch (e: any) { toast('新建失败: ' + e.message) }
  }
  async function clearChat() {
    const isTg = sess === 'tg'
    const q = isTg ? '清空「Telegram 主聊天」的上下文？这会影响 Telegram 那边（等于 /clear）。' : '清空这个会话的内容？（会话本身还在）'
    if (!confirm(q)) return
    try { const r = await api.chatClear(sess); setMsgs([]); setSessions(r.sessions || []); toast(`已清空 ${r.cleared} 条`) }
    catch (e: any) { toast('清空失败: ' + e.message) }
  }
  async function delChat() {
    if (sess === 'tg') { toast('主聊天会话不能删'); return }
    if (!confirm('删掉这个会话？（连同里面的消息）')) return
    try { const r = await api.chatDel(sess); setSessions(r.sessions || []); setSess(r.session); setMsgs((r.msgs || []) as Msg[]); toast('已删除') }
    catch (e: any) { toast('删除失败: ' + e.message) }
  }
  /** 2026-09-21 老板「加一个回退功能网页端」: 删掉最后一轮(我说的那句话 + 它的回答),
   *  并把原话放回输入框 —— 改一个字重发, 不用重打。
   *  另一层用途: 模型这一轮推诿了(上下文里已经长出"我刚拒绝过"), 与其在污染的上下文里再哄它,
   *  不如把这轮直接抹掉重发。服务端 /api/chat/undo 对 TG 主聊天和网页会话都生效。 */
  async function undoLast() {
    if (busy || job) { toast('这一轮还在跑 —— 先点停止再回退'); return }
    if (!confirm('回退最后一轮？（删掉你说的那句话 + 它的回答，原话放回输入框）')) return
    try {
      const r = await api.undo(sess, 1)
      setMsgs((r.msgs || []) as Msg[])
      if (r.back) { setText(r.back); toast('已回退 · 原话已放回输入框') }
      else toast('没有可回退的内容')
    } catch (e: any) { toast('回退失败: ' + e.message) }
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* 2026-09-20 老板「手机切换不了对话」根因: 工具栏加了 overflow-x-auto ——
         按 CSS 规范它会把 overflow-y 也变成 auto, 于是 SessPicker 绝对定位的下拉列表被整个裁掉,
          点开等于没点。现在改成两行: 手机端会话选择器独占一行(全宽), 按钮在下面一行; 桌面端仍一行。 */}
      <div className="flex flex-col gap-1.5 pb-2 sm:flex-row sm:items-center sm:gap-2">
        <div className="min-w-0 sm:max-w-[34vw] sm:flex-1">
          <SessPicker value={sess} items={sessions} onPick={(v) => { setSess(v); setMsgs([]) }} />
        </div>
        <div className="flex items-center gap-1.5 whitespace-nowrap">
          <span className="min-w-1 flex-1" />
          {/* 2026-09-21 token 消耗量: 跑的时候跟着 job.tokens 长, 跑完留在 lastTok(否则 setJob(null) 就没了)
              2026-09-23 老板「token实时消耗没有吗 没有查询我的key余额的吗」→ 这里补齐三枚芯片:
                · ⚡ 本轮  = 正在跑的那次累计(poll 里每轮结束的 usage 累加, 秒级刷新)
                · 今日    = 今天这个账号一共烧了多少 token(S.daily_usage)
                · 余额    = DeepSeek key 余额(管理员可见, 60 秒缓存; 点一下立即重查) */}
          {(() => {
            const running = job?.tokens || 0
            const tot = running || lastTok?.total || 0
            const today = S.quota?.tokens || 0
            const bal = S.apikey?.text || ''
            const chips: any[] = []
            if (tot) {
              chips.push(
                <span key="job" className="inline-flex shrink-0 items-center gap-1 rounded-full border border-lineweak bg-muted/40 px-2 py-0.5 font-mono text-[11px] text-fg3"
                  title={`token 消耗：本轮累计 ${tot}${lastTok ? `（最后一次调用 输入 ${lastTok.p} / 输出 ${lastTok.c}）` : ''}`}>
                  <Zap size={11} className={cx('text-warn', running ? 'breathe' : '')} />{running ? '本轮 ' : ''}{fmt.tok(tot)}
                </span>,
              )
            }
            if (today) {
              chips.push(
                <span key="today" className="inline-flex shrink-0 items-center gap-1 rounded-full border border-lineweak px-2 py-0.5 font-mono text-[11px] text-fg4"
                  title={`今天(北京时间)全账号累计 ${today} token · ${S.quota?.today ?? 0} 条对话`}>
                  今日 {fmt.tok(today)}
                </span>,
              )
            }
            if (bal) {
              chips.push(
                <button key="bal" type="button" onClick={() => { void reload(true) }}
                  className="inline-flex shrink-0 items-center gap-1 rounded-full border border-lineweak px-2 py-0.5 font-mono text-[11px] text-fg3 tap"
                  title="DeepSeek API key 余额（点一下重新查询；60 秒缓存）—— 也可以在 TG 里发 /balance 看明细">
                  <CreditCard size={11} />{bal}
                </button>,
              )
            }
            if (!chips.length) return null
            return <>{chips}</>
          })()}
          <Btn size="sm" variant="ghost" className="shrink-0" onClick={undoLast} disabled={busy} title="回退最后一轮：删掉你说的那句话和它的回答，原话放回输入框"><Undo2 size={13} />回退</Btn>
          <Btn size="sm" variant="outline" className="shrink-0" onClick={newChat} title="新建会话"><Plus size={13} /><span className="hidden sm:inline">新会话</span></Btn>
          <Btn size="sm" variant="ghost" className="shrink-0" onClick={() => loadHist(sess)}><RefreshCw size={13} /></Btn>
          <Btn size="sm" variant="ghost" className="shrink-0" onClick={clearChat} title="清空这个会话的内容">清空</Btn>
          {sess !== 'tg' && <Btn size="sm" variant="ghost" className="shrink-0" onClick={delChat} title="删除这个会话">删</Btn>}
        </div>
      </div>
      <div className="relative min-h-0 flex-1">
        {!atBottom && (
          <button type="button" onClick={() => { stickRef.current = true; setAtBottom(true); scroll(true) }}
            className="absolute bottom-2 left-1/2 z-10 -translate-x-1/2 rounded-full border border-line bg-card px-3 py-1 text-[12px] text-fg2 shadow-md tap">
            ↓ 回到底部
          </button>
        )}
        <div ref={boxRef} onScroll={onScroll} className="chatscroll h-full min-h-0 overflow-y-auto pr-1">
        {/* 2026-09-21 老板「任务清单可以显示在底部 点一下展开 可以吧」:
            原来这块"计划 · x/y"钉在消息区**顶部** —— 一屏里它占着最值钱的位置, 而且每轮都在,
            你往上翻历史时它也跟着滚。现在挪到输入框上方, 折叠成一条(进度条 + 正在做的那条), 点开才铺全文。 */}
        {msgs.map((m, i) => (
          /* 2026-09-30 老板「新信息出来弹在太底下了」根因: 这里挂的 anim-in 是 `translateY(8px)` 起步,
             在**贴底**的消息列表里, 起手那 8px 正好落在可视区外(输入条下面) —— 所以看着是"从最底下弹出来"。
             RikkaHub 对消息本体**不做位移**, 只用 Modifier.animateContentSize() 让高度按弹簧长高。
             现在换成 <SpringIn slide=0>: 高度 0→自然高度(弹簧) + 淡入, 贴底时就是"从底边长出来"。
             只有"刚追加进来"的(fresh)才播 —— 打开历史/切会话不播, 否则一进页面满屏乱动。 */
          <SpringIn key={i} className="mb-2.5" disabled={!m.fresh}>
          <div className={cx('flex gap-2', m.me && 'flex-row-reverse')}>
            <Av me={m.me} />
            <div className={cx('minw0', m.me ? 'max-w-[82%] rounded-[10px] border border-lineweak bg-soft px-2.5 py-1.5' : 'flex-1')}>
              {m.inject ? <div className="mb-0.5 text-[11px] text-accent">插话 · 已在下一轮并入</div> : null}
              {/* 2026-09-18 顺序: **过程在上, 结论在下**(跟 DSH 一样: 先看思考/工具, 最后才是答案) */}
              {!!m.steps?.length && <Steps steps={m.steps} events={m.events || []} />}
              {!m.steps?.length && !!m.events?.length && <ToolFold ev={m.events} />}
              <Bubble text={m.text} />
            </div>
          </div>
          </SpringIn>
        ))}
        {job && (job.status === 'running' || job.status === 'asking') && (
          <div className="mb-2.5 flex gap-2">
            <Av me={false} />
            <div className="minw0 flex-1">
              <div className="flex items-center gap-1.5 text-[11.5px] text-fg4">
                <span className="breathe-glow inline-flex items-center gap-1.5 rounded-full border border-lineweak bg-muted/40 px-2 py-0.5">
                  <span className="live-dot" />
                  <Spinner />
                  <span className="text-fg3">第 {job.round} 轮 · {fmt.sec(job.elapsed)}{job.tokens ? ` · ${fmt.tok(job.tokens)} tok` : ''}</span>
                </span>
                {job.think ? (
                  <button type="button" className="ml-1 inline-flex items-center gap-1 rounded-full border border-lineweak px-1.5 text-[11px] tap"
                    onClick={() => setShowThink(!showThink)}>
                    <M icon={showThink ? I.chevDown : I.chevRight} size={12} />{showThink ? '收起思考' : '看思考'}
                  </button>
                ) : null}
              </div>
              {showThink && job.think ? (
                <div className="mt-1 max-h-[200px] overflow-y-auto whitespace-pre-wrap break-any border-l-2 border-lineweak pl-2 text-[12px] text-fg3">
                  {job.think}
                </div>
              ) : null}
              {!!job.sub?.length && <SubPanel sub={job.sub} />}
              <Steps steps={(job as any).steps || []} events={job.events} live />
              {!((job as any).steps || []).length && <ToolFold ev={job.events} live />}
              {job.ask ? <AskCard q={job.ask.q} opts={job.ask.opts} multi={job.ask.multi} onPick={answerAsk} busy={false} /> : null}
              {/* 还没落定的那句话: 用打字机逐字打出来, 样式跟上面已落定的播报行一致 */}
              {job.stream ? (
                /* 正在流式追加的那句话: 文本每换一行高度都会跳一格 —— 套 <SpringGrow initial>
                   (= Compose 的 animateContentSize), 首现有弹簧、之后长高也走同一条弹簧, 不会一格一格地顿。 */
                <SpringGrow className="mt-1" initial>
                  <div className="glass-row glass-note anim-step flex items-start gap-1.5">
                    <span className="mt-[3px] shrink-0 text-accent"><Megaphone size={13} className="breathe" /></span>
                    <div className="minw0 flex-1"><Typewriter text={job.stream} cursor /></div>
                  </div>
                </SpringGrow>
              ) : null}
            </div>
          </div>
        )}
        {!msgs.length && !job && <Empty>这个会话还没有记录 —— 说句话就开始</Empty>}
        </div>
      </div>
      {/* 2026-09-21 老板「任务清单可以显示在底部 点一下展开 可以吧」:
          从消息区顶部挪到输入框上方 —— 折叠时一条(📋 进度 + 正在做的那条), 点一下铺开全文。
          折叠态也保留了"现在做到哪了", 所以不点开也不会瞎。 */}
      {(() => {
        const items = S.todo?.items || []
        if (!items.length) return null
        const done = items.filter((i) => i.state === 'done').length
        const doing = items.find((i) => i.state === 'doing')
        const pct = Math.round((done / items.length) * 100)
        return (
          <div className="mb-1.5">
            <button type="button" onClick={() => setPlanOpen(!planOpen)}
              className="glass-row flex w-full items-center gap-2 rounded-[10px] px-2.5 py-1.5 text-left tap"
              title={planOpen ? '收起任务清单' : '展开任务清单'}>
              <span className="shrink-0 text-fg3"><ListChecks size={13} /></span>
              <span className="shrink-0 font-mono text-[11.5px] tabular-nums text-fg2">{done}/{items.length}</span>
              <span className="relative h-[3px] min-w-[36px] flex-1 overflow-hidden rounded-full bg-lineweak">
                <span className="absolute inset-y-0 left-0 rounded-full bg-accent transition-[width] duration-700 ease-out"
                  style={{ width: pct + '%' }} />
              </span>
              <span className="minw0 max-w-[46%] truncate text-[11.5px] text-fg4">
                {doing ? (
                  <span className="inline-flex items-center gap-1">
                    <Loader2 size={11} className="animate-spin text-accent" />{doing.text}
                  </span>
                ) : (done === items.length ? <span className="inline-flex items-center gap-1 text-ok"><Check size={11} />全部完成</span> : '')}
              </span>
              <M icon={planOpen ? I.chevDown : I.chevRight} size={12} />
            </button>
            {/* 2026-09-23 老板「展开的动画不行」→ 原来这里是 `planOpen && …`: 展开有动画、**收起是瞬间消失**。
                改成常驻挂载 + .fold(grid-template-rows 0fr→1fr) —— 开和收都平滑, 时长 .5s 走同一套缓动。 */}
            <div className="fold" data-open={planOpen ? '1' : undefined}>
              <div className="fold-in">
                <div className="mt-1 max-h-[38vh] space-y-0.5 overflow-y-auto rounded-[10px] border border-lineweak bg-muted px-2.5 py-1.5">
                  {items.map((it, i) => (
                    <div key={i} className="flex items-start gap-1.5 text-[12.5px] leading-[1.5]"
                      style={{ ['--d' as any]: `${Math.min(i, 6) * 32}ms` }}>
                      <span className={cx('mt-[2px] shrink-0 inline-flex', it.state === 'done' ? 'text-ok' : it.state === 'doing' ? 'text-accent' : 'text-fg4')}>
                        {it.state === 'done' ? <Check size={12} /> : it.state === 'doing' ? <Loader2 size={12} className="animate-spin" /> : <Circle size={9} />}
                      </span>
                      <span className={cx('minw0 break-any', it.state === 'done' && 'text-fg3 line-through')}>{it.text}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )
      })()}
      <div className="pad-safe-b mt-2 border-t border-lineweak pt-2">
        {/* 2026-09-18 聊天里也能传文件: 选完先传上去, 再跟着消息一起发给大肥鱼(带服务器路径, 他直接能读) */}
        {!!atts.length && (
          <div className="mb-1.5 flex flex-wrap gap-1.5">
            {atts.map((a, i) => (
              <span key={i} className="anim-pop inline-flex items-center gap-1.5 rounded-full border border-line bg-muted px-2 py-0.5 text-[11.5px]">
                <Paperclip size={11} />
                <span className="max-w-[160px] truncate">{a.name}</span>
                <span className="font-mono text-fg4">{fmt.size(a.size)}</span>
                <button type="button" className="inline-flex items-center text-fg4 tap" onClick={() => setAtts((x) => x.filter((_, j) => j !== i))}><X size={11} /></button>
              </span>
            ))}
          </div>
        )}
        <div className="glass-bar flex items-end gap-2 p-1.5"
          onClick={(e) => {
            // 2026-09-21 老板「电脑版怎么输入不了」: 点空白处/点歪了也把光标送进输入框。
            // 只有当点到的不是按钮/链接/文件选择器时才抢焦点, 免得把「发送」「停止」的点击吃掉。
            const t = e.target as HTMLElement
            if (t.closest('button,label,input,a')) return
            taRef.current?.focus()
          }}>
          <label className={cx('flex h-[38px] w-[38px] shrink-0 cursor-pointer items-center justify-center rounded-[10px] border border-line text-fg2 tap hover:bg-muted', uploading && 'opacity-50')}
            title="上传文件给大肥鱼">
            {uploading ? <Spinner className="mr-0" /> : <Paperclip size={16} />}
            <input type="file" multiple className="hidden" disabled={uploading} onChange={onPickFiles} />
          </label>
          <textarea ref={taRef} value={text} onChange={(e) => setText(e.target.value)} rows={1}
            autoComplete="off" autoCorrect="off" autoCapitalize="off" spellCheck={false} enterKeyHint="send"
            onKeyDown={(e) => {
              // 2026-09-21 根因: 这里原来无条件 preventDefault + send()。
              //   中文输入法「拼音 → 按 Enter 选词上屏」那一下也是 Enter keydown,
              //   于是上屏被 preventDefault 吃掉、还顺手把半截拼音当消息发了 → 表现就是"打字上不去"。
              //   正在拼字(isComposing / keyCode 229)时一个键都不许拦。
              const ne = e.nativeEvent as any
              if (ne?.isComposing || (e as any).keyCode === 229) return
              if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() }
            }}
            placeholder={job ? '任务在跑 —— 发出去的会"插话"进去' : (sess === 'tg' ? '给大肥鱼发条消息…（这条和 Telegram 是同一个会话）' : '在这个会话里接着说…（不影响 Telegram）')}
            className="max-h-[140px] min-h-[38px] flex-1 resize-none rounded-[10px] border border-line bg-transparent px-3 py-2 text-[14px] text-fg outline-none placeholder:text-fg4 focus:border-accent/60 focus:ring-1 focus:ring-accent/25" />
          {job ? (
            <>
              <Btn variant="primary" onClick={send} disabled={!text.trim() && !atts.length} className="h-[38px] px-4"><Send size={14} />插话</Btn>
              <Btn variant="danger" onClick={stopRun} className="h-[38px] px-3" title="停止这一轮"><Square size={14} />停止</Btn>
            </>
          ) : (
            <Btn variant="primary" onClick={send} disabled={busy || (!text.trim() && !atts.length)} className="h-[38px] px-4"><Send size={14} />发送</Btn>
          )}
        </div>
      </div>
    </div>
  )
}

/* ---------------- 工作台 ---------------- */
export function Topics({ S, reload, toast }: Ctx) {
  const [tid, setTid] = React.useState('')
  const [name, setName] = React.useState('')
  return (
    <>
      <Card title="登记 / 改名">
        <div className="flex gap-2">
          <Input value={tid} onChange={(e) => setTid(e.target.value)} placeholder="话题号" inputMode="numeric" className="!w-[110px]" />
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="名字(随便起)" />
          <Btn variant="primary" onClick={async () => {
            const n = parseInt(tid, 10); if (!n) return toast('先填话题号')
            try { await api.saveTopic(n, name); toast('已登记'); setTid(''); setName(''); await reload(true) } catch (e: any) { toast(e.message) }
          }}>保存</Btn>
        </div>
        <div className="mt-2 text-[12px] text-fg3">bot 读不了聊天历史，名册靠"话题里来消息"自动补；这里可以手动补/改名</div>
      </Card>
      <Card title={`工作台 · ${S.topics.length}`}>
        {!S.topics.length && <Empty>名册还空着 —— 去哪个工作台说句话，它会自动出现在这里</Empty>}
        {S.topics.map((t) => (
          <div key={t.topic} className="flex items-center gap-3 border-b border-lineweak py-2 last:border-b-0">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5">{t.current && <Tag tone="ok">当前</Tag>}<b className="break-any">{t.name}</b></div>
              <div className="mt-0.5 font-mono text-[11.5px] text-fg3">话题 {t.topic} · 聊天 {t.chat}{t.last != null ? ` · ${fmt.sec(t.last)}前说过话` : ''}</div>
            </div>
            <Btn size="sm" onClick={async () => {
              const txt = prompt('往这个工作台发一句什么？'); if (!txt) return
              try { await api.sendTopic(t.chat, t.topic, txt); toast('已发进工作台') } catch (e: any) { toast(e.message) }
            }}><MessageSquare size={13} />发消息</Btn>
          </div>
        ))}
      </Card>
    </>
  )
}

/* ---------------- 值守 ---------------- */
export function Watch({ S, reload, toast }: Ctx) {
  if (!S.watch.length) return <Card title="值守"><Empty>没有值守任务（在 TG 里让 bot 建："盯着 xxx"）</Empty></Card>
  const op = async (wid: string, act: string) => {
    try { await api.watch(act, wid); toast('已' + ({ pause: '暂停', resume: '继续', run: '触发', del: '删除' } as any)[act]); await reload(true) } catch (e: any) { toast(e.message) }
  }
  return (
    <Card title={`值守 · ${S.watch.length}`}>
      {S.watch.map((w) => (
        <div key={w.id} className="flex items-start gap-3 border-b border-lineweak py-2.5 last:border-b-0">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-1.5">
              {w.enabled ? <Tag tone="ok">运行中</Tag> : <Tag>已暂停</Tag>}<b className="break-any">{w.name}</b>
            </div>
            <div className="mt-0.5 break-any font-mono text-[11.5px] text-fg3">{w.kind} · {w.target}</div>
            <div className="mt-0.5 text-[12px] text-fg3">跑过 {w.runs || 0} · 变化 {w.changes || 0} · 上次 {w.last_ts ? fmt.time(w.last_ts) : '从未'}</div>
          </div>
          <div className="flex shrink-0 flex-col gap-1.5">
            <Btn size="sm" onClick={() => op(w.id, w.enabled ? 'pause' : 'resume')}>{w.enabled ? <><Pause size={12} />暂停</> : <><Play size={12} />继续</>}</Btn>
            <Btn size="sm" variant="ghost" onClick={() => op(w.id, 'run')}>立即跑</Btn>
            <Btn size="sm" variant="danger" onClick={() => op(w.id, 'del')}><Trash size={12} />删除</Btn>
          </div>
        </div>
      ))}
    </Card>
  )
}

/* ---------------- 设置 ---------------- */
export function Settings({ S, reload, toast }: Ctx) {
  const MODES = [['auto', '自动切换（任务走 Pro，闲聊走 Flash）'], ['flash', '固定 Flash（DeepSeek-V4.1，快）'], ['pro', '固定 Pro（DeepSeek-V4-Pro，强）']]
  const THINKS = [['auto', '自动'], ['off', '关（最快）'], ['minimal', '极低'], ['low', '低'], ['medium', '中'], ['high', '高'], ['max', '最高（最慢）']]
  const SWS: [keyof State['switches'], string, string][] = [
    ['talk', '过程播报', '执行时把进度播报出来'], ['typewriter', '打字机呈现', '逐段浮现'],
    ['live', '流式输出', '⌛️ 画布 + 正文边收边打'], ['rich', '长正文走富文本', '超 3200 字整条发，上限 32768 不截断'],
    ['emoji', '自定义表情', '回复里带动画表情'], ['react', '表情回应', '先甩个表情再说话'],
    ['bubble', '分条发送', '长回复拆成几条'], ['delay', '偶尔慢回', '更像真人（心情差才生效）'],
  ]
  const setM = async (patch: any) => { try { await api.setModel(patch); toast('已切换'); await reload(true) } catch (e: any) { toast(e.message) } }
  const setS = async (n: string, v: boolean) => { try { await api.setSwitch(n, v); await reload(true) } catch (e: any) { toast(e.message) } }
  return (
    <>
      <Card title="模型">
        <div className="py-1">
          <div className="mb-1.5 text-[13px] text-fg3">模型档位</div>
          <Select value={S.model.mode || 'auto'} onChange={(v) => setM({ mode: v })}>
            {MODES.map(([v, n]) => <option key={v} value={v}>{n}</option>)}
          </Select>
        </div>
        <div className="py-1">
          <div className="mb-1.5 text-[13px] text-fg3">推理等级</div>
          <Select value={S.model.think || 'auto'} onChange={(v) => setM({ think: v })}>
            {THINKS.map(([v, n]) => <option key={v} value={v}>{n}</option>)}
          </Select>
        </div>
        <div className="mt-1 font-mono text-[11.5px] text-fg3">{S.model.light}{S.model.pro ? ' / ' + S.model.pro : ''}</div>
      </Card>
      <Card title="开关">
        {SWS.map(([k, n, d]) => (
          <div key={k} className="flex items-center gap-3 border-b border-lineweak py-2.5 last:border-b-0">
            <div className="min-w-0 flex-1">
              <div className="text-[14px]">{n}</div>
              <div className="text-[12px] text-fg3">{d}</div>
            </div>
            <Switch checked={!!S.switches[k]} onChange={(v) => setS(k, v)} />
          </div>
        ))}
      </Card>
    </>
  )
}

/* ---------------- 文件 ---------------- */
export function Files({ S, reload, toast }: Ctx) {
  const [up, setUp] = React.useState(false)
  const [busy, setBusy] = React.useState('')
  // 2026-09-20 老板「为啥有一大把文件」→ 能删: 单个删 + 一键清空
  const del = async (name?: string) => {
    const who = name ? `「${name}」` : `全部 ${S.files.length} 个文件`
    if (!window.confirm(`删掉${who}？删了就没了。`)) return
    setBusy(name || '*')
    try {
      const r = await api.fileDel(name)
      toast(name ? `已删除 ${name}` : `已清空 ${r.removed} 个`)
      await reload(true)
    } catch (e: any) { toast(e.message) } finally { setBusy('') }
  }
  return (
    <>
      <Card title="上传">
        <label className={cx('flex h-9 w-full cursor-pointer items-center justify-center gap-2 rounded-[8px] border border-dashed border-line text-[13px] text-fg2 hover:bg-muted', up && 'opacity-50')}>
          <Upload size={14} />{up ? '上传中…' : '选择文件上传'}
          <input type="file" className="hidden" disabled={up} onChange={async (e) => {
            const f = e.target.files?.[0]; if (!f) return
            setUp(true)
            try { const r = await api.upload(f); toast('已上传 ' + r.name); await reload(true) } catch (er: any) { toast(er.message) } finally { setUp(false) }
          }} />
        </label>
        <div className="mt-2 break-any font-mono text-[11.5px] text-fg3">/opt/deepseek-bot/miniapp_files/{S.uid}/</div>
        <div className="text-[12px] text-fg3">传上来后直接让 bot 处理（它读得到）</div>
      </Card>
      <Card title={`文件 · ${S.files.length}`}
        right={S.files.length ? <Btn size="sm" variant="danger" onClick={() => del()} disabled={busy === '*'}>清空</Btn> : undefined}>
        {!S.files.length && <Empty>还没有文件</Empty>}
        {S.files.map((f) => (
          <div key={f.name} className="flex items-center gap-3 border-b border-lineweak py-2 last:border-b-0">
            <div className="min-w-0 flex-1">
              <div className="break-any font-mono text-[12.5px]">{f.name}</div>
              <div className="text-[12px] text-fg3">{fmt.size(f.size)} · {fmt.time(f.mtime)}</div>
            </div>
            <a href={api.fileUrl(f.name)} download={f.name}><Btn size="sm"><Download size={13} />下载</Btn></a>
            <Btn size="sm" variant="danger" onClick={() => del(f.name)} disabled={busy === f.name}>删除</Btn>
          </div>
        ))}
      </Card>
    </>
  )
}

/* ---------------- 账单 ---------------- */
export function Billing({ S }: Ctx) {
  const q = S.quota || {}
  return (
    <>
      <Card title="余额">
        <Row k="剩余额度" v={`${q.balance ?? '-'} 次`} />
        <Row k="今日已用" v={`${q.today ?? 0} 条`} />
        <Row k="今日 tokens" v={String(q.tokens ?? 0)} />
        <div className="pt-2 text-[12px] text-fg3">按天重置 · 5U=175次 · 10U=360次 · 20U=750次（永久叠加）</div>
      </Card>
      <Card title="最近付款 · 72h">
        {q.last_pay ? <div className="break-any font-mono text-[12px]">{JSON.stringify(q.last_pay)}</div> : <Empty>最近没有付款记录</Empty>}
      </Card>
    </>
  )
}

export const ICONS = { Overview: Terminal, Tasks: Settings2, Chat: MessageSquare, Topics: Folder, Watch: Eye, Settings: Settings2, Files: Folder, Billing: CreditCard }
export type { Topic }
