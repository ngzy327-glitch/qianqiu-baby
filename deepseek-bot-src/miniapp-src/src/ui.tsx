/** UI 组合层: 控件**直接用 DSH 自己的组件**(src/dsh/*, MIT vendored), 这里只做:
 *  · 把它们的 API 收成我页面好用的形状(Btn/Tag tone 映射等)
 *  · 用 --dsw-* token 拼出卡片/行/空态这些布局件
 */
import * as React from 'react'
import { Button } from './dsh/Button'
import { Switch as DshSwitch } from './dsh/Switch'
import { Input as DshInput } from './dsh/Input'
import { Tag as DshTag, type TagTone } from './dsh/Tag'
import { Pill } from './dsh/Pill'

export const cx = (...a: (string | false | null | undefined)[]) => a.filter(Boolean).join(' ')
export { Pill }

export function Card({ title, children, right, className }: { title?: string; children: React.ReactNode; right?: React.ReactNode; className?: string }) {
  return (
    <section className={cx('mb-2.5 rounded-[12px] border border-lineweak bg-card', className)}>
      {title && (
        <header className="flex items-center gap-2 px-3 pb-0 pt-2.5">
          <h3 className="text-[11.5px] font-semibold tracking-[.02em] text-fg4">{title}</h3>
          <span className="flex-1" />
          {right}
        </header>
      )}
      <div className="px-3 py-1.5">{children}</div>
    </section>
  )
}

/** 两列小统计块(概览用; 比一行一个键值紧凑得多) */
export function Stats({ items }: { items: [string, React.ReactNode, string?][] }) {
  return (
    <div className="grid grid-cols-2 gap-2">
      {items.map(([k, v, sub], i) => (
        <div key={i} className="rounded-[10px] border border-lineweak bg-muted px-2.5 py-2">
          <div className="text-[11.5px] text-fg4">{k}</div>
          <div className="mt-0.5 break-any text-[15px] font-semibold">{v}</div>
          {sub ? <div className="break-any text-[11px] text-fg3">{sub}</div> : null}
        </div>
      ))}
    </div>
  )
}

export function Row({ k, v, sub, right, mono }: { k?: React.ReactNode; v?: React.ReactNode; sub?: React.ReactNode; right?: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex min-w-0 items-center gap-3 border-b border-lineweak py-1.5 last:border-b-0">
      {k !== undefined && <div className="shrink-0 text-[12.5px] text-fg3">{k}</div>}
      <div className="minw0 flex-1">
        {v !== undefined && <div className={cx('break-any text-right text-[13.5px] font-medium', mono && 'font-mono text-[12px]')}>{v}</div>}
        {sub !== undefined && <div className="mt-0.5 break-any text-right text-[11.5px] leading-snug text-fg3">{sub}</div>}
      </div>
      {right}
    </div>
  )
}

/** DSH Button 只有 primary/ghost/outline/toolbar; danger 用 outline + 红字 */
export function Btn({ variant = 'outline', size = 'md', className, ...rest }:
  Omit<React.ComponentProps<typeof Button>, 'variant'> & { variant?: 'primary' | 'ghost' | 'outline' | 'toolbar' | 'danger' }) {
  if (variant === 'danger') {
    return <Button size={size} variant="outline" className={cx('text-err', className)} {...rest} />
  }
  return <Button size={size} variant={variant} className={className} {...rest} />
}

export function Tag({ children, tone }: { children: React.ReactNode; tone?: 'ok' | 'warn' | 'err' | TagTone }) {
  const map: Record<string, TagTone> = { ok: 'success', warn: 'warning', err: 'danger' }
  return <DshTag tone={(map[tone as string] || (tone as TagTone) || 'outline')}>{children}</DshTag>
}

export function Switch({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label?: string }) {
  return <DshSwitch checked={checked} onChange={onChange} label={label || '开关'} />
}

export function Input({ className, ...rest }: React.InputHTMLAttributes<HTMLInputElement>) {
  return <DshInput className={className} {...rest} />
}

export function Select({ value, onChange, children, className }: { value: string; onChange: (v: string) => void; children: React.ReactNode; className?: string }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)}
      className={cx('h-9 w-full rounded-[10px] border border-line bg-muted px-2.5 text-[13px] text-fg outline-none', className)}>
      {children}
    </select>
  )
}

export function Spinner({ className }: { className?: string }) {
  return <span className={cx('inline-block h-3 w-3 animate-spin rounded-full border-2 border-line border-t-accent align-[-2px]', className)} />
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <div className="py-4 text-center text-[13px] text-fg3">{children}</div>
}
