import type { Severity } from '@/lib/types'

const STYLES: Record<string, string> = {
  CRITICAL: 'bg-critical/20 text-critical border border-critical/40',
  HIGH: 'bg-high/20 text-high border border-high/40',
  MEDIUM: 'bg-medium/20 text-medium border border-medium/40',
  LOW: 'bg-low/20 text-low border border-low/40',
  INFO: 'bg-slate-500/20 text-slate-400 border border-slate-500/40',
}

interface SeverityBadgeProps {
  severity: Severity | string
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  const key = (severity ?? '').toString().toUpperCase()
  const style = STYLES[key] ?? STYLES.INFO
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold tracking-wide ${style}`}>
      {key}
    </span>
  )
}
