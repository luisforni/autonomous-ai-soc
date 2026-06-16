const STYLES: Record<string, string> = {
  running: 'bg-green-500/20 text-green-400 border border-green-500/40',
  idle: 'bg-slate-500/20 text-slate-400 border border-slate-500/40',
  error: 'bg-critical/20 text-critical border border-critical/40',
}

const DOTS: Record<string, string> = {
  running: 'bg-green-400 animate-pulse',
  idle: 'bg-slate-400',
  error: 'bg-critical animate-pulse',
}

interface StatusBadgeProps {
  status: 'running' | 'idle' | 'error'
}

export function StatusBadge({ status }: StatusBadgeProps) {
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${STYLES[status]}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${DOTS[status]}`} />
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  )
}
