import type { ReactNode } from 'react'

interface StatsCardProps {
  title: string
  value: string
  trend: string
  trendUp: boolean
  icon: ReactNode
  accent: 'accent' | 'critical' | 'high' | 'medium' | 'low'
}

const ACCENT_STYLES = {
  accent: 'text-accent bg-accent/10 border-accent/30',
  critical: 'text-critical bg-critical/10 border-critical/30',
  high: 'text-high bg-high/10 border-high/30',
  medium: 'text-medium bg-medium/10 border-medium/30',
  low: 'text-low bg-low/10 border-low/30',
}

const VALUE_STYLES = {
  accent: 'text-white',
  critical: 'text-critical',
  high: 'text-high',
  medium: 'text-medium',
  low: 'text-low',
}

export function StatsCard({ title, value, trend, trendUp, icon, accent }: StatsCardProps) {
  return (
    <div className="bg-surface border border-border rounded-xl p-5 space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-slate-400 text-sm">{title}</p>
        <div className={`w-9 h-9 rounded-lg border flex items-center justify-center ${ACCENT_STYLES[accent]}`}>
          {icon}
        </div>
      </div>
      <p className={`text-3xl font-bold tracking-tight ${VALUE_STYLES[accent]}`}>{value}</p>
      <p className={`text-xs ${trendUp ? 'text-high' : 'text-slate-400'}`}>{trend}</p>
    </div>
  )
}
