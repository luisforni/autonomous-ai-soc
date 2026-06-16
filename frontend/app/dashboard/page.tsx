'use client'

import { ShieldAlert, AlertTriangle, Bot, Activity, FlaskConical } from 'lucide-react'
import Link from 'next/link'
import { useTranslation } from '@/lib/i18n'

export default function DashboardPage() {
  const { t } = useTranslation()

  const stats = [
    { titleKey: 'dashboard.totalAlerts',    value: '—', icon: <ShieldAlert className="w-5 h-5" />, accent: 'accent' },
    { titleKey: 'dashboard.criticalAlerts', value: '—', icon: <AlertTriangle className="w-5 h-5" />, accent: 'critical' },
    { titleKey: 'dashboard.activeAgents',   value: '126', icon: <Bot className="w-5 h-5" />, accent: 'accent', sub: t('dashboard.agentsDeployed') },
    { titleKey: 'dashboard.riskScore',      value: '—', icon: <Activity className="w-5 h-5" />, accent: 'high' },
  ]

  const accentClass: Record<string, string> = {
    accent:   'text-accent bg-accent/10 border-accent/30',
    critical: 'text-critical bg-critical/10 border-critical/30',
    high:     'text-high bg-high/10 border-high/30',
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">{t('dashboard.title')}</h1>
        <p className="text-slate-400 text-sm mt-1">{t('dashboard.subtitle')}</p>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {stats.map(({ titleKey, value, icon, accent, sub }) => (
          <div key={titleKey} className="bg-surface border border-border rounded-xl p-5">
            <div className="flex items-center justify-between mb-3">
              <p className="text-slate-400 text-sm">{t(titleKey)}</p>
              <div className={`w-9 h-9 rounded-lg border flex items-center justify-center ${accentClass[accent]}`}>
                {icon}
              </div>
            </div>
            <p className="text-3xl font-bold text-white">{value}</p>
            {sub && <p className="text-xs text-slate-500 mt-1">{sub}</p>}
          </div>
        ))}
      </div>

      {/* Empty state */}
      <div className="bg-surface border border-border rounded-xl p-10 flex flex-col items-center justify-center text-center gap-4">
        <div className="w-16 h-16 rounded-full bg-accent/10 border border-accent/20 flex items-center justify-center">
          <FlaskConical className="w-7 h-7 text-accent" />
        </div>
        <div>
          <h2 className="text-lg font-semibold text-white">{t('dashboard.noDataTitle')}</h2>
          <p className="text-sm text-slate-400 mt-1 max-w-md">{t('dashboard.noDataMsg')}</p>
        </div>
        <Link
          href="/analyze"
          className="flex items-center gap-2 bg-accent text-background font-semibold px-5 py-2.5 rounded-lg hover:bg-accent/90 transition-colors text-sm"
        >
          <FlaskConical className="w-4 h-4" />
          {t('dashboard.startScan')}
        </Link>
      </div>
    </div>
  )
}
