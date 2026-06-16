'use client'

import { useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { useTranslation } from '@/lib/i18n'
import type { Alert, Severity } from '@/lib/types'

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

function formatTime(ts: string) {
  return new Date(ts).toLocaleString()
}

export default function AlertsPage() {
  const { t } = useTranslation()
  const [filter, setFilter] = useState<Severity | 'ALL'>('ALL')

  // Real alerts would come from a live feed or API. No mock data.
  const alerts: Alert[] = []
  const filtered = filter === 'ALL' ? alerts : alerts.filter(a => a.severity === filter)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">{t('alerts.title')}</h1>
        <p className="text-slate-400 text-sm mt-1">{filtered.length} {t('alerts.showing')}</p>
      </div>

      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => setFilter('ALL')}
          className={`px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
            filter === 'ALL' ? 'bg-accent/20 text-accent border border-accent/40' : 'bg-surface border border-border text-slate-400 hover:text-accent hover:border-accent/40'
          }`}
        >
          {t('common.all')}
        </button>
        {SEVERITIES.map(s => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
              filter === s ? 'bg-accent/20 text-accent border border-accent/40' : 'bg-surface border border-border text-slate-400 hover:text-accent hover:border-accent/40'
            }`}
          >
            {s}
          </button>
        ))}
      </div>

      {alerts.length === 0 ? (
        <div className="bg-surface border border-border rounded-xl p-10 flex flex-col items-center gap-4 text-center">
          <ShieldAlert className="w-10 h-10 text-slate-600" />
          <div>
            <p className="text-white font-medium">{t('alerts.noAlertsTitle')}</p>
            <p className="text-sm text-slate-400 mt-1">{t('alerts.noAlertsMsg')}</p>
          </div>
        </div>
      ) : (
        <div className="bg-surface border border-border rounded-xl overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-slate-400 border-b border-border">
                <th className="text-left px-5 py-3">{t('alerts.severityCol')}</th>
                <th className="text-left px-5 py-3">{t('alerts.titleCol')}</th>
                <th className="text-left px-5 py-3">{t('alerts.categoryCol')}</th>
                <th className="text-left px-5 py-3">{t('alerts.agentCol')}</th>
                <th className="text-left px-5 py-3">{t('alerts.confidenceCol')}</th>
                <th className="text-left px-5 py-3">{t('alerts.timeCol')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map(alert => (
                <tr key={alert.id} className="hover:bg-white/5 transition-colors">
                  <td className="px-5 py-3"><SeverityBadge severity={alert.severity} /></td>
                  <td className="px-5 py-3 text-slate-200 max-w-xs">{alert.title}</td>
                  <td className="px-5 py-3"><span className="text-xs font-mono text-slate-400">{alert.category}</span></td>
                  <td className="px-5 py-3"><span className="text-xs font-mono text-accent">{alert.agent}</span></td>
                  <td className="px-5 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-16 bg-border rounded-full h-1.5">
                        <div className="h-1.5 rounded-full bg-accent" style={{ width: `${alert.confidence * 100}%` }} />
                      </div>
                      <span className="text-xs text-slate-400">{(alert.confidence * 100).toFixed(0)}%</span>
                    </div>
                  </td>
                  <td className="px-5 py-3 text-xs text-slate-400 whitespace-nowrap">{formatTime(alert.timestamp)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
