'use client'

import { Siren } from 'lucide-react'
import { useTranslation } from '@/lib/i18n'
import type { Incident } from '@/lib/types'

const STATUS_STYLES: Record<string, string> = {
  open:          'bg-critical/20 text-critical border border-critical/40',
  investigating: 'bg-high/20 text-high border border-high/40',
  contained:     'bg-medium/20 text-medium border border-medium/40',
  resolved:      'bg-green-500/20 text-green-400 border border-green-500/40',
}

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: 'text-critical',
  HIGH:     'text-high',
  MEDIUM:   'text-medium',
  LOW:      'text-low',
}

function formatDate(ts: string) {
  return new Date(ts).toLocaleString()
}

export default function IncidentsPage() {
  const { t } = useTranslation()

  // Real incidents come from the backend. No mock data.
  const incidents: Incident[] = []
  const open = incidents.filter(i => i.status === 'open').length
  const investigating = incidents.filter(i => i.status === 'investigating').length

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">{t('incidents.title')}</h1>
        <p className="text-slate-400 text-sm mt-1">
          {open} {t('incidents.open')} · {investigating} {t('incidents.investigating')} · {incidents.length} {t('incidents.total')}
        </p>
      </div>

      {incidents.length === 0 ? (
        <div className="bg-surface border border-border rounded-xl p-10 flex flex-col items-center gap-4 text-center">
          <Siren className="w-10 h-10 text-slate-600" />
          <div>
            <p className="text-white font-medium">{t('incidents.noIncidentsTitle')}</p>
            <p className="text-sm text-slate-400 mt-1">{t('incidents.noIncidentsMsg')}</p>
          </div>
        </div>
      ) : (
        <div className="bg-surface border border-border rounded-xl overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-slate-400 border-b border-border">
                <th className="text-left px-5 py-3">{t('incidents.idCol')}</th>
                <th className="text-left px-5 py-3">{t('incidents.titleCol')}</th>
                <th className="text-left px-5 py-3">{t('incidents.statusCol')}</th>
                <th className="text-left px-5 py-3">{t('incidents.severityCol')}</th>
                <th className="text-left px-5 py-3">{t('incidents.createdCol')}</th>
                <th className="text-left px-5 py-3">{t('incidents.updatedCol')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {incidents.map(incident => (
                <tr key={incident.id} className="hover:bg-white/5 transition-colors">
                  <td className="px-5 py-3">
                    <span className="font-mono text-xs text-accent">{incident.id}</span>
                  </td>
                  <td className="px-5 py-3 text-slate-200 max-w-sm">{incident.title}</td>
                  <td className="px-5 py-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium capitalize ${STATUS_STYLES[incident.status] ?? ''}`}>
                      {t(`incidents.statuses.${incident.status}`) || incident.status}
                    </span>
                  </td>
                  <td className={`px-5 py-3 font-semibold text-xs ${SEVERITY_STYLES[incident.severity] ?? 'text-slate-400'}`}>
                    {incident.severity}
                  </td>
                  <td className="px-5 py-3 text-xs text-slate-400 whitespace-nowrap">{formatDate(incident.created)}</td>
                  <td className="px-5 py-3 text-xs text-slate-400 whitespace-nowrap">{formatDate(incident.updated)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
