'use client'

import { useState, useEffect } from 'react'
import { Search, Bot, Loader2 } from 'lucide-react'
import { getAgents } from '@/lib/api'
import { useTranslation } from '@/lib/i18n'
import type { AgentInfo } from '@/lib/types'

const CATEGORIES = ['all', 'monitoring', 'threats', 'cloud', 'containers', 'intelligence', 'incident_response', 'compliance', 'specialized']

const STATUS_STYLES: Record<string, string> = {
  running: 'bg-green-500/10 text-green-400 border border-green-500/30',
  idle:    'bg-slate-500/10 text-slate-400 border border-slate-500/30',
  error:   'bg-red-500/10 text-red-400 border border-red-500/30',
}

const PRIORITY_STYLES: Record<string, string> = {
  CRITICAL: 'text-red-400',
  HIGH:     'text-orange-400',
  MEDIUM:   'text-yellow-400',
  LOW:      'text-green-400',
}

export default function AgentsPage() {
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('all')
  const [agents, setAgents] = useState<AgentInfo[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getAgents()
      .then(data => {
        const list = (data as { agents?: AgentInfo[] }).agents ?? []
        setAgents(list)
      })
      .catch(() => setAgents([]))
      .finally(() => setLoading(false))
  }, [])

  const filtered = agents.filter(a => {
    const q = search.toLowerCase()
    const matchSearch = !q || (a.name ?? '').toLowerCase().includes(q) || (a.description ?? '').toLowerCase().includes(q)
    const matchCat = category === 'all' || a.category === category
    return matchSearch && matchCat
  })

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">{t('agents.title')}</h1>
        <p className="text-slate-400 text-sm mt-1">
          {agents.length} {t('agents.deployed')} · {agents.filter(a => a.status === 'running').length} {t('agents.active')}
        </p>
      </div>

      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder={t('agents.searchPlaceholder')}
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full bg-surface border border-border rounded-lg pl-10 pr-4 py-2.5 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-accent transition-colors"
          />
        </div>
        <div className="flex flex-wrap gap-2">
          {CATEGORIES.map(cat => (
            <button
              key={cat}
              onClick={() => setCategory(cat)}
              className={`px-3 py-2 rounded-lg text-xs font-medium transition-colors capitalize ${
                category === cat
                  ? 'bg-accent/20 text-accent border border-accent/40'
                  : 'bg-surface border border-border text-slate-400 hover:border-accent/40 hover:text-accent'
              }`}
            >
              {t(`agents.categories.${cat}`) || cat.replace('_', ' ')}
            </button>
          ))}
        </div>
      </div>

      {loading && (
        <div className="flex items-center justify-center py-16 gap-3 text-slate-400">
          <Loader2 className="w-5 h-5 animate-spin" />
          <span className="text-sm">{t('common.loading')}</span>
        </div>
      )}

      {!loading && agents.length === 0 && (
        <div className="bg-surface border border-border rounded-xl p-10 flex flex-col items-center gap-4 text-center">
          <Bot className="w-10 h-10 text-slate-600" />
          <div>
            <p className="text-white font-medium">{t('agents.noAgentsTitle')}</p>
            <p className="text-sm text-slate-400 mt-1">{t('agents.noAgentsMsg')}</p>
          </div>
        </div>
      )}

      {!loading && agents.length > 0 && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {filtered.map(agent => (
              <div key={agent.name} className="bg-surface border border-border rounded-xl p-4 space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <p className="text-sm font-semibold text-white font-mono">{agent.name}</p>
                  <span className={`shrink-0 px-2 py-0.5 rounded text-xs font-medium ${STATUS_STYLES[agent.status] ?? STATUS_STYLES.idle}`}>
                    {t(`agents.status.${agent.status}`) || agent.status}
                  </span>
                </div>
                {agent.description && (
                  <p className="text-xs text-slate-400">{agent.description}</p>
                )}
                <div className="flex items-center justify-between pt-1">
                  <span className="text-xs text-slate-500 capitalize">{agent.category?.replace('_', ' ')}</span>
                  {agent.priority && (
                    <span className={`text-xs font-semibold ${PRIORITY_STYLES[agent.priority] ?? 'text-slate-400'}`}>
                      {t(`agents.priority.${agent.priority}`) || agent.priority}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
          {filtered.length === 0 && (
            <div className="text-center py-12 text-slate-500 text-sm">{t('agents.noResults')}</div>
          )}
        </>
      )}
    </div>
  )
}
