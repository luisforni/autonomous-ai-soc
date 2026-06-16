'use client'

import { useState, useEffect } from 'react'
import { getHealth, getConfig, updateConfig } from '@/lib/api'
import { CheckCircle2, XCircle, Loader2, Save, Wifi } from 'lucide-react'
import { useTranslation } from '@/lib/i18n'

const PROVIDERS = [
  { name: 'openai',       type: 'cloud', model: 'gpt-4o',                                    needsKey: true  },
  { name: 'anthropic',    type: 'cloud', model: 'claude-opus-4-8',                           needsKey: true  },
  { name: 'google',       type: 'cloud', model: 'gemini-1.5-pro',                            needsKey: true  },
  { name: 'azure_openai', type: 'cloud', model: 'gpt-4o (Azure)',                            needsKey: true  },
  { name: 'groq',         type: 'cloud', model: 'llama-3.3-70b-versatile',                   needsKey: true  },
  { name: 'mistral',      type: 'cloud', model: 'mistral-large-latest',                      needsKey: true  },
  { name: 'cohere',       type: 'cloud', model: 'command-r-plus',                            needsKey: true  },
  { name: 'together',     type: 'cloud', model: 'meta-llama/Meta-Llama-3.1-70B',             needsKey: true  },
  { name: 'fireworks',    type: 'cloud', model: 'accounts/fireworks/models/llama-v3p1-70b',  needsKey: true  },
  { name: 'deepseek',     type: 'cloud', model: 'deepseek-chat',                             needsKey: true  },
  { name: 'huggingface',  type: 'cloud', model: 'meta-llama/Meta-Llama-3-70B',               needsKey: true  },
  { name: 'ollama',       type: 'local', model: 'llama3.2',                                  needsKey: false },
  { name: 'lm_studio',    type: 'local', model: 'local-model',                               needsKey: false },
  { name: 'llamacpp',     type: 'local', model: 'llama-3.2-3b',                              needsKey: false },
]

type HealthStatus = 'idle' | 'loading' | 'ok' | 'error'
type SaveStatus   = 'idle' | 'saving' | 'ok' | 'error'

export default function SettingsPage() {
  const { t } = useTranslation()
  const [currentProvider, setCurrentProvider] = useState<string>('...')
  const [currentModel, setCurrentModel]       = useState<string>('')
  const [health, setHealth]                   = useState<HealthStatus>('idle')
  const [healthData, setHealthData]           = useState<Record<string, unknown> | null>(null)

  // Form state
  const [selectedProvider, setSelectedProvider] = useState<string>('')
  const [apiKey, setApiKey]                     = useState<string>('')
  const [model, setModel]                       = useState<string>('')
  const [baseUrl, setBaseUrl]                   = useState<string>('')
  const [saveStatus, setSaveStatus]             = useState<SaveStatus>('idle')

  useEffect(() => {
    getConfig()
      .then(cfg => {
        setCurrentProvider(cfg.provider)
        setCurrentModel(cfg.model)
        setSelectedProvider(cfg.provider)
        const pInfo = PROVIDERS.find(p => p.name === cfg.provider)
        if (pInfo && !pInfo.needsKey) {
          setBaseUrl(cfg.model ? '' : '')
        }
        setModel(cfg.model ?? '')
      })
      .catch(() => setCurrentProvider('unknown'))
  }, [])

  async function checkHealth() {
    setHealth('loading')
    try {
      const data = await getHealth()
      setHealthData(data)
      setHealth('ok')
    } catch {
      setHealth('error')
    }
  }

  async function handleSave() {
    if (!selectedProvider) return
    setSaveStatus('saving')
    try {
      await updateConfig({ provider: selectedProvider, api_key: apiKey, model, base_url: baseUrl })
      setSaveStatus('ok')
      setCurrentProvider(selectedProvider)
      const pInfo = PROVIDERS.find(p => p.name === selectedProvider)
      setCurrentModel(model || pInfo?.model || '')
      setTimeout(() => setSaveStatus('idle'), 3000)
    } catch {
      setSaveStatus('error')
      setTimeout(() => setSaveStatus('idle'), 3000)
    }
  }

  const selectedInfo = PROVIDERS.find(p => p.name === selectedProvider)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">{t('settings.title')}</h1>
        <p className="text-slate-400 text-sm mt-1">{t('settings.subtitle')}</p>
      </div>

      {/* Current provider badge */}
      <div className="bg-surface border border-border rounded-xl p-5 flex flex-col sm:flex-row sm:items-center gap-4">
        <div className="flex-1">
          <p className="text-sm text-slate-400">{t('settings.currentProvider')}</p>
          <p className="text-xl font-bold text-white mt-1">{currentProvider.toUpperCase()}</p>
          {currentModel && <p className="text-xs text-slate-400 font-mono mt-0.5">{currentModel}</p>}
        </div>
        <span className="px-3 py-1.5 rounded-lg bg-accent/20 text-accent border border-accent/40 text-sm font-semibold self-start">
          {t('settings.activeLabel')}
        </span>
      </div>

      {/* Change provider form */}
      <div className="bg-surface border border-border rounded-xl p-5 space-y-5">
        <div>
          <h2 className="text-lg font-semibold text-white">{t('settings.changeProvider')}</h2>
          <p className="text-xs text-slate-400 mt-0.5">{t('settings.providerDesc')}</p>
        </div>

        {/* Provider selector grid */}
        <div>
          <p className="text-xs font-medium text-slate-400 mb-2">{t('settings.selectProvider')}</p>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
            {PROVIDERS.map(p => (
              <button
                key={p.name}
                onClick={() => { setSelectedProvider(p.name); setApiKey(''); setModel(''); setBaseUrl('') }}
                className={`flex flex-col items-start gap-1 px-3 py-2.5 rounded-lg border text-left transition-colors ${
                  selectedProvider === p.name
                    ? 'border-accent/60 bg-accent/10 text-accent'
                    : 'border-border bg-background text-slate-300 hover:border-accent/30 hover:text-accent'
                }`}
              >
                <span className="text-xs font-mono font-semibold">{p.name}</span>
                <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${
                  p.type === 'cloud' ? 'bg-accent/10 text-accent' : 'bg-green-500/10 text-green-400'
                }`}>
                  {t(`common.${p.type}`)}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Credentials */}
        {selectedProvider && (
          <div className="space-y-4 border-t border-border pt-4">
            {selectedInfo?.needsKey ? (
              <div>
                <label className="text-xs font-medium text-slate-400 block mb-1.5">{t('settings.apiKey')}</label>
                <input
                  type="password"
                  value={apiKey}
                  onChange={e => setApiKey(e.target.value)}
                  placeholder={t('settings.apiKeyPlaceholder')}
                  className="w-full bg-background border border-border rounded-lg px-4 py-2.5 text-sm text-white placeholder:text-slate-600 focus:outline-none focus:border-accent transition-colors"
                />
              </div>
            ) : (
              <div className="flex items-center gap-2 text-sm text-green-400 bg-green-500/5 border border-green-500/20 rounded-lg px-4 py-2.5">
                <Wifi className="w-4 h-4" />
                {t('settings.localNoKey')}
              </div>
            )}

            {!selectedInfo?.needsKey && (
              <div>
                <label className="text-xs font-medium text-slate-400 block mb-1.5">{t('settings.baseUrl')}</label>
                <input
                  type="text"
                  value={baseUrl}
                  onChange={e => setBaseUrl(e.target.value)}
                  placeholder={t('settings.baseUrlPlaceholder')}
                  className="w-full bg-background border border-border rounded-lg px-4 py-2.5 text-sm text-white placeholder:text-slate-600 focus:outline-none focus:border-accent transition-colors"
                />
              </div>
            )}

            <div>
              <label className="text-xs font-medium text-slate-400 block mb-1.5">{t('settings.modelLabel')}</label>
              <input
                type="text"
                value={model}
                onChange={e => setModel(e.target.value)}
                placeholder={selectedInfo?.model ?? t('settings.modelPlaceholder')}
                className="w-full bg-background border border-border rounded-lg px-4 py-2.5 text-sm text-white placeholder:text-slate-600 focus:outline-none focus:border-accent transition-colors"
              />
            </div>

            <button
              onClick={handleSave}
              disabled={saveStatus === 'saving'}
              className="flex items-center gap-2 bg-accent text-background font-semibold px-5 py-2.5 rounded-lg hover:bg-accent/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed text-sm"
            >
              {saveStatus === 'saving'
                ? <Loader2 className="w-4 h-4 animate-spin" />
                : <Save className="w-4 h-4" />}
              {saveStatus === 'saving' ? t('settings.saving') : t('settings.saveProvider')}
            </button>

            {saveStatus === 'ok' && (
              <div className="flex items-center gap-2 text-green-400 bg-green-500/10 border border-green-500/30 rounded-lg px-4 py-2.5 text-sm">
                <CheckCircle2 className="w-4 h-4" />
                {t('settings.saveSuccess')}
              </div>
            )}
            {saveStatus === 'error' && (
              <div className="flex items-center gap-2 text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-2.5 text-sm">
                <XCircle className="w-4 h-4" />
                {t('settings.saveError')}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Health check */}
      <div className="bg-surface border border-border rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white">{t('settings.healthCheck')}</h2>
            <p className="text-xs text-slate-400 mt-0.5">{t('settings.healthCheckDesc')}</p>
          </div>
          <button
            onClick={checkHealth}
            disabled={health === 'loading'}
            className="flex items-center gap-2 bg-accent/10 border border-accent/40 text-accent px-4 py-2 rounded-lg text-sm font-medium hover:bg-accent/20 transition-colors disabled:opacity-50"
          >
            {health === 'loading' && <Loader2 className="w-4 h-4 animate-spin" />}
            {t('settings.checkHealth')}
          </button>
        </div>
        {health === 'ok' && (
          <div className="flex items-start gap-3 bg-green-500/10 border border-green-500/30 rounded-lg p-4">
            <CheckCircle2 className="w-5 h-5 text-green-400 mt-0.5 shrink-0" />
            <div>
              <p className="text-green-400 font-medium text-sm">{t('settings.backendHealthy')}</p>
              {healthData && <pre className="text-xs text-slate-400 mt-2 overflow-auto">{JSON.stringify(healthData, null, 2)}</pre>}
            </div>
          </div>
        )}
        {health === 'error' && (
          <div className="flex items-center gap-3 bg-critical/10 border border-critical/30 rounded-lg p-4">
            <XCircle className="w-5 h-5 text-critical shrink-0" />
            <p className="text-critical text-sm">
              {t('settings.backendOffline')} {process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}.
            </p>
          </div>
        )}
      </div>

      {/* Providers reference table */}
      <div className="bg-surface border border-border rounded-xl overflow-x-auto">
        <div className="px-5 py-4 border-b border-border">
          <h2 className="text-lg font-semibold text-white">{t('settings.supportedProviders')}</h2>
          <p className="text-xs text-slate-400 mt-0.5">{PROVIDERS.length} {t('settings.providerCount')}</p>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-slate-400 border-b border-border">
              <th className="text-left px-5 py-3">{t('settings.providerCol')}</th>
              <th className="text-left px-5 py-3">{t('settings.typeCol')}</th>
              <th className="text-left px-5 py-3">{t('settings.modelCol')}</th>
              <th className="text-left px-5 py-3">{t('settings.statusCol')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {PROVIDERS.map(p => (
              <tr key={p.name} className={`hover:bg-white/5 transition-colors ${p.name === currentProvider ? 'bg-accent/5' : ''}`}>
                <td className="px-5 py-3">
                  <span className={`font-mono text-sm ${p.name === currentProvider ? 'text-accent font-semibold' : 'text-white'}`}>{p.name}</span>
                  {p.name === currentProvider && <span className="ml-2 text-xs text-accent">({t('settings.activeProvider')})</span>}
                </td>
                <td className="px-5 py-3">
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                    p.type === 'cloud' ? 'bg-accent/10 text-accent border border-accent/30' : 'bg-green-500/10 text-green-400 border border-green-500/30'
                  }`}>
                    {t(`common.${p.type}`)}
                  </span>
                </td>
                <td className="px-5 py-3 font-mono text-xs text-slate-400">{p.model}</td>
                <td className="px-5 py-3 text-xs text-slate-500">{t('settings.configuredViaEnv')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
