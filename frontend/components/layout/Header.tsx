'use client'

import { useEffect, useState, useRef } from 'react'
import { Wifi, Globe, ChevronDown } from 'lucide-react'
import { getConfig } from '@/lib/api'
import { useTranslation, SUPPORTED_LANGUAGES, type LangCode } from '@/lib/i18n'

export function Header() {
  const [provider, setProvider] = useState<string>('...')
  const [showLangMenu, setShowLangMenu] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)
  const { t, lang, setLang } = useTranslation()

  useEffect(() => {
    getConfig()
      .then(cfg => setProvider(cfg.provider))
      .catch(() => setProvider('offline'))
  }, [])

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setShowLangMenu(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

  const currentLang = SUPPORTED_LANGUAGES.find(l => l.code === lang)

  return (
    <header className="h-14 bg-sidebar border-b border-border flex items-center justify-between px-6 shrink-0">
      <div className="flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
        <span className="text-sm text-slate-400">{t('header.systemOperational')}</span>
      </div>

      <div className="flex items-center gap-3">
        {/* Language selector */}
        <div className="relative" ref={menuRef}>
          <button
            onClick={() => setShowLangMenu(v => !v)}
            className="flex items-center gap-1.5 bg-surface border border-border rounded-lg px-2.5 py-1.5 hover:border-accent/40 transition-colors"
            title={t('header.selectLanguage')}
          >
            <Globe className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-xs text-slate-300">{currentLang?.flag} {currentLang?.code.toUpperCase()}</span>
            <ChevronDown className="w-3 h-3 text-slate-500" />
          </button>

          {showLangMenu && (
            <div className="absolute right-0 top-full mt-1 w-44 bg-surface border border-border rounded-xl shadow-2xl z-50 overflow-hidden">
              <div className="px-3 py-2 border-b border-border">
                <p className="text-xs text-slate-500 font-medium">{t('header.selectLanguage')}</p>
              </div>
              <div className="py-1 max-h-72 overflow-y-auto">
                {SUPPORTED_LANGUAGES.map(l => (
                  <button
                    key={l.code}
                    onClick={() => { setLang(l.code as LangCode); setShowLangMenu(false) }}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 text-sm transition-colors hover:bg-white/5 ${
                      lang === l.code ? 'text-accent' : 'text-slate-300'
                    }`}
                  >
                    <span>{l.flag}</span>
                    <span className="flex-1 text-left">{l.nativeName}</span>
                    {lang === l.code && <span className="w-1.5 h-1.5 rounded-full bg-accent" />}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Provider badge */}
        <div className="flex items-center gap-2 bg-surface border border-border rounded-lg px-3 py-1.5">
          <Wifi className="w-3.5 h-3.5 text-accent" />
          <span className="text-xs text-slate-300 font-mono">{provider.toUpperCase()}</span>
        </div>

        {/* Live indicator */}
        <div className="flex items-center gap-2 bg-green-500/10 border border-green-500/30 rounded-lg px-3 py-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
          <span className="text-xs text-green-400 font-medium">{t('header.live')}</span>
        </div>
      </div>
    </header>
  )
}
