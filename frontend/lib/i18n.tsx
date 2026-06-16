'use client'

import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { getTranslations, SUPPORTED_LANGUAGES, type LangCode } from '@/locales'
import type { TranslationSchema } from '@/locales/es'

const DEFAULT_LANG: LangCode = 'es'
const LS_KEY = 'aisoc_lang'

interface I18nContextType {
  lang: LangCode
  setLang: (lang: LangCode) => void
  t: (key: string) => string
  dir: string
}

const I18nContext = createContext<I18nContextType | null>(null)

function resolveDotPath(obj: Record<string, unknown>, path: string): string {
  const val = path.split('.').reduce<unknown>((cur, key) => {
    if (cur && typeof cur === 'object') return (cur as Record<string, unknown>)[key]
    return undefined
  }, obj)
  return typeof val === 'string' ? val : path
}

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<LangCode>(DEFAULT_LANG)

  useEffect(() => {
    const saved = localStorage.getItem(LS_KEY) as LangCode | null
    if (saved && SUPPORTED_LANGUAGES.some(l => l.code === saved)) {
      setLangState(saved)
    }
  }, [])

  const setLang = (newLang: LangCode) => {
    setLangState(newLang)
    localStorage.setItem(LS_KEY, newLang)
    const info = SUPPORTED_LANGUAGES.find(l => l.code === newLang)
    document.documentElement.lang = newLang
    document.documentElement.dir = info?.dir ?? 'ltr'
  }

  const translations = getTranslations(lang)
  const t = (key: string) => resolveDotPath(translations as unknown as Record<string, unknown>, key)
  const dir = SUPPORTED_LANGUAGES.find(l => l.code === lang)?.dir ?? 'ltr'

  return (
    <I18nContext.Provider value={{ lang, setLang, t, dir }}>
      {children}
    </I18nContext.Provider>
  )
}

export function useTranslation() {
  const ctx = useContext(I18nContext)
  if (!ctx) throw new Error('useTranslation must be used inside LanguageProvider')
  return ctx
}

export { SUPPORTED_LANGUAGES, type LangCode, type TranslationSchema }
