import type { TranslationSchema } from './es'
import es from './es'
import en from './en'

// Deep merge: fills missing keys from `base` (English) into `target`
function deepMerge(base: Record<string, unknown>, target: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = { ...base }
  for (const key in target) {
    if (
      target[key] !== null &&
      typeof target[key] === 'object' &&
      !Array.isArray(target[key]) &&
      typeof base[key] === 'object'
    ) {
      result[key] = deepMerge(base[key] as Record<string, unknown>, target[key] as Record<string, unknown>)
    } else if (target[key] !== undefined) {
      result[key] = target[key]
    }
  }
  return result
}

// Partial translations for other languages (key UI strings only, falls back to English)
const pt: Partial<TranslationSchema> = {
  nav: { dashboard: 'Painel', agents: 'Agentes', alerts: 'Alertas', incidents: 'Incidentes', scanTarget: 'Escanear Alvo', settings: 'Configurações', docs: 'Documentação' },
  header: { systemOperational: 'Sistema Operacional', live: 'AO VIVO', selectLanguage: 'Idioma' },
  sidebar: { subtitle: 'Centro de Operações de Segurança', version: 'v1.0.0' },
  dashboard: { ...en.dashboard, title: 'Painel de Segurança', subtitle: 'Monitoramento de ameaças em tempo real', noDataTitle: 'Sem dados disponíveis', noDataMsg: 'Execute uma análise em Escanear Alvo para gerar alertas.' },
  common: { ...en.common, save: 'Salvar', cancel: 'Cancelar', search: 'Buscar', loading: 'Carregando...' },
}

const fr: Partial<TranslationSchema> = {
  nav: { dashboard: 'Tableau de bord', agents: 'Agents', alerts: 'Alertes', incidents: 'Incidents', scanTarget: 'Scanner Cible', settings: 'Paramètres', docs: 'Documentation' },
  header: { systemOperational: 'Système Opérationnel', live: 'EN DIRECT', selectLanguage: 'Langue' },
  sidebar: { subtitle: 'Centre d\'Opérations de Sécurité', version: 'v1.0.0' },
  dashboard: { ...en.dashboard, title: 'Tableau de bord Sécurité', subtitle: 'Surveillance des menaces en temps réel', noDataTitle: 'Aucune donnée', noDataMsg: 'Lancez une analyse depuis Scanner Cible pour générer des alertes.' },
  common: { ...en.common, save: 'Enregistrer', cancel: 'Annuler', search: 'Rechercher', loading: 'Chargement...' },
}

const de: Partial<TranslationSchema> = {
  nav: { dashboard: 'Dashboard', agents: 'Agenten', alerts: 'Warnungen', incidents: 'Vorfälle', scanTarget: 'Ziel Scannen', settings: 'Einstellungen', docs: 'Dokumentation' },
  header: { systemOperational: 'System Betriebsbereit', live: 'LIVE', selectLanguage: 'Sprache' },
  sidebar: { subtitle: 'Sicherheitsbetriebszentrum', version: 'v1.0.0' },
  dashboard: { ...en.dashboard, title: 'Sicherheits-Dashboard', subtitle: 'Echtzeit-Bedrohungsüberwachung', noDataTitle: 'Keine Daten', noDataMsg: 'Führen Sie eine Analyse unter Ziel Scannen aus.' },
  common: { ...en.common, save: 'Speichern', cancel: 'Abbrechen', search: 'Suchen', loading: 'Laden...' },
}

const it: Partial<TranslationSchema> = {
  nav: { dashboard: 'Dashboard', agents: 'Agenti', alerts: 'Avvisi', incidents: 'Incidenti', scanTarget: 'Scansiona Obiettivo', settings: 'Impostazioni', docs: 'Documentazione' },
  header: { systemOperational: 'Sistema Operativo', live: 'IN DIRETTA', selectLanguage: 'Lingua' },
  sidebar: { subtitle: 'Centro Operazioni di Sicurezza', version: 'v1.0.0' },
  dashboard: { ...en.dashboard, title: 'Dashboard Sicurezza', subtitle: 'Monitoraggio minacce in tempo reale', noDataTitle: 'Nessun dato', noDataMsg: 'Esegui un\'analisi da Scansiona Obiettivo per generare avvisi.' },
  common: { ...en.common, save: 'Salva', cancel: 'Annulla', search: 'Cerca', loading: 'Caricamento...' },
}

const zh: Partial<TranslationSchema> = {
  nav: { dashboard: '控制台', agents: '代理', alerts: '警报', incidents: '事件', scanTarget: '扫描目标', settings: '设置', docs: '文档' },
  header: { systemOperational: '系统运行中', live: '实时', selectLanguage: '语言' },
  sidebar: { subtitle: '安全运营中心', version: 'v1.0.0' },
  dashboard: { ...en.dashboard, title: '安全仪表板', subtitle: '实时威胁监控', noDataTitle: '暂无数据', noDataMsg: '在"扫描目标"中运行分析以生成警报。' },
  common: { ...en.common, save: '保存', cancel: '取消', search: '搜索', loading: '加载中...' },
}

const ja: Partial<TranslationSchema> = {
  nav: { dashboard: 'ダッシュボード', agents: 'エージェント', alerts: 'アラート', incidents: 'インシデント', scanTarget: 'スキャン', settings: '設定', docs: 'ドキュメント' },
  header: { systemOperational: 'システム稼働中', live: 'ライブ', selectLanguage: '言語' },
  sidebar: { subtitle: 'セキュリティオペレーションセンター', version: 'v1.0.0' },
  dashboard: { ...en.dashboard, title: 'セキュリティダッシュボード', subtitle: 'リアルタイム脅威監視', noDataTitle: 'データなし', noDataMsg: 'スキャンターゲットから分析を実行してアラートを生成します。' },
  common: { ...en.common, save: '保存', cancel: 'キャンセル', search: '検索', loading: '読み込み中...' },
}

const ar: Partial<TranslationSchema> = {
  nav: { dashboard: 'لوحة التحكم', agents: 'العملاء', alerts: 'التنبيهات', incidents: 'الحوادث', scanTarget: 'مسح الهدف', settings: 'الإعدادات', docs: 'التوثيق' },
  header: { systemOperational: 'النظام يعمل', live: 'مباشر', selectLanguage: 'اللغة' },
  sidebar: { subtitle: 'مركز عمليات الأمن', version: 'v1.0.0' },
  dashboard: { ...en.dashboard, title: 'لوحة الأمان', subtitle: 'مراقبة التهديدات في الوقت الفعلي', noDataTitle: 'لا توجد بيانات', noDataMsg: 'قم بتشغيل تحليل من مسح الهدف لإنشاء التنبيهات.' },
  common: { ...en.common, save: 'حفظ', cancel: 'إلغاء', search: 'بحث', loading: 'جار التحميل...' },
}

const ru: Partial<TranslationSchema> = {
  nav: { dashboard: 'Панель', agents: 'Агенты', alerts: 'Оповещения', incidents: 'Инциденты', scanTarget: 'Сканировать', settings: 'Настройки', docs: 'Документация' },
  header: { systemOperational: 'Система работает', live: 'В ЭФИРЕ', selectLanguage: 'Язык' },
  sidebar: { subtitle: 'Центр операций безопасности', version: 'v1.0.0' },
  dashboard: { ...en.dashboard, title: 'Панель безопасности', subtitle: 'Мониторинг угроз в реальном времени', noDataTitle: 'Нет данных', noDataMsg: 'Запустите анализ из раздела Сканировать для генерации оповещений.' },
  common: { ...en.common, save: 'Сохранить', cancel: 'Отмена', search: 'Поиск', loading: 'Загрузка...' },
}

export const SUPPORTED_LANGUAGES = [
  { code: 'es', name: 'Español',    nativeName: 'Español',    flag: '🇪🇸', dir: 'ltr' },
  { code: 'en', name: 'English',    nativeName: 'English',    flag: '🇬🇧', dir: 'ltr' },
  { code: 'pt', name: 'Português',  nativeName: 'Português',  flag: '🇧🇷', dir: 'ltr' },
  { code: 'fr', name: 'Français',   nativeName: 'Français',   flag: '🇫🇷', dir: 'ltr' },
  { code: 'de', name: 'Deutsch',    nativeName: 'Deutsch',    flag: '🇩🇪', dir: 'ltr' },
  { code: 'it', name: 'Italiano',   nativeName: 'Italiano',   flag: '🇮🇹', dir: 'ltr' },
  { code: 'zh', name: 'Chinese',    nativeName: '中文',        flag: '🇨🇳', dir: 'ltr' },
  { code: 'ja', name: 'Japanese',   nativeName: '日本語',      flag: '🇯🇵', dir: 'ltr' },
  { code: 'ar', name: 'Arabic',     nativeName: 'العربية',     flag: '🇸🇦', dir: 'rtl' },
  { code: 'ru', name: 'Russian',    nativeName: 'Русский',    flag: '🇷🇺', dir: 'ltr' },
] as const

export type LangCode = typeof SUPPORTED_LANGUAGES[number]['code']

const rawTranslations: Record<string, Partial<TranslationSchema>> = { es, en, pt, fr, de, it, zh, ja, ar, ru }

export function getTranslations(lang: LangCode): TranslationSchema {
  const base = en as unknown as Record<string, unknown>
  const target = (rawTranslations[lang] ?? en) as Record<string, unknown>
  return deepMerge(base, target) as TranslationSchema
}

export { es, en }
