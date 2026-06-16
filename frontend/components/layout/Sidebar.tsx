'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import {
  LayoutDashboard,
  Bot,
  ShieldAlert,
  Siren,
  FlaskConical,
  Settings,
  Shield,
  BookOpen,
} from 'lucide-react'
import { useTranslation } from '@/lib/i18n'

export function Sidebar() {
  const pathname = usePathname()
  const { t } = useTranslation()

  const NAV_ITEMS = [
    { href: '/dashboard',  label: t('nav.dashboard'),  icon: LayoutDashboard },
    { href: '/agents',     label: t('nav.agents'),     icon: Bot },
    { href: '/alerts',     label: t('nav.alerts'),     icon: ShieldAlert },
    { href: '/incidents',  label: t('nav.incidents'),  icon: Siren },
    { href: '/analyze',    label: t('nav.scanTarget'), icon: FlaskConical },
    { href: '/docs',       label: t('nav.docs'),       icon: BookOpen },
    { href: '/settings',   label: t('nav.settings'),   icon: Settings },
  ]

  return (
    <aside className="w-60 shrink-0 bg-sidebar border-r border-border flex flex-col h-full">
      <div className="flex items-center gap-3 px-5 py-5 border-b border-border">
        <div className="w-8 h-8 rounded-lg bg-accent/20 border border-accent/40 flex items-center justify-center">
          <Shield className="w-4 h-4 text-accent" />
        </div>
        <div>
          <p className="text-white font-bold text-sm leading-tight">AI-SOC</p>
          <p className="text-accent text-xs">{t('sidebar.subtitle')}</p>
        </div>
      </div>

      <nav className="flex-1 py-4 space-y-1 px-3">
        {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
          const active = pathname === href || (href !== '/dashboard' && pathname.startsWith(href))
          return (
            <Link
              key={href}
              href={href}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                active
                  ? 'bg-accent/15 text-accent border border-accent/30'
                  : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
            >
              <Icon className="w-4 h-4 shrink-0" />
              {label}
            </Link>
          )
        })}
      </nav>

      <div className="px-5 py-4 border-t border-border">
        <p className="text-xs text-slate-500">Autonomous AI-SOC</p>
        <p className="text-xs text-slate-600">{t('sidebar.version')} · Luis Forni</p>
      </div>
    </aside>
  )
}
