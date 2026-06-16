import type { Metadata } from 'next'
import './globals.css'
import { Sidebar } from '@/components/layout/Sidebar'
import { Header } from '@/components/layout/Header'
import { LanguageProvider } from '@/lib/i18n'

export const metadata: Metadata = {
  title: 'AI-SOC Dashboard',
  description: 'Autonomous AI Security Operations Center',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="es" className="dark">
      <body className="bg-background text-foreground">
        <LanguageProvider>
          <div className="flex h-screen overflow-hidden">
            <Sidebar />
            <div className="flex flex-col flex-1 overflow-hidden">
              <Header />
              <main className="flex-1 overflow-y-auto p-6">
                {children}
              </main>
            </div>
          </div>
        </LanguageProvider>
      </body>
    </html>
  )
}
