import type { Config } from 'tailwindcss'

const config: Config = {
  darkMode: 'class',
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        background: '#0a0f1e',
        surface: '#0f1729',
        border: '#1e2d4a',
        sidebar: '#080c18',
        accent: '#00d4ff',
        critical: '#ff3b3b',
        high: '#ff8c00',
        medium: '#ffd700',
        low: '#4488ff',
        info: '#888888',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
}

export default config
