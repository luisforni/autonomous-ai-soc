'use client'

import { createContext, useContext, useState, useCallback, type ReactNode } from 'react'
import type { ScanResult } from './types'

type TargetType = 'domain' | 'ip' | 'url'

interface ScanState {
  target: string
  targetType: TargetType
  results: ScanResult[]
  scanning: boolean
}

interface ScanStore extends ScanState {
  setTarget: (t: string) => void
  setTargetType: (t: TargetType) => void
  setResults: (fn: (prev: ScanResult[]) => ScanResult[]) => void
  setScanning: (s: boolean) => void
  reset: () => void
}

const initial: ScanState = { target: '', targetType: 'domain', results: [], scanning: false }

const ScanContext = createContext<ScanStore | null>(null)

export function ScanProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<ScanState>(initial)

  const setTarget = useCallback((target: string) => setState(s => ({ ...s, target })), [])
  const setTargetType = useCallback((targetType: TargetType) => setState(s => ({ ...s, targetType })), [])
  const setResults = useCallback((fn: (prev: ScanResult[]) => ScanResult[]) =>
    setState(s => ({ ...s, results: fn(s.results) })), [])
  const setScanning = useCallback((scanning: boolean) => setState(s => ({ ...s, scanning })), [])
  const reset = useCallback(() => setState(initial), [])

  return (
    <ScanContext.Provider value={{ ...state, setTarget, setTargetType, setResults, setScanning, reset }}>
      {children}
    </ScanContext.Provider>
  )
}

export function useScan() {
  const ctx = useContext(ScanContext)
  if (!ctx) throw new Error('useScan must be used inside ScanProvider')
  return ctx
}
