import type { AnalysisResult, ThreatCategory } from './types'

const BASE_URL = ''

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`API error ${res.status}: ${text}`)
  }
  return res.json() as Promise<T>
}

export interface BackendAgentState {
  name: string
  label: string
  status: 'pending' | 'running' | 'done' | 'error'
  result: AnalysisResult | null
  error: string | null
}

export interface BackendScan {
  id: string
  target: string
  target_type: string
  status: 'running' | 'complete'
  created_at: string
  completed_at: string | null
  agents: BackendAgentState[]
}

export async function getHealth(): Promise<Record<string, unknown>> {
  return request<Record<string, unknown>>('/health')
}

export async function getAgents(): Promise<Record<string, unknown>> {
  return request<Record<string, unknown>>('/api/v1/agents')
}

export async function getConfig(): Promise<{ provider: string; model: string }> {
  return request<{ provider: string; model: string }>('/api/v1/config')
}

export interface ConfigUpdate {
  provider: string
  api_key?: string
  model?: string
  base_url?: string
}

export async function updateConfig(data: ConfigUpdate): Promise<{ ok: boolean; provider: string }> {
  return request<{ ok: boolean; provider: string }>('/api/v1/config', {
    method: 'PUT',
    body: JSON.stringify(data),
  })
}

export async function analyzeByCategory(
  category: ThreatCategory,
  data: Record<string, unknown>
): Promise<AnalysisResult> {
  return request<AnalysisResult>(`/api/v1/analyze/${category}`, {
    method: 'POST',
    body: JSON.stringify({ data }),
  })
}

export async function analyzeByAgent(
  agentName: string,
  data: Record<string, unknown>
): Promise<AnalysisResult> {
  return request<AnalysisResult>(`/api/v1/analyze/agent/${agentName}`, {
    method: 'POST',
    body: JSON.stringify({ data }),
  })
}

export async function createScan(
  target: string,
  target_type: string,
  agents: { name: string; label: string; data: Record<string, unknown> }[]
): Promise<{ scan_id: string }> {
  return request<{ scan_id: string }>('/api/v1/scan', {
    method: 'POST',
    body: JSON.stringify({ target, target_type, agents }),
  })
}

export async function getScan(scanId: string): Promise<BackendScan> {
  return request<BackendScan>(`/api/v1/scan/${scanId}`)
}

export async function deleteScan(scanId: string): Promise<void> {
  await request<unknown>(`/api/v1/scan/${scanId}`, { method: 'DELETE' })
}
