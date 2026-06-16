export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

export type ThreatCategory =
  | 'monitoring'
  | 'threats'
  | 'cloud'
  | 'containers'
  | 'intelligence'
  | 'incident_response'
  | 'compliance'
  | 'specialized'

export interface Alert {
  id: string
  title: string
  severity: Severity
  category: string
  agent: string
  confidence: number
  timestamp: string
  description?: string
}

export interface Incident {
  id: string
  title: string
  status: 'open' | 'investigating' | 'contained' | 'resolved'
  severity: Severity
  created: string
  updated: string
}

export interface AgentInfo {
  name: string
  category: string
  description: string
  status: 'running' | 'idle' | 'error'
  priority: Severity
  version?: string
  tags?: string[]
}

export interface AgentAlert {
  severity: Severity
  title?: string
  description?: string
  confidence?: number
  category?: string
}

export interface AnalysisResult {
  agent_name?: string
  timestamp?: string
  risk_score: number
  confidence?: number
  execution_time_ms?: number
  alerts?: AgentAlert[]
  recommendations?: string[]
  findings?: Record<string, unknown>[]
  iocs?: unknown[]
  raw_ai_response?: string
  summary?: string
  metadata?: Record<string, unknown>
}

export interface ScanResult {
  agent: string
  label: string
  status: 'pending' | 'running' | 'done' | 'error'
  result?: AnalysisResult
  error?: string
}
