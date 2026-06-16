import { StatusBadge } from '@/components/ui/StatusBadge'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { Bot } from 'lucide-react'
import type { AgentInfo } from '@/lib/types'

interface AgentCardProps {
  agent: AgentInfo
}

export function AgentCard({ agent }: AgentCardProps) {
  return (
    <div className="bg-surface border border-border rounded-xl p-5 hover:border-accent/40 transition-colors space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-accent/10 border border-accent/30 flex items-center justify-center shrink-0">
            <Bot className="w-4 h-4 text-accent" />
          </div>
          <div>
            <p className="font-mono text-sm font-semibold text-white">{agent.name}</p>
            <p className="text-xs text-slate-500 capitalize mt-0.5">{agent.category.replace('_', ' ')}</p>
          </div>
        </div>
        <StatusBadge status={agent.status} />
      </div>

      <p className="text-xs text-slate-400 leading-relaxed">{agent.description}</p>

      <div className="flex items-center justify-between pt-1">
        <SeverityBadge severity={agent.priority} />
        <span className="text-xs text-slate-500">Priority</span>
      </div>
    </div>
  )
}
