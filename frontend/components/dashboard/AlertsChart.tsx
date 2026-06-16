'use client'

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'

interface DataPoint {
  date: string
  alerts: number
}

interface AlertsChartProps {
  data: DataPoint[]
}

export function AlertsChart({ data }: AlertsChartProps) {
  return (
    <div className="bg-surface border border-border rounded-xl p-5">
      <h2 className="text-lg font-semibold text-white mb-4">Alerts Over Time</h2>
      <ResponsiveContainer width="100%" height={220}>
        <LineChart data={data} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" />
          <XAxis dataKey="date" tick={{ fill: '#94a3b8', fontSize: 12 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: '#94a3b8', fontSize: 12 }} axisLine={false} tickLine={false} />
          <Tooltip
            contentStyle={{ backgroundColor: '#0f1729', border: '1px solid #1e2d4a', borderRadius: 8 }}
            labelStyle={{ color: '#e2e8f0' }}
            itemStyle={{ color: '#00d4ff' }}
          />
          <Line
            type="monotone"
            dataKey="alerts"
            stroke="#00d4ff"
            strokeWidth={2}
            dot={{ fill: '#00d4ff', strokeWidth: 0, r: 4 }}
            activeDot={{ r: 6, fill: '#00d4ff' }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
