'use client'

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts'

interface DataPoint {
  category: string
  count: number
}

interface CategoryChartProps {
  data: DataPoint[]
}

const COLORS = ['#ff3b3b', '#ff8c00', '#ffd700', '#4488ff', '#00d4ff', '#a855f7', '#22c55e']

export function CategoryChart({ data }: CategoryChartProps) {
  return (
    <div className="bg-surface border border-border rounded-xl p-5">
      <h2 className="text-lg font-semibold text-white mb-4">Alerts by Category</h2>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" vertical={false} />
          <XAxis dataKey="category" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: '#94a3b8', fontSize: 12 }} axisLine={false} tickLine={false} />
          <Tooltip
            contentStyle={{ backgroundColor: '#0f1729', border: '1px solid #1e2d4a', borderRadius: 8 }}
            labelStyle={{ color: '#e2e8f0' }}
            cursor={{ fill: 'rgba(255,255,255,0.03)' }}
          />
          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
            {data.map((_, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
