interface RiskGaugeProps {
  score: number // 0-10
}

export function RiskGauge({ score }: RiskGaugeProps) {
  const pct = score / 10
  const radius = 40
  const circumference = Math.PI * radius // half-circle
  const offset = circumference * (1 - pct)

  const color =
    score >= 8 ? '#ff3b3b'
    : score >= 6 ? '#ff8c00'
    : score >= 4 ? '#ffd700'
    : '#4488ff'

  return (
    <svg width="100" height="60" viewBox="0 0 100 60" className="shrink-0">
      {/* Track */}
      <path
        d="M 10 55 A 40 40 0 0 1 90 55"
        fill="none"
        stroke="#1e2d4a"
        strokeWidth="8"
        strokeLinecap="round"
      />
      {/* Fill */}
      <path
        d="M 10 55 A 40 40 0 0 1 90 55"
        fill="none"
        stroke={color}
        strokeWidth="8"
        strokeLinecap="round"
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        style={{ transition: 'stroke-dashoffset 0.6s ease' }}
      />
      {/* Score label */}
      <text x="50" y="52" textAnchor="middle" fill={color} fontSize="14" fontWeight="bold">
        {score.toFixed(1)}
      </text>
    </svg>
  )
}
