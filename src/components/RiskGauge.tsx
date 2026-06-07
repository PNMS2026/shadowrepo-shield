import { RISK_LEVEL_CONFIG, getRiskLevel, RiskLevel } from "../types";

interface RiskGaugeProps {
  score: number;
  size?: number;
  level?: RiskLevel;
}

export default function RiskGauge({ score, size = 180, level }: RiskGaugeProps) {
  const finalLevel = level || getRiskLevel(score);
  const config = RISK_LEVEL_CONFIG[finalLevel];

  const radius = (size - 20) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const center = size / 2;

  const label = finalLevel === "high" && score >= 80 ? "High Risk — Manual Review Recommended" : config.label;

  return (
    <div className="risk-gauge" style={{ width: size, height: size }}>
      <svg
        className="risk-gauge-circle"
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
      >
        <circle
          className="risk-gauge-bg"
          cx={center}
          cy={center}
          r={radius}
        />
        <circle
          className="risk-gauge-fill"
          cx={center}
          cy={center}
          r={radius}
          style={{
            stroke: config.color,
            strokeDasharray: circumference,
            strokeDashoffset: offset,
            filter: `drop-shadow(0 0 8px ${config.color}40)`,
          }}
        />
      </svg>
      <div className="risk-gauge-value">
        <div className="risk-gauge-score" style={{ color: config.color }}>
          {score}
        </div>
        <div className="risk-gauge-label" style={{ color: config.color }}>
          {label}
        </div>
      </div>
    </div>
  );
}
