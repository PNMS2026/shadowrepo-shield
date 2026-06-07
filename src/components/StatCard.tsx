import type { ReactNode } from "react";

interface StatCardProps {
  icon: ReactNode;
  value: string | number;
  label: string;
  color: string;
  bgColor: string;
}

export default function StatCard({
  icon,
  value,
  label,
  color,
  bgColor,
}: StatCardProps) {
  return (
    <div className="stat-card">
      <div className="stat-icon" style={{ background: bgColor }}>
        <span style={{ color }}>{icon}</span>
      </div>
      <div className="stat-info">
        <div className="stat-value" style={{ color }}>
          {value}
        </div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}
