import type { Severity, RiskLevel } from "../types";

interface RiskBadgeProps {
  severity?: Severity;
  riskLevel?: RiskLevel;
  size?: "sm" | "md";
}

export default function RiskBadge({
  severity,
  riskLevel,
  size = "md",
}: RiskBadgeProps) {
  const level = riskLevel || severity || "low";

  const severityLabels: Record<string, string> = {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
  };

  return (
    <span
      className={`badge badge-${level}`}
      style={
        size === "sm" ? { fontSize: "10px", padding: "2px 7px" } : undefined
      }
    >
      {severityLabels[level] || level}
    </span>
  );
}
