import type { Finding } from "../types";
import { CATEGORY_LABELS, getCategoryIcon } from "../types";
import RiskBadge from "./RiskBadge";

interface FindingCardProps {
  finding: Finding;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#10b981",
};

export default function FindingCard({ finding }: FindingCardProps) {
  return (
    <div className="finding-card animate-fade-in">
      <div
        className="finding-severity-bar"
        style={{ background: SEVERITY_COLORS[finding.severity] }}
      />
      <div className="finding-content">
        <div className="finding-title">
          <span>{getCategoryIcon(finding.category)}</span>
          <span>{finding.description}</span>
          <RiskBadge severity={finding.severity} size="sm" />
        </div>
        <div className="finding-meta">
          {finding.file_path}
          {finding.line_number ? `:${finding.line_number}` : ""}
          <span style={{ margin: "0 8px", color: "#475569" }}>•</span>
          {CATEGORY_LABELS[finding.category]}
        </div>
        {finding.matched_content && (
          <div
            className="finding-meta"
            style={{
              padding: "6px 8px",
              background: "rgba(239, 68, 68, 0.06)",
              borderRadius: "4px",
              marginBottom: "6px",
              fontSize: "11px",
              wordBreak: "break-all",
            }}
          >
            <code>{finding.matched_content}</code>
          </div>
        )}
        <div className="finding-recommendation">
          💡 {finding.recommendation}
        </div>
      </div>
    </div>
  );
}
