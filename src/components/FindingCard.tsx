import { useState } from "react";
import type { Finding } from "../types";
import { CATEGORY_LABELS, getCategoryIcon } from "../types";
import RiskBadge from "./RiskBadge";
import { explainFinding } from "../lib/tauri";

interface FindingCardProps {
  finding: Finding;
  aiEnabled?: boolean;
  aiModel?: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#f85149",
  high: "#db6d28",
  medium: "#d29922",
  low: "#2ea043",
  informational: "#8b949e",
};

export default function FindingCard({ finding, aiEnabled, aiModel }: FindingCardProps) {
  const [explanation, setExplanation] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleExplain() {
    if (!aiModel) return;
    setLoading(true);
    setError(null);
    try {
      const resp = await explainFinding(aiModel, {
        pattern_id: finding.pattern_id,
        severity: finding.severity,
        category: finding.category,
        description: finding.description,
        file_path: finding.file_path,
        matched_content: finding.matched_content,
        recommendation: finding.recommendation,
      });
      setExplanation(resp);
    } catch (err: any) {
      console.error(err);
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="finding-card animate-fade-in" style={{ flexDirection: "column" }}>
      <div style={{ display: "flex", gap: "12px" }}>
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
                padding: "8px 12px",
                background: "var(--color-surface-700)",
                border: "1px solid var(--color-surface-600)",
                borderRadius: "4px",
                marginBottom: "8px",
                fontSize: "11px",
                wordBreak: "break-all",
                color: "var(--color-text-primary)",
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

      {aiEnabled && aiModel && (
        <div style={{ marginTop: "12px", borderTop: "1px solid var(--color-surface-600)", paddingTop: "8px", paddingLeft: "15px" }}>
          {!explanation && !loading && !error && (
            <button
              onClick={handleExplain}
              style={{
                background: "var(--color-surface-700)",
                border: "1px solid var(--color-surface-600)",
                color: "var(--color-brand-secondary)",
                borderRadius: "4px",
                padding: "4px 10px",
                fontSize: "11px",
                fontWeight: 600,
                cursor: "pointer",
                display: "inline-flex",
                alignItems: "center",
                gap: "6px"
              }}
            >
              ✨ Explain with AI
            </button>
          )}

          {loading && (
            <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "11px", color: "var(--color-text-muted)" }}>
              <span style={{ width: "12px", height: "12px", border: "2px solid rgba(255,255,255,0.1)", borderTopColor: "var(--color-brand-primary)", borderRadius: "50%", display: "inline-block", animation: "spin 1s linear infinite" }} />
              Generating explanation via {aiModel}...
            </div>
          )}

          {error && (
            <div style={{ fontSize: "11px", color: "#ef4444", marginTop: "4px" }}>
              ❌ Error: {error}
              <button onClick={handleExplain} style={{ marginLeft: "8px", background: "none", border: "none", color: "var(--color-brand-accent)", textDecoration: "underline", cursor: "pointer", fontSize: "11px" }}>Retry</button>
            </div>
          )}

          {explanation && (
            <div
              style={{
                background: "var(--color-surface-900)",
                border: "1px solid var(--color-surface-600)",
                borderRadius: "4px",
                padding: "10px",
                marginTop: "6px",
                fontSize: "12px",
                color: "var(--color-text-secondary)",
                lineHeight: "1.6"
              }}
            >
              <div style={{ fontWeight: 700, fontSize: "11px", color: "var(--color-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "6px", display: "flex", justifyContent: "space-between" }}>
                <span>AI Explanation ({aiModel})</span>
                <button
                  onClick={() => navigator.clipboard.writeText(explanation)}
                  style={{ background: "none", border: "none", color: "var(--color-brand-accent)", cursor: "pointer", fontSize: "10px" }}
                >
                  Copy
                </button>
              </div>
              <div style={{ whiteSpace: "pre-wrap" }}>{explanation}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
