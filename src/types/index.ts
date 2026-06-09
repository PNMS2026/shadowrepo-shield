// ============================================================
// ShadowRepo Shield — Core TypeScript Type Definitions
// ============================================================

export type Severity = "critical" | "high" | "medium" | "low" | "informational";

export type RiskLevel = "low" | "review_recommended" | "high" | "critical";

export type Category =
  | "malicious_indicator"
  | "hook_execution_risk"
  | "secret_handling_warning"
  | "web3_audit_risk"
  | "solidity_audit_risk"
  | "ci_cd_warning"
  | "informational";

export type ScanStatus = "pending" | "scanning" | "completed" | "failed";

export type ScanMode = "local" | "verified";

export type ReportFormat = "json" | "html" | "pdf";

export interface Finding {
  id: string;
  scan_id: string;
  pattern_id: string;
  severity: Severity;
  category: Category;
  description: string;
  file_path: string;
  line_number: number | null;
  matched_content: string | null;
  recommendation: string;
}

export interface ScanResult {
  id: string;
  name: string;
  path: string;
  scan_date: string;
  risk_score: number;
  risk_level: RiskLevel;
  total_files: number;
  total_findings: number;
  repo_hash: string;
  report_hash: string;
  status: ScanStatus;
  scan_mode: ScanMode;
  scanner_signature: string | null;
  findings: Finding[];
  blockchain_tx: string | null;
  blockchain_network: string | null;
}

export interface ScanSummary {
  id: string;
  name: string;
  path: string;
  scan_date: string;
  risk_score: number;
  risk_level: RiskLevel;
  total_files: number;
  total_findings: number;
  status: ScanStatus;
  scan_mode: ScanMode;
  blockchain_tx: string | null;
}

export interface Settings {
  storage_path: string;
  offline_mode: boolean;
  auto_delete_temp: boolean;
  blockchain_network: string;
  contract_address: string;
  rpc_url: string;
  ai_enabled: boolean;
  ai_model: string;
}

export interface BlockchainProof {
  repo_hash: string;
  report_hash: string;
  risk_score: number;
  scanner: string;
  timestamp: number;
  exists: boolean;
}

export interface DashboardStats {
  total_scans: number;
  critical_findings: number;
  average_risk: number;
  repos_scanned: number;
  verified_scans: number;
}

/// AI advisory analysis — does NOT affect score, severity, grade, or risk level
export interface AiAnalysis {
  summary: string;
  recommendations: string[];
  confidence: string;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

export const CATEGORY_LABELS: Record<Category, string> = {
  malicious_indicator: "Malicious Indicator",
  hook_execution_risk: "Hook / Execution Risk",
  secret_handling_warning: "Secret Handling Warning",
  web3_audit_risk: "Web3 Audit Risk",
  solidity_audit_risk: "Solidity Audit Risk",
  ci_cd_warning: "CI/CD Warning",
  informational: "Informational",
};

export const RISK_LEVEL_CONFIG: Record<
  RiskLevel,
  { label: string; color: string; bg: string }
> = {
  low: { label: "Low Risk", color: "#2ea043", bg: "rgba(46, 160, 67, 0.15)" },
  review_recommended: {
    label: "Review Recommended",
    color: "#d29922",
    bg: "rgba(210, 153, 34, 0.15)",
  },
  high: {
    label: "High Risk",
    color: "#db6d28",
    bg: "rgba(219, 109, 40, 0.15)",
  },
  critical: {
    label: "Critical Threat Indicators Found",
    color: "#f85149",
    bg: "rgba(248, 81, 73, 0.15)",
  },
};

export function getRiskLevel(score: number): RiskLevel {
  if (score <= 20) return "low";
  if (score <= 49) return "review_recommended";
  if (score <= 79) return "high";
  return "critical";
}

export function getCategoryIcon(category: Category): string {
  switch (category) {
    case "malicious_indicator":
      return "🚨";
    case "hook_execution_risk":
      return "⚙️";
    case "secret_handling_warning":
      return "🔑";
    case "web3_audit_risk":
      return "⛓️";
    case "solidity_audit_risk":
      return "📜";
    case "ci_cd_warning":
      return "🤖";
    case "informational":
      return "ℹ️";
  }
}
