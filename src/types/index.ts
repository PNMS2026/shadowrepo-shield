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
  blockchain_tx: string | null;
}

export interface Settings {
  storage_path: string;
  offline_mode: boolean;
  auto_delete_temp: boolean;
  blockchain_network: string;
  contract_address: string;
  rpc_url: string;
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
  low: { label: "Low Risk", color: "#10B981", bg: "rgba(16, 185, 129, 0.15)" },
  review_recommended: {
    label: "Review Recommended",
    color: "#F59E0B",
    bg: "rgba(245, 158, 11, 0.15)",
  },
  high: {
    label: "High Risk",
    color: "#F97316",
    bg: "rgba(249, 115, 22, 0.15)",
  },
  critical: {
    label: "Critical Threat Indicators Found",
    color: "#EF4444",
    bg: "rgba(239, 68, 68, 0.15)",
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
