use serde::{Deserialize, Serialize};

/// Severity levels for findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

/// Categories of security findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    MaliciousIndicator,
    HookExecutionRisk,
    SecretHandlingWarning,
    Web3AuditRisk,
    SolidityAuditRisk,
    CiCdWarning,
    Informational,
}

/// Risk level derived from score
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    ReviewRecommended,
    High,
    Critical,
}

/// Scan status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Pending,
    Scanning,
    Completed,
    Failed,
}

/// A single security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub scan_id: String,
    pub pattern_id: String,
    pub severity: Severity,
    pub category: Category,
    pub description: String,
    pub file_path: String,
    pub line_number: Option<u32>,
    pub matched_content: Option<String>,
    pub recommendation: String,
}

/// Full scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: String,
    pub name: String,
    pub path: String,
    pub scan_date: String,
    pub risk_score: u32,
    pub risk_level: RiskLevel,
    pub total_files: u32,
    pub total_findings: u32,
    pub repo_hash: String,
    pub report_hash: String,
    pub status: ScanStatus,
    pub findings: Vec<Finding>,
    pub blockchain_tx: Option<String>,
    pub blockchain_network: Option<String>,
}

/// Summary of a scan for history listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub id: String,
    pub name: String,
    pub path: String,
    pub scan_date: String,
    pub risk_score: u32,
    pub risk_level: RiskLevel,
    pub total_files: u32,
    pub total_findings: u32,
    pub status: ScanStatus,
    pub blockchain_tx: Option<String>,
}

/// Application settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub storage_path: String,
    pub offline_mode: bool,
    pub auto_delete_temp: bool,
    pub blockchain_network: String,
    pub contract_address: String,
    pub rpc_url: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            storage_path: String::new(),
            offline_mode: false,
            auto_delete_temp: true,
            blockchain_network: "hardhat".to_string(),
            contract_address: "0x5FbDB2315678afecb367f032d93F642f64180aa3".to_string(),
            rpc_url: "http://127.0.0.1:8545".to_string(),
        }
    }
}

/// Dashboard statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    pub total_scans: u32,
    pub critical_findings: u32,
    pub average_risk: u32,
    pub repos_scanned: u32,
}

/// A pattern rule for the scanner
#[derive(Debug, Clone)]
pub struct PatternRule {
    pub id: String,
    pub severity: Severity,
    pub category: Category,
    pub description: String,
    pub recommendation: String,
    pub pattern: regex::Regex,
}

/// Information about a scanned file
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: String,
    pub relative_path: String,
    pub size: u64,
    pub hash: String,
}
