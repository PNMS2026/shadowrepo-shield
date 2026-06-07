use rusqlite::{params, Connection, Result};
use std::path::Path;
use super::scanner::types::{
    Category, DashboardStats, Finding, RiskLevel, ScanResult, ScanStatus, ScanSummary, Settings,
    Severity,
};

/// Initialize database and run migrations
pub fn init_db(db_path: &Path) -> Result<()> {
    let conn = Connection::open(db_path)?;

    // Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON;", [])?;

    // Create scans table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            path TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            total_files INTEGER NOT NULL,
            total_findings INTEGER NOT NULL,
            repo_hash TEXT NOT NULL,
            report_hash TEXT NOT NULL,
            status TEXT NOT NULL,
            blockchain_tx TEXT,
            blockchain_network TEXT
        );",
        [],
    )?;

    // Create findings table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            pattern_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            file_path TEXT NOT NULL,
            line_number INTEGER,
            matched_content TEXT,
            recommendation TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );",
        [],
    )?;

    // Create settings table (single row)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            storage_path TEXT NOT NULL,
            offline_mode INTEGER NOT NULL,
            auto_delete_temp INTEGER NOT NULL,
            blockchain_network TEXT NOT NULL,
            contract_address TEXT NOT NULL,
            rpc_url TEXT NOT NULL
        );",
        [],
    )?;

    // Insert default settings if not exists
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM settings WHERE id = 1;",
        [],
        |row| row.get(0),
    )?;

    if count == 0 {
        let parent_dir = db_path.parent().unwrap_or(Path::new(""));
        let default_storage = parent_dir.join("reports").to_string_lossy().to_string();

        conn.execute(
            "INSERT INTO settings (id, storage_path, offline_mode, auto_delete_temp, blockchain_network, contract_address, rpc_url)
             VALUES (1, ?1, 0, 1, 'hardhat', '0x5FbDB2315678afecb367f032d93F642f64180aa3', 'http://127.0.0.1:8545');",
            params![default_storage],
        )?;
    }

    Ok(())
}

/// Save a scan result to database
pub fn save_scan(db_path: &Path, result: &ScanResult) -> Result<()> {
    let mut conn = Connection::open(db_path)?;
    let tx = conn.transaction()?;

    // Insert scan
    tx.execute(
        "INSERT OR REPLACE INTO scans (
            id, name, path, scan_date, risk_score, risk_level, total_files, total_findings, repo_hash, report_hash, status, blockchain_tx, blockchain_network
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13);",
        params![
            result.id,
            result.name,
            result.path,
            result.scan_date,
            result.risk_score,
            format!("{:?}", result.risk_level).to_lowercase(),
            result.total_files,
            result.total_findings,
            result.repo_hash,
            result.report_hash,
            format!("{:?}", result.status).to_lowercase(),
            result.blockchain_tx,
            result.blockchain_network
        ],
    )?;

    // Clear old findings if re-scanning
    tx.execute("DELETE FROM findings WHERE scan_id = ?1;", params![result.id])?;

    // Insert findings
    for finding in &result.findings {
        tx.execute(
            "INSERT INTO findings (
                id, scan_id, pattern_id, severity, category, description, file_path, line_number, matched_content, recommendation
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10);",
            params![
                finding.id,
                finding.scan_id,
                finding.pattern_id,
                format!("{:?}", finding.severity).to_lowercase(),
                format!("{:?}", finding.category).to_lowercase(),
                finding.description,
                finding.file_path,
                finding.line_number,
                finding.matched_content,
                finding.recommendation
            ],
        )?;
    }

    tx.commit()?;
    Ok(())
}

/// Retrieve a scan result from database
pub fn get_scan(db_path: &Path, scan_id: &str) -> Result<Option<ScanResult>> {
    let conn = Connection::open(db_path)?;

    let mut stmt = conn.prepare(
        "SELECT id, name, path, scan_date, risk_score, risk_level, total_files, total_findings, repo_hash, report_hash, status, blockchain_tx, blockchain_network
         FROM scans WHERE id = ?1;"
    )?;

    let scan_opt = stmt.query_row(params![scan_id], |row| {
        let risk_lvl_str: String = row.get(5)?;
        let risk_level = match risk_lvl_str.as_str() {
            "critical" => RiskLevel::Critical,
            "high" => RiskLevel::High,
            "review_recommended" | "medium" => RiskLevel::ReviewRecommended,
            _ => RiskLevel::Low,
        };

        let status_str: String = row.get(10)?;
        let status = match status_str.as_str() {
            "scanning" => ScanStatus::Scanning,
            "failed" => ScanStatus::Failed,
            _ => ScanStatus::Completed,
        };

        Ok(ScanResult {
            id: row.get(0)?,
            name: row.get(1)?,
            path: row.get(2)?,
            scan_date: row.get(3)?,
            risk_score: row.get(4)?,
            risk_level,
            total_files: row.get(6)?,
            total_findings: row.get(7)?,
            repo_hash: row.get(8)?,
            report_hash: row.get(9)?,
            status,
            findings: Vec::new(),
            blockchain_tx: row.get(11)?,
            blockchain_network: row.get(12)?,
        })
    });

    let mut result = match scan_opt {
        Ok(r) => r,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(e),
    };

    // Load findings
    let mut stmt = conn.prepare(
        "SELECT id, scan_id, pattern_id, severity, category, description, file_path, line_number, matched_content, recommendation
         FROM findings WHERE scan_id = ?1;"
    )?;

    let findings_iter = stmt.query_map(params![scan_id], |row| {
        let severity_str: String = row.get(3)?;
        let severity = match severity_str.as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "informational" => Severity::Informational,
            _ => Severity::Low,
        };

        let category_str: String = row.get(4)?;
        let category = match category_str.as_str() {
            "malicious_indicator" => Category::MaliciousIndicator,
            "hook_execution_risk" => Category::HookExecutionRisk,
            "secret_handling_warning" => Category::SecretHandlingWarning,
            "web3_audit_risk" => Category::Web3AuditRisk,
            "solidity_audit_risk" => Category::SolidityAuditRisk,
            "ci_cd_warning" => Category::CiCdWarning,
            _ => Category::Informational,
        };

        Ok(Finding {
            id: row.get(0)?,
            scan_id: row.get(1)?,
            pattern_id: row.get(2)?,
            severity,
            category,
            description: row.get(5)?,
            file_path: row.get(6)?,
            line_number: row.get(7)?,
            matched_content: row.get(8)?,
            recommendation: row.get(9)?,
        })
    })?;

    for finding in findings_iter {
        result.findings.push(finding?);
    }

    Ok(Some(result))
}

/// Retrieve scan history (summaries)
pub fn get_scan_history(db_path: &Path) -> Result<Vec<ScanSummary>> {
    let conn = Connection::open(db_path)?;

    let mut stmt = conn.prepare(
        "SELECT id, name, path, scan_date, risk_score, risk_level, total_files, total_findings, status, blockchain_tx
         FROM scans ORDER BY scan_date DESC;"
    )?;

    let summaries_iter = stmt.query_map([], |row| {
        let risk_lvl_str: String = row.get(5)?;
        let risk_level = match risk_lvl_str.as_str() {
            "critical" => RiskLevel::Critical,
            "high" => RiskLevel::High,
            "review_recommended" | "medium" => RiskLevel::ReviewRecommended,
            _ => RiskLevel::Low,
        };

        let status_str: String = row.get(8)?;
        let status = match status_str.as_str() {
            "scanning" => ScanStatus::Scanning,
            "failed" => ScanStatus::Failed,
            _ => ScanStatus::Completed,
        };

        Ok(ScanSummary {
            id: row.get(0)?,
            name: row.get(1)?,
            path: row.get(2)?,
            scan_date: row.get(3)?,
            risk_score: row.get(4)?,
            risk_level,
            total_files: row.get(6)?,
            total_findings: row.get(7)?,
            status,
            blockchain_tx: row.get(9)?,
        })
    })?;

    let mut list = Vec::new();
    for summary in summaries_iter {
        list.push(summary?);
    }

    Ok(list)
}

/// Delete a scan and all its findings
pub fn delete_scan(db_path: &Path, scan_id: &str) -> Result<()> {
    let conn = Connection::open(db_path)?;
    // CASCADE triggers will delete findings automatically
    conn.execute("DELETE FROM scans WHERE id = ?1;", params![scan_id])?;
    Ok(())
}

/// Load settings
pub fn get_settings(db_path: &Path) -> Result<Settings> {
    let conn = Connection::open(db_path)?;

    let settings = conn.query_row(
        "SELECT storage_path, offline_mode, auto_delete_temp, blockchain_network, contract_address, rpc_url
         FROM settings WHERE id = 1;",
        [],
        |row| {
            let offline_mode: i32 = row.get(1)?;
            let auto_delete_temp: i32 = row.get(2)?;

            Ok(Settings {
                storage_path: row.get(0)?,
                offline_mode: offline_mode != 0,
                auto_delete_temp: auto_delete_temp != 0,
                blockchain_network: row.get(3)?,
                contract_address: row.get(4)?,
                rpc_url: row.get(5)?,
            })
        },
    )?;

    Ok(settings)
}

/// Update settings
pub fn update_settings(db_path: &Path, settings: &Settings) -> Result<()> {
    let conn = Connection::open(db_path)?;

    conn.execute(
        "UPDATE settings SET
            storage_path = ?1,
            offline_mode = ?2,
            auto_delete_temp = ?3,
            blockchain_network = ?4,
            contract_address = ?5,
            rpc_url = ?6
         WHERE id = 1;",
        params![
            settings.storage_path,
            if settings.offline_mode { 1 } else { 0 },
            if settings.auto_delete_temp { 1 } else { 0 },
            settings.blockchain_network,
            settings.contract_address,
            settings.rpc_url
        ],
    )?;

    Ok(())
}

/// Update blockchain transaction for a scan
pub fn update_blockchain_tx(
    db_path: &Path,
    scan_id: &str,
    tx_hash: &str,
    network: &str,
) -> Result<()> {
    let conn = Connection::open(db_path)?;

    conn.execute(
        "UPDATE scans SET blockchain_tx = ?1, blockchain_network = ?2 WHERE id = ?3;",
        params![tx_hash, network, scan_id],
    )?;

    Ok(())
}

/// Load dashboard statistics
pub fn get_dashboard_stats(db_path: &Path) -> Result<DashboardStats> {
    let conn = Connection::open(db_path)?;

    let total_scans: u32 = conn.query_row(
        "SELECT COUNT(*) FROM scans;",
        [],
        |row| row.get(0),
    )?;

    let critical_findings: u32 = conn.query_row(
        "SELECT COUNT(*) FROM scans WHERE risk_level = 'critical';",
        [],
        |row| row.get(0),
    )?;

    let average_risk: f64 = conn.query_row(
        "SELECT COALESCE(AVG(risk_score), 0.0) FROM scans;",
        [],
        |row| row.get(0),
    )?;

    let repos_scanned: u32 = conn.query_row(
        "SELECT COUNT(DISTINCT path) FROM scans;",
        [],
        |row| row.get(0),
    )?;

    Ok(DashboardStats {
        total_scans,
        critical_findings,
        average_risk: average_risk.round() as u32,
        repos_scanned,
    })
}
