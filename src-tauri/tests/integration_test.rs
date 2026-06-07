use shadowrepo_shield_lib::db;
use shadowrepo_shield_lib::report;
use shadowrepo_shield_lib::scanner;
use shadowrepo_shield_lib::scanner::types::{RiskLevel, ScanStatus};
use std::fs;
use std::path::Path;
use zip::ZipArchive;

#[test]
fn test_integration_flow() {
    // 1. Create a temporary database path
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("test_shield.db");

    // Initialize DB
    db::init_db(&db_path).expect("Failed to initialize SQLite database");

    // Check default settings
    let settings = db::get_settings(&db_path).expect("Failed to get settings");
    assert!(!settings.storage_path.is_empty());
    assert!(settings.auto_delete_temp);

    // 2. Extract mock malicious repository ZIP
    let zip_path = Path::new("../malicious.zip");
    assert!(zip_path.exists(), "malicious.zip must exist at project root");

    let extract_dir = temp_dir.path().join("extract");
    fs::create_dir_all(&extract_dir).unwrap();

    let file = fs::File::open(zip_path).unwrap();
    let mut archive = ZipArchive::new(file).unwrap();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).unwrap();
        let outpath = extract_dir.join(file.name());
        if (*file.name()).ends_with('/') {
            fs::create_dir_all(&outpath).unwrap();
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(p).unwrap();
                }
            }
            let mut outfile = fs::File::create(&outpath).unwrap();
            std::io::copy(&mut file, &mut outfile).unwrap();
        }
    }

    // 3. Execute static scan
    let scan_id = "test-scan-001".to_string();
    let result = scanner::run_scan(&extract_dir, &scan_id, "mock-malicious")
        .expect("Scan failed");

    // 4. Assert findings and threat pattern detections
    assert!(result.total_files > 0, "No files scanned");
    assert!(result.total_findings >= 4, "Should find at least 4 security findings");
    assert_eq!(result.risk_level, RiskLevel::Critical, "Mock repo must be classified as Critical");
    assert!(result.risk_score >= 90, "Mock repo score must be high (>= 90)");

    let mut has_postinstall = false;
    let mut has_child_process = false;
    let mut has_env_read = false;
    let mut has_approval_all = false;
    let mut has_approve_max = false;
    let mut has_hardcoded_key = false;

    for finding in &result.findings {
        match finding.pattern_id.as_str() {
            "pkg-postinstall" => has_postinstall = true,
            "js-child-process" => has_child_process = true,
            "js-env-read" => has_env_read = true,
            "web3-approval-all" => has_approval_all = true,
            "web3-approve-max" => has_approve_max = true,
            "web3-hardcoded-key" => has_hardcoded_key = true,
            _ => {}
        }
    }

    assert!(has_postinstall, "Missed package.json postinstall hook detection");
    assert!(has_child_process, "Missed child_process import detection");
    assert!(has_env_read, "Missed readFileSync(.env) detection");
    assert!(has_approval_all, "Missed setApprovalForAll detection");
    assert!(has_approve_max, "Missed MaxUint256 approval detection");
    assert!(has_hardcoded_key, "Missed hardcoded private key detection");

    // 5. Assert SQLite Persistence
    db::save_scan(&db_path, &result).expect("Failed to save scan result to DB");
    
    let loaded = db::get_scan(&db_path, &scan_id)
        .expect("Failed to query scan result")
        .expect("Scan result not found in DB");

    assert_eq!(loaded.id, result.id);
    assert_eq!(loaded.risk_score, result.risk_score);
    assert_eq!(loaded.total_findings, result.total_findings);
    assert_eq!(loaded.findings.len(), result.findings.len());

    // 6. Assert Report Exports (JSON and HTML)
    let json_report = temp_dir.path().join("report.json");
    let html_report = temp_dir.path().join("report.html");

    report::export_to_json(&result, &json_report).expect("JSON export failed");
    report::export_to_html(&result, &html_report).expect("HTML export failed");

    assert!(json_report.exists());
    assert!(html_report.exists());

    let html_content = fs::read_to_string(html_report).unwrap();
    assert!(html_content.contains("mock-malicious"));
    assert!(html_content.contains("Critical Threat Indicators Found"));

    // 7. Cleanup temp extracted folder
    fs::remove_dir_all(&extract_dir).expect("Failed to delete temp extracted files");
    assert!(!extract_dir.exists(), "Extracted folder was not cleaned up successfully");
}
