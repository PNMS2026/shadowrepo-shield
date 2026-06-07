use super::types::{Category, Finding, RiskLevel, Severity};

/// Check if any finding triggers Critical threat level directly
pub fn has_critical_trigger(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.severity == Severity::Critical)
}

/// Calculate risk score (0-100) from findings
pub fn calculate_risk_score(findings: &[Finding]) -> u32 {
    if findings.is_empty() {
        return 0;
    }

    // Direct critical trigger overrides the score to 100
    if has_critical_trigger(findings) {
        return 100;
    }

    // 1. Deduplicate: same file + same rule (pattern_id) should count once.
    let mut unique_findings: Vec<&Finding> = Vec::new();
    for finding in findings {
        if !unique_findings.iter().any(|uf| uf.file_path == finding.file_path && uf.pattern_id == finding.pattern_id) {
            unique_findings.push(finding);
        }
    }

    // 2. Cap same rule ID contribution to max 2 occurrences globally.
    let mut counted_findings: Vec<&Finding> = Vec::new();
    let mut rule_counts = std::collections::HashMap::new();
    for finding in unique_findings {
        let count = rule_counts.entry(&finding.pattern_id).or_insert(0);
        if *count < 2 {
            counted_findings.push(finding);
            *count += 1;
        }
    }

    // Check if combined with malicious indicators.
    let has_malicious = findings.iter().any(|f| f.category == Category::MaliciousIndicator);

    // 3. Accumulate contributions with specific severity weights:
    // Informational: 0.25, Low: 0.5, Medium: 3.0, High: 10.0, Critical: 35.0
    let mut sum_low: f32 = 0.0;
    let mut sum_info: f32 = 0.0;

    for finding in &counted_findings {
        match finding.severity {
            Severity::Low => sum_low += 0.5,
            Severity::Informational => sum_info += 0.25,
            _ => {}
        }
    }

    // Apply caps for low and informational severity contributions
    let low_cap = sum_low.min(8.0);
    let info_cap = sum_info.min(3.0);

    // Scaling factors
    let low_scale = if sum_low > 0.0 { low_cap / sum_low } else { 1.0 };
    let info_scale = if sum_info > 0.0 { info_cap / sum_info } else { 1.0 };

    let mut web3_sum: f32 = 0.0;
    let mut solidity_sum: f32 = 0.0;
    let mut other_sum: f32 = 0.0;

    for finding in &counted_findings {
        let raw_weight = match finding.severity {
            Severity::Critical => 35.0,
            Severity::High => 10.0,
            Severity::Medium => 3.0,
            Severity::Low => 0.5 * low_scale,
            Severity::Informational => 0.25 * info_scale,
        };

        if finding.category == Category::Web3AuditRisk {
            web3_sum += raw_weight;
        } else if finding.category == Category::SolidityAuditRisk {
            solidity_sum += raw_weight;
        } else {
            other_sum += raw_weight;
        }
    }

    // Apply category caps if not combined with malicious indicators
    if !has_malicious {
        web3_sum = web3_sum.min(30.0);
        solidity_sum = solidity_sum.min(35.0);
    }

    let final_score = web3_sum + solidity_sum + other_sum;
    
    // Round to nearest integer and clamp to 0-100
    let rounded = (final_score + 0.5) as u32;
    rounded.min(100)
}

/// Get risk level from score and findings
pub fn get_risk_level(score: u32, findings: &[Finding]) -> RiskLevel {
    if score >= 80 {
        if has_critical_trigger(findings) {
            RiskLevel::Critical
        } else {
            RiskLevel::High
        }
    } else {
        match score {
            0..=20 => RiskLevel::Low,
            21..=49 => RiskLevel::ReviewRecommended,
            _ => RiskLevel::High,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(category: Category, severity: Severity, pattern_id: &str, file: &str) -> Finding {
        Finding {
            id: "test".into(),
            scan_id: "test".into(),
            pattern_id: pattern_id.into(),
            severity,
            category,
            description: "test".into(),
            file_path: file.into(),
            line_number: Some(1),
            matched_content: None,
            recommendation: "test".into(),
        }
    }

    #[test]
    fn test_empty_findings_zero_score() {
        assert_eq!(calculate_risk_score(&[]), 0);
    }

    #[test]
    fn test_category_scores() {
        let f1 = vec![make_finding(Category::Informational, Severity::Informational, "info-rule", "test.js")];
        assert_eq!(calculate_risk_score(&f1), 0); // 0.25 rounds to 0

        let f2 = vec![
            make_finding(Category::Informational, Severity::Informational, "info-rule1", "test.js"),
            make_finding(Category::Informational, Severity::Informational, "info-rule2", "test.js")
        ];
        assert_eq!(calculate_risk_score(&f2), 1); // 0.5 rounds to 1
    }

    #[test]
    fn test_score_caps_at_100() {
        let findings = vec![
            make_finding(Category::MaliciousIndicator, Severity::Critical, "mal-1", "test.js"),
            make_finding(Category::MaliciousIndicator, Severity::Critical, "mal-2", "test.js"),
            make_finding(Category::MaliciousIndicator, Severity::Critical, "mal-3", "test.js"),
        ];
        assert_eq!(calculate_risk_score(&findings), 100);
    }

    #[test]
    fn test_risk_levels() {
        // Without critical triggers
        let findings_no_crit = vec![];
        assert!(matches!(get_risk_level(0, &findings_no_crit), RiskLevel::Low));
        assert!(matches!(get_risk_level(20, &findings_no_crit), RiskLevel::Low));
        assert!(matches!(get_risk_level(21, &findings_no_crit), RiskLevel::ReviewRecommended));
        assert!(matches!(get_risk_level(49, &findings_no_crit), RiskLevel::ReviewRecommended));
        assert!(matches!(get_risk_level(50, &findings_no_crit), RiskLevel::High));
        assert!(matches!(get_risk_level(80, &findings_no_crit), RiskLevel::High));

        // With critical triggers
        let findings_crit = vec![make_finding(Category::MaliciousIndicator, Severity::Critical, "rule", "test.js")];
        assert!(matches!(get_risk_level(80, &findings_crit), RiskLevel::Critical));
        assert!(matches!(get_risk_level(100, &findings_crit), RiskLevel::Critical));
    }
}
