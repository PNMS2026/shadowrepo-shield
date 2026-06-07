use super::types::{Category, Finding, RiskLevel};

/// Calculate risk score (0-100) from findings
pub fn calculate_risk_score(findings: &[Finding]) -> u32 {
    let mut score = 0;

    for finding in findings {
        let weight = match finding.category {
            Category::MaliciousIndicator => 100,
            Category::HookExecutionRisk => 25,
            Category::SecretHandlingWarning => 15,
            Category::Web3AuditRisk => 10,
            Category::SolidityAuditRisk => 5,
            Category::CiCdWarning => 5,
            Category::Informational => 1,
        };
        score += weight;
    }

    score.min(100)
}

/// Get risk level from score
pub fn get_risk_level(score: u32) -> RiskLevel {
    match score {
        0..=14 => RiskLevel::Low,
        15..=39 => RiskLevel::ReviewRecommended,
        40..=74 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::Severity;

    fn make_finding(category: Category) -> Finding {
        Finding {
            id: "test".into(),
            scan_id: "test".into(),
            pattern_id: "test".into(),
            severity: Severity::Medium,
            category,
            description: "test".into(),
            file_path: "test.js".into(),
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
        let f1 = vec![make_finding(Category::Informational)];
        assert_eq!(calculate_risk_score(&f1), 1);

        let f2 = vec![make_finding(Category::SolidityAuditRisk)];
        assert_eq!(calculate_risk_score(&f2), 5);

        let f3 = vec![make_finding(Category::MaliciousIndicator)];
        assert_eq!(calculate_risk_score(&f3), 100);
    }

    #[test]
    fn test_score_caps_at_100() {
        let findings = vec![
            make_finding(Category::HookExecutionRisk),
            make_finding(Category::HookExecutionRisk),
            make_finding(Category::HookExecutionRisk),
            make_finding(Category::HookExecutionRisk),
            make_finding(Category::HookExecutionRisk),
        ];
        assert_eq!(calculate_risk_score(&findings), 100);
    }

    #[test]
    fn test_risk_levels() {
        assert!(matches!(get_risk_level(0), RiskLevel::Low));
        assert!(matches!(get_risk_level(14), RiskLevel::Low));
        assert!(matches!(get_risk_level(15), RiskLevel::ReviewRecommended));
        assert!(matches!(get_risk_level(39), RiskLevel::ReviewRecommended));
        assert!(matches!(get_risk_level(40), RiskLevel::High));
        assert!(matches!(get_risk_level(74), RiskLevel::High));
        assert!(matches!(get_risk_level(75), RiskLevel::Critical));
        assert!(matches!(get_risk_level(100), RiskLevel::Critical));
    }
}
