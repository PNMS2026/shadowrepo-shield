use regex::Regex;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const AI_KEYS_RAW: &str = include_str!("../../ai_keys.json");

#[derive(Deserialize, Debug)]
struct AiKeys {
    openai_api_key: String,
    gemini_api_key: String,
    nvidia_api_key: String,
    openrouter_api_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FindingExplanationRequest {
    pub pattern_id: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub file_path: String,
    pub matched_content: Option<String>,
    pub recommendation: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecutiveSummaryRequest {
    pub project_name: String,
    pub total_files: u32,
    pub total_findings: u32,
    pub risk_score: u32,
    pub findings_summary: Vec<FindingSummaryInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FindingSummaryInfo {
    pub description: String,
    pub severity: String,
    pub file_path: String,
}

/// Redact sensitive patterns (private keys, mnemonics, credentials) from snippets
pub fn redact_secrets(input: &str) -> String {
    let mut result = input.to_string();

    // 1. Redact 0x-prefixed 64-character private keys
    let pk_regex = Regex::new(r"(?i)0x[a-f0-9]{64}").unwrap();
    result = pk_regex.replace_all(&result, "[REDACTED_PRIVATE_KEY]").to_string();

    // 2. Redact raw 64-character hex keys
    let raw_hex_regex = Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap();
    result = raw_hex_regex.replace_all(&result, "[REDACTED_KEY]").to_string();

    // 3. Redact common environment variables values / secret assignments
    let env_regex = Regex::new(r##"(?i)(private_?key|mnemonic|seed_?phrase|password|secret|api_?key|key|pwd|token)\s*[:=]\s*['"#]?[^\s'"#\n]+['"#]?"##).unwrap();
    result = env_regex.replace_all(&result, |caps: &regex::Captures| {
        let full_match = &caps[0];
        if full_match.contains("[REDACTED") {
            full_match.to_string()
        } else {
            format!("{}: [REDACTED_SECRET]", &caps[1])
        }
    }).to_string();

    // 4. Redact potential mnemonic lists (12 to 24 space-separated lowercase words)
    let mnemonic_regex = Regex::new(r"\b[a-z]{3,12}(?:\s+[a-z]{3,12}){11,23}\b").unwrap();
    result = mnemonic_regex.replace_all(&result, "[REDACTED_MNEMONIC]").to_string();

    result
}

/// Helper to get keys parsed
fn get_api_keys() -> Result<AiKeys, String> {
    serde_json::from_str(AI_KEYS_RAW)
        .map_err(|e| format!("Failed to parse embedded AI keys config: {}", e))
}

/// Run request to OpenAI compatible chat completions
async fn call_openai_compatible(
    base_url: &str,
    api_key: &str,
    model: &str,
    prompt: &str,
) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    #[derive(Serialize)]
    struct Message {
        role: String,
        content: String,
    }
    #[derive(Serialize)]
    struct Payload {
        model: String,
        messages: Vec<Message>,
        temperature: f32,
    }

    let payload = Payload {
        model: model.to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: prompt.to_string(),
        }],
        temperature: 0.2,
    };

    let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Network request failed: {}", e))?;

    let status = response.status();
    if !status.is_success() {
        let err_text = response.text().await.unwrap_or_default();
        return Err(format!("API returned status {}: {}", status, err_text));
    }

    #[derive(Deserialize)]
    struct Choice {
        message: ChoiceMessage,
    }
    #[derive(Deserialize)]
    struct ChoiceMessage {
        content: String,
    }
    #[derive(Deserialize)]
    struct ResponsePayload {
        choices: Vec<Choice>,
    }

    let parsed: ResponsePayload = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse API response: {}", e))?;

    if parsed.choices.is_empty() {
        return Err("API returned choices list empty".into());
    }

    Ok(parsed.choices[0].message.content.clone())
}

/// Run request to Gemini API
async fn call_gemini(api_key: &str, model: &str, prompt: &str) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    #[derive(Serialize)]
    struct TextPart {
        text: String,
    }
    #[derive(Serialize)]
    struct Content {
        parts: Vec<TextPart>,
    }
    #[derive(Serialize)]
    struct Payload {
        contents: Vec<Content>,
    }

    let payload = Payload {
        contents: vec![Content {
            parts: vec![TextPart {
                text: prompt.to_string(),
            }],
        }],
    };

    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
        model, api_key
    );

    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Gemini API request failed: {}", e))?;

    let status = response.status();
    if !status.is_success() {
        let err_text = response.text().await.unwrap_or_default();
        return Err(format!("Gemini API error {}: {}", status, err_text));
    }

    #[derive(Deserialize)]
    struct Part {
        text: String,
    }
    #[derive(Deserialize)]
    struct ContentResp {
        parts: Vec<Part>,
    }
    #[derive(Deserialize)]
    struct Candidate {
        content: ContentResp,
    }
    #[derive(Deserialize)]
    struct ResponsePayload {
        candidates: Vec<Candidate>,
    }

    let parsed: ResponsePayload = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Gemini response: {}", e))?;

    if parsed.candidates.is_empty() || parsed.candidates[0].content.parts.is_empty() {
        return Err("Gemini API candidate content empty".into());
    }

    Ok(parsed.candidates[0].content.parts[0].text.clone())
}

/// Explain a specific finding
pub async fn explain_finding(
    model: &str,
    mut req: FindingExplanationRequest,
) -> Result<String, String> {
    // Apply redactions to snippet
    if let Some(ref snippet) = req.matched_content {
        req.matched_content = Some(redact_secrets(snippet));
    }

    let prompt = format!(
        "You are an expert Web3 and cybersecurity auditor. Explain this security scanner finding:\n\
         - Finding Description: {}\n\
         - Severity: {}\n\
         - Category: {}\n\
         - Rule ID: {}\n\
         - File Path: {}\n\
         - Matched Content (Redacted): {:?}\n\
         - Basic Recommendation: {}\n\n\
         Provide a clear explanation covering:\n\
         1. **Risk Analysis**: Why this is dangerous and how it could be abused.\n\
         2. **Remediation**: Practical, safe steps to fix the issue.\n\
         3. **False Positive Check**: How to verify if this is a false alarm.\n\
         Use professional, clear formatting.",
        req.description, req.severity, req.category, req.pattern_id, req.file_path, req.matched_content, req.recommendation
    );

    execute_ai_query(model, &prompt).await
}

/// Generate executive report summary
pub async fn generate_executive_summary_ai(
    model: &str,
    req: ExecutiveSummaryRequest,
) -> Result<String, String> {
    let mut findings_list = String::new();
    for (i, f) in req.findings_summary.iter().enumerate() {
        findings_list.push_str(&format!(
            "{}. [{}] {} in file {}\n",
            i + 1,
            f.severity.to_uppercase(),
            f.description,
            f.file_path
        ));
    }

    let prompt = format!(
        "You are a Senior Cybersecurity Director. Generate a professional executive summary for the following scan report:\n\
         - Project Name: {}\n\
         - Files Scanned: {}\n\
         - Total Findings: {}\n\
         - Overall Risk Score: {}/100\n\n\
         Detailed Findings:\n\
         {}\n\n\
         Please provide a concise (150-250 words) executive summary suitable for a client or developer lead report. \
         State the overall posture, highlight critical issues, and state that the scanner completed the analysis locally. \
         Do not include markdown headers, keep it as a clean paragraph.",
        req.project_name, req.total_files, req.total_findings, req.risk_score, findings_list
    );

    execute_ai_query(model, &prompt).await
}

/// Route AI query to correct provider keys/endpoints
async fn execute_ai_query(model: &str, prompt: &str) -> Result<String, String> {
    let keys = get_api_keys()?;

    match model {
        "mock" => {
            // Local Mock fallback
            Ok("This is a local mock AI response for testing. Enabling AI and choosing a valid model will trigger active explanations.".to_string())
        }
        // Gemini Models
        "gemini-1.5-flash" | "gemini-1.5-pro" | "gemini-2.0-flash" => {
            if keys.gemini_api_key.trim().is_empty() {
                return Err("Gemini API key is not configured by the developer.".into());
            }
            call_gemini(&keys.gemini_api_key, model, prompt).await
        }
        // OpenAI Models
        "gpt-4o" | "gpt-4o-mini" | "gpt-3.5-turbo" => {
            if keys.openai_api_key.trim().is_empty() {
                return Err("OpenAI API key is not configured by the developer.".into());
            }
            call_openai_compatible("https://api.openai.com/v1", &keys.openai_api_key, model, prompt).await
        }
        // NVIDIA NIM Models
        "meta/llama3-70b-instruct" | "mistralai/mixtral-8x22b-instruct" => {
            if keys.nvidia_api_key.trim().is_empty() {
                return Err("NVIDIA NIM API key is not configured by the developer.".into());
            }
            let model_name = match model {
                "meta/llama3-70b-instruct" => "meta/llama3-70b-instruct",
                _ => "mistralai/mixtral-8x22b-instruct",
            };
            call_openai_compatible("https://integrate.api.nvidia.com/v1", &keys.nvidia_api_key, model_name, prompt).await
        }
        // OpenRouter Models
        "anthropic/claude-3.5-sonnet" | "meta/llama-3.1-405b-instruct" => {
            if keys.openrouter_api_key.trim().is_empty() {
                return Err("OpenRouter API key is not configured by the developer.".into());
            }
            call_openai_compatible("https://openrouter.ai/api/v1", &keys.openrouter_api_key, model, prompt).await
        }
        _ => Err(format!("Unsupported or unrecognized model selected: {}", model)),
    }
}

/// AI Advisory Analysis response — does NOT contain or modify score/severity/grade/risk
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AiAnalysisResponse {
    pub summary: String,
    pub recommendations: Vec<String>,
    pub confidence: String,
}

/// Generate an AI advisory analysis from an already-completed scan result.
///
/// SECURITY RULES:
/// - This function NEVER modifies the risk score, severity, grade, or risk level
/// - It only sends finding metadata (descriptions, file paths, redacted matched content)
/// - It does NOT send full source code to any external server
/// - The output is purely advisory and must be clearly labeled as such
pub async fn ai_risk_analysis(
    model: &str,
    scan_name: &str,
    risk_score: u32,
    risk_level: &str,
    findings: Vec<FindingSummaryInfo>,
) -> Result<AiAnalysisResponse, String> {
    if model == "mock" {
        return Ok(AiAnalysisResponse {
            summary: format!(
                "Advisory analysis for '{}': The scan detected {} findings with a deterministic risk score of {}/100 ({}).",
                scan_name,
                findings.len(),
                risk_score,
                risk_level
            ),
            recommendations: vec![
                "Review all Critical and High severity findings immediately.".to_string(),
                "Check for legitimate use cases before removing flagged patterns.".to_string(),
                "Run the scan again after applying fixes to verify improvements.".to_string(),
            ],
            confidence: "mock".to_string(),
        });
    }

    // Build prompt — only send finding metadata, never full source code
    let mut findings_text = String::new();
    for (i, f) in findings.iter().enumerate().take(30) {
        let redacted_path = redact_secrets(&f.file_path);
        findings_text.push_str(&format!(
            "{}. [{}] {} — File: {}\n",
            i + 1,
            f.severity.to_uppercase(),
            f.description,
            redacted_path
        ));
    }

    let prompt = format!(
        r#"You are ShadowRepo Shield AI Advisor. Analyze these security scan findings and provide advisory guidance.

IMPORTANT RULES:
- You are providing ADVISORY analysis only
- You must NOT assign, modify, or suggest changes to the numeric risk score, severity levels, or grade
- The risk score of {score}/100 ({level}) was determined by the deterministic scanner and is final
- Focus on explaining the findings and suggesting practical fixes

Project: {name}
Deterministic Risk Score: {score}/100 ({level})
Total Findings: {count}

Findings:
{findings}

Provide your response in this exact format:

SUMMARY: A 2-3 sentence advisory summary of the security posture.

RECOMMENDATIONS:
1. [First actionable recommendation]
2. [Second actionable recommendation]
3. [Third actionable recommendation]

CONFIDENCE: [low/medium/high] — how confident you are in the advisory analysis."#,
        score = risk_score,
        level = risk_level,
        name = scan_name,
        count = findings.len(),
        findings = findings_text,
    );

    let raw_response = execute_ai_query(model, &prompt).await?;

    // Parse response into structured format
    let mut summary = String::new();
    let mut recommendations = Vec::new();
    let mut confidence = "medium".to_string();
    let mut section = "";

    for line in raw_response.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("SUMMARY:") {
            section = "summary";
            summary = trimmed.trim_start_matches("SUMMARY:").trim().to_string();
        } else if trimmed.starts_with("RECOMMENDATIONS:") {
            section = "recommendations";
        } else if trimmed.starts_with("CONFIDENCE:") {
            section = "confidence";
            let conf = trimmed.trim_start_matches("CONFIDENCE:").trim().to_lowercase();
            confidence = if conf.contains("high") {
                "high".to_string()
            } else if conf.contains("low") {
                "low".to_string()
            } else {
                "medium".to_string()
            };
        } else {
            match section {
                "summary" => {
                    if !trimmed.is_empty() {
                        if !summary.is_empty() {
                            summary.push(' ');
                        }
                        summary.push_str(trimmed);
                    }
                }
                "recommendations" => {
                    if !trimmed.is_empty() {
                        let clean = trimmed.trim_start_matches(|c: char| c.is_ascii_digit() || c == '.' || c == '-' || c == ' ');
                        if !clean.is_empty() {
                            recommendations.push(clean.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Fallback if parsing didn't work well
    if summary.is_empty() {
        summary = raw_response.chars().take(500).collect::<String>();
    }
    if recommendations.is_empty() {
        recommendations.push("Review all flagged findings and assess their relevance to your project.".to_string());
    }

    Ok(AiAnalysisResponse {
        summary,
        recommendations,
        confidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_redactions() {
        let input = "const key = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';";
        let redacted = redact_secrets(input);
        assert!(redacted.contains("[REDACTED_PRIVATE_KEY]"));
        assert!(!redacted.contains("0x1234567890"));

        let env_line = "PRIVATE_KEY=hello_world_secret";
        let redacted_env = redact_secrets(env_line);
        assert!(redacted_env.contains("PRIVATE_KEY: [REDACTED_SECRET]"));

        let mnemonic = "apple banana cherry dog elephant fox grape horse ink juice king lemon";
        let redacted_mnemonic = redact_secrets(mnemonic);
        assert!(redacted_mnemonic.contains("[REDACTED_MNEMONIC]"));
    }
}
