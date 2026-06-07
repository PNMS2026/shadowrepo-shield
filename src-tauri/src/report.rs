use std::fs::File;
use std::io::Write;
use std::path::Path;
use super::scanner::types::{ScanResult, Severity};

/// Export scan result to JSON format with enhanced metadata
pub fn export_to_json(result: &ScanResult, output_path: &Path) -> Result<(), String> {
    let json_data = serde_json::to_string_pretty(result)
        .map_err(|e| format!("Failed to serialize report to JSON: {}", e))?;

    let mut file = File::create(output_path)
        .map_err(|e| format!("Failed to create JSON report file: {}", e))?;

    file.write_all(json_data.as_bytes())
        .map_err(|e| format!("Failed to write JSON report file: {}", e))?;

    Ok(())
}

/// Export scan result to a premium dark-themed HTML report with executive summary
pub fn export_to_html(result: &ScanResult, output_path: &Path) -> Result<(), String> {
    let mut html = String::new();

    let (risk_color, risk_bg, risk_label) = match result.risk_score {
        0..=14 => ("#10b981", "rgba(16, 185, 129, 0.08)", "Low Risk"),
        15..=39 => ("#f59e0b", "rgba(245, 158, 11, 0.08)", "Review Recommended"),
        40..=74 => ("#f97316", "rgba(249, 115, 22, 0.08)", "High Risk"),
        _ => ("#ef4444", "rgba(239, 68, 68, 0.08)", "Critical Threat Indicators Found"),
    };

    // Count by severity
    let critical_count = result.findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high_count = result.findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium_count = result.findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low_count = result.findings.iter().filter(|f| f.severity == Severity::Low).count();

    // Executive summary text
    let exec_summary = generate_executive_summary(result, critical_count, high_count, medium_count, low_count);

    // Header & Styles
    html.push_str(&format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShadowRepo Shield Report — {name}</title>
    <style>
        :root {{
            --color-bg: #09090b;
            --color-surface: #18181b;
            --color-border: #27272a;
            --color-text-primary: #f4f4f5;
            --color-text-secondary: #a1a1aa;
            --color-text-muted: #71717a;
            --color-brand: #6366f1;
        }}
        body {{
            background: var(--color-bg);
            color: var(--color-text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            margin: 0;
            padding: 40px 20px;
            line-height: 1.6;
        }}
        .container {{ max-width: 960px; margin: 0 auto; }}
        .header {{
            border-bottom: 1px solid var(--color-border);
            padding-bottom: 24px;
            margin-bottom: 32px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }}
        h1 {{ font-size: 28px; font-weight: 800; margin: 0 0 8px 0; letter-spacing: -0.02em; }}
        h2 {{ font-size: 20px; font-weight: 700; margin: 24px 0 12px 0; }}
        .subtitle {{ color: var(--color-text-secondary); font-size: 14px; margin: 0; }}
        .badge {{
            display: inline-flex; align-items: center; padding: 6px 14px;
            border-radius: 9999px; font-size: 13px; font-weight: 700;
            text-transform: uppercase; letter-spacing: 0.05em;
        }}
        .grid {{ display: grid; grid-template-columns: 260px 1fr; gap: 24px; margin-bottom: 32px; }}
        .card {{ background: var(--color-surface); border: 1px solid var(--color-border); border-radius: 12px; padding: 24px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }}
        .stat-card {{
            background: rgba(255, 255, 255, 0.02); border: 1px solid var(--color-border);
            border-radius: 8px; padding: 16px; display: flex; flex-direction: column;
        }}
        .stat-value {{ font-size: 24px; font-weight: 700; margin-bottom: 4px; }}
        .stat-label {{ font-size: 12px; color: var(--color-text-secondary); }}
        .section-title {{
            font-size: 18px; font-weight: 700; margin: 24px 0 16px 0;
            border-left: 3px solid var(--color-brand); padding-left: 10px;
        }}
        .exec-summary {{
            background: rgba(99, 102, 241, 0.04); border: 1px solid rgba(99, 102, 241, 0.1);
            border-radius: 12px; padding: 20px; margin-bottom: 24px; font-size: 14px;
            line-height: 1.7; color: var(--color-text-secondary);
        }}
        .exec-summary strong {{ color: var(--color-text-primary); }}
        .finding-card {{
            background: var(--color-surface); border: 1px solid var(--color-border);
            border-radius: 12px; padding: 20px; margin-bottom: 16px;
        }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }}
        .finding-title {{ font-weight: 700; font-size: 15px; }}
        .finding-meta {{ font-size: 12px; color: var(--color-text-muted); margin-bottom: 12px; font-family: monospace; }}
        .code-block {{
            background: #09090b; border: 1px solid var(--color-border); border-radius: 6px;
            padding: 12px; font-family: "JetBrains Mono", Courier, monospace;
            font-size: 12px; overflow-x: auto; margin-bottom: 12px; color: #e4e4e7;
        }}
        .recommendation {{
            background: rgba(99, 102, 241, 0.05); border-left: 3px solid var(--color-brand);
            padding: 12px; font-size: 13px; border-radius: 0 6px 6px 0;
        }}
        .severity-summary {{
            display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap;
        }}
        .severity-pill {{
            padding: 6px 14px; border-radius: 8px; font-size: 13px; font-weight: 600;
        }}
        .disclaimer {{
            background: rgba(245, 158, 11, 0.04); border: 1px solid rgba(245, 158, 11, 0.1);
            border-radius: 8px; padding: 16px; font-size: 12px;
            color: var(--color-text-secondary); margin-top: 32px;
        }}
        .privacy-notice {{
            background: rgba(16, 185, 129, 0.04); border: 1px solid rgba(16, 185, 129, 0.1);
            border-radius: 8px; padding: 16px; font-size: 12px;
            color: var(--color-text-secondary); margin-top: 12px; text-align: center;
        }}
        .meta-row {{ font-size: 12px; color: var(--color-text-muted); margin: 4px 0; font-family: monospace; }}
        @media print {{ body {{ background: #fff; color: #111; }} .card, .finding-card {{ border-color: #ccc; background: #f9f9f9; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>ShadowRepo Shield Security Report</h1>
                <p class="subtitle">{name}</p>
                <div class="meta-row">Scan ID: {scan_id}</div>
                <div class="meta-row">Generated: {scan_date}</div>
            </div>
            <div class="badge" style="background: {risk_bg}; color: {risk_color}; border: 1px solid {risk_color}20;">
                {risk_label} — {score}/100
            </div>
        </div>

        <div class="section-title">Executive Summary</div>
        <div class="exec-summary">{exec_summary}</div>

        <div class="grid">
            <div class="card" style="text-align: center;">
                <div style="font-size: 54px; font-weight: 800; color: {risk_color}; line-height: 1;">{score}</div>
                <div style="font-size: 12px; color: var(--color-text-secondary); margin-top: 8px; text-transform: uppercase; letter-spacing: 0.1em;">Security Risk Score</div>
                <div style="font-size: 11px; color: var(--color-text-muted); margin-top: 12px;">0–14 Low · 15–39 Review Recommended · 40–74 High · 75–100 Critical Threat</div>
            </div>
            <div class="card">
                <div class="stats-grid">
                    <div class="stat-card">
                        <span class="stat-value">{total_files}</span>
                        <span class="stat-label">Files Scanned</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-value">{total_findings}</span>
                        <span class="stat-label">Total Findings</span>
                    </div>
                    <div class="stat-card" style="grid-column: span 2;">
                        <span class="stat-value" style="font-size: 11px; font-family: monospace; word-break: break-all;">{repo_hash}</span>
                        <span class="stat-label">Repository Hash (SHA-256)</span>
                    </div>
                    <div class="stat-card" style="grid-column: span 2;">
                        <span class="stat-value" style="font-size: 11px; font-family: monospace; word-break: break-all;">{report_hash}</span>
                        <span class="stat-label">Report Hash (SHA-256)</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="section-title">Severity Breakdown</div>
        <div class="severity-summary">
            <div class="severity-pill" style="background: rgba(239, 68, 68, 0.1); color: #ef4444;">Critical: {critical}</div>
            <div class="severity-pill" style="background: rgba(249, 115, 22, 0.1); color: #f97316;">High: {high}</div>
            <div class="severity-pill" style="background: rgba(245, 158, 11, 0.1); color: #f59e0b;">Medium: {medium}</div>
            <div class="severity-pill" style="background: rgba(16, 185, 129, 0.1); color: #10b981;">Low: {low}</div>
        </div>

        <div class="section-title">Security Findings ({total_findings})</div>
"#,
        name = escape_html(&result.name),
        scan_id = result.id,
        scan_date = result.scan_date,
        risk_bg = risk_bg,
        risk_color = risk_color,
        risk_label = risk_label,
        score = result.risk_score,
        total_files = result.total_files,
        total_findings = result.total_findings,
        repo_hash = result.repo_hash,
        report_hash = result.report_hash,
        exec_summary = exec_summary,
        critical = critical_count,
        high = high_count,
        medium = medium_count,
        low = low_count,
    ));

    // Findings grouped by severity
    let severity_order = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low];
    for sev in &severity_order {
        let sev_findings: Vec<_> = result.findings.iter().filter(|f| &f.severity == sev).collect();
        if sev_findings.is_empty() {
            continue;
        }

        for finding in sev_findings {
            let (f_color, f_bg) = match finding.severity {
                Severity::Critical => ("#ef4444", "rgba(239, 68, 68, 0.08)"),
                Severity::High => ("#f97316", "rgba(249, 115, 22, 0.08)"),
                Severity::Medium => ("#f59e0b", "rgba(245, 158, 11, 0.08)"),
                Severity::Low => ("#10b981", "rgba(16, 185, 129, 0.08)"),
            };

            let line_info = finding
                .line_number
                .map(|l| format!(":L{}", l))
                .unwrap_or_default();

            let code_html = if let Some(ref code) = finding.matched_content {
                format!(r#"<div class="code-block">{}</div>"#, escape_html(code))
            } else {
                "".to_string()
            };

            html.push_str(&format!(
                r#"<div class="finding-card">
                    <div class="finding-header">
                        <div class="finding-title">{}</div>
                        <div class="badge" style="background: {}; color: {}; font-size: 11px; padding: 3px 10px;">{:?}</div>
                    </div>
                    <div class="finding-meta">File: {}{}</div>
                    {}
                    <div class="recommendation">
                        <strong>Recommendation:</strong> {}
                    </div>
                </div>"#,
                escape_html(&finding.description),
                f_bg,
                f_color,
                finding.severity,
                escape_html(&finding.file_path),
                line_info,
                code_html,
                escape_html(&finding.recommendation)
            ));
        }
    }

    if result.findings.is_empty() {
        html.push_str(
            r#"<div class="card" style="text-align: center; padding: 48px;">
                <h3 style="margin: 0 0 8px 0;">No Vulnerabilities Found</h3>
                <p style="color: var(--color-text-secondary); margin: 0; font-size: 14px;">The scanner did not detect any matches against security threat rules.</p>
               </div>"#,
        );
    }

    // Footer
    html.push_str(
        r#"
        <div class="privacy-notice">
            🔒 <strong>Privacy:</strong> No source code was uploaded to any server during this scan. All analysis was performed locally on the user's device. Only cryptographic hashes may be optionally submitted to blockchain for verification.
        </div>
    </div>
</body>
</html>"#,
    );

    let mut file = File::create(output_path)
        .map_err(|e| format!("Failed to create HTML report file: {}", e))?;

    file.write_all(html.as_bytes())
        .map_err(|e| format!("Failed to write HTML report file: {}", e))?;

    Ok(())
}

/// Export scan result to a real PDF document using printpdf
pub fn export_to_pdf(result: &ScanResult, output_path: &Path) -> Result<(), String> {
    use printpdf::*;

    let (doc, page1, layer1) = PdfDocument::new(
        &format!("ShadowRepo Shield Report — {}", result.name),
        Mm(210.0),
        Mm(297.0),
        "Layer 1",
    );

    let font = doc.add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| format!("Failed to load font: {}", e))?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| format!("Failed to load bold font: {}", e))?;
    let font_mono = doc.add_builtin_font(BuiltinFont::Courier)
        .map_err(|e| format!("Failed to load mono font: {}", e))?;

    // Count by severity
    let critical_count = result.findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high_count = result.findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium_count = result.findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low_count = result.findings.iter().filter(|f| f.severity == Severity::Low).count();

    let page_width = 210.0_f32;
    let margin = 25.0_f32;
    let content_width = page_width - 2.0 * margin;
    let _ = content_width; // Available for future use

    // Helper closure state
    struct PdfWriter {
        y: f32,
        page_height: f32,
        margin: f32,
    }

    impl PdfWriter {
        fn new() -> Self {
            Self { y: 272.0, page_height: 297.0, margin: 25.0 }
        }

        fn needs_new_page(&self, lines_needed: f32) -> bool {
            self.y - lines_needed < self.margin
        }
    }

    let mut writer = PdfWriter::new();
    let current_layer = doc.get_page(page1).get_layer(layer1);

    // Title
    current_layer.use_text("SHADOWREPO SHIELD", 18.0, Mm(margin), Mm(writer.y), &font_bold);
    writer.y -= 7.0;
    current_layer.use_text("Security Scan Report", 12.0, Mm(margin), Mm(writer.y), &font);
    writer.y -= 10.0;

    // Separator line
    let line = Line {
        points: vec![
            (Point::new(Mm(margin), Mm(writer.y)), false),
            (Point::new(Mm(page_width - margin), Mm(writer.y)), false),
        ],
        is_closed: false,
    };
    current_layer.add_line(line);
    writer.y -= 8.0;

    // Scan metadata
    let meta_lines = vec![
        format!("Scan Name:     {}", result.name),
        format!("Scan ID:       {}", result.id),
        format!("Scan Date:     {}", result.scan_date),
        format!("Risk Score:    {}/100 ({:?})", result.risk_score, result.risk_level),
        format!("Files Scanned: {}", result.total_files),
        format!("Total Findings: {}", result.total_findings),
    ];

    for line_text in &meta_lines {
        current_layer.use_text(line_text, 9.0, Mm(margin), Mm(writer.y), &font_mono);
        writer.y -= 5.0;
    }
    writer.y -= 3.0;

    // Hashes
    current_layer.use_text("Repo Hash:", 8.0, Mm(margin), Mm(writer.y), &font_bold);
    writer.y -= 4.0;
    current_layer.use_text(&result.repo_hash, 7.0, Mm(margin), Mm(writer.y), &font_mono);
    writer.y -= 5.0;
    current_layer.use_text("Report Hash:", 8.0, Mm(margin), Mm(writer.y), &font_bold);
    writer.y -= 4.0;
    current_layer.use_text(&result.report_hash, 7.0, Mm(margin), Mm(writer.y), &font_mono);
    writer.y -= 8.0;

    // Severity breakdown
    current_layer.use_text("SEVERITY BREAKDOWN", 11.0, Mm(margin), Mm(writer.y), &font_bold);
    writer.y -= 6.0;
    let severity_text = format!(
        "Critical: {}  |  High: {}  |  Medium: {}  |  Low: {}",
        critical_count, high_count, medium_count, low_count
    );
    current_layer.use_text(&severity_text, 9.0, Mm(margin), Mm(writer.y), &font);
    writer.y -= 10.0;

    // Executive summary
    current_layer.use_text("EXECUTIVE SUMMARY", 11.0, Mm(margin), Mm(writer.y), &font_bold);
    writer.y -= 6.0;
    let summary = generate_executive_summary(result, critical_count, high_count, medium_count, low_count);
    for chunk in wrap_text(&summary, 90) {
        if writer.needs_new_page(5.0) { break; }
        current_layer.use_text(&chunk, 8.0, Mm(margin), Mm(writer.y), &font);
        writer.y -= 4.5;
    }
    writer.y -= 6.0;

    // Findings
    current_layer.use_text("FINDINGS", 11.0, Mm(margin), Mm(writer.y), &font_bold);
    writer.y -= 7.0;

    // We'll add findings on subsequent pages as needed
    let mut current_page_layer = current_layer;
    let severity_order = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low];

    for sev in &severity_order {
        let sev_findings: Vec<_> = result.findings.iter().filter(|f| &f.severity == sev).collect();
        if sev_findings.is_empty() { continue; }

        for (i, finding) in sev_findings.iter().enumerate() {
            // Check if we need a new page
            if writer.needs_new_page(30.0) {
                let (new_page, new_layer) = doc.add_page(Mm(210.0), Mm(297.0), &format!("Page {}", i + 2));
                current_page_layer = doc.get_page(new_page).get_layer(new_layer);
                writer.y = 272.0;
                current_page_layer.use_text("ShadowRepo Shield — Findings (continued)", 9.0, Mm(margin), Mm(writer.y), &font);
                writer.y -= 8.0;
            }

            let sev_label = format!("[{:?}]", finding.severity);
            current_page_layer.use_text(&sev_label, 8.0, Mm(margin), Mm(writer.y), &font_bold);

            // Truncate description to fit
            let desc = if finding.description.len() > 80 {
                format!("{}...", &finding.description[..77])
            } else {
                finding.description.clone()
            };
            current_page_layer.use_text(&desc, 8.0, Mm(margin + 18.0), Mm(writer.y), &font);
            writer.y -= 4.5;

            let file_info = match finding.line_number {
                Some(ln) => format!("File: {}:L{}", finding.file_path, ln),
                None => format!("File: {}", finding.file_path),
            };
            let file_info_trunc = if file_info.len() > 95 {
                format!("{}...", &file_info[..92])
            } else {
                file_info
            };
            current_page_layer.use_text(&file_info_trunc, 7.0, Mm(margin + 4.0), Mm(writer.y), &font_mono);
            writer.y -= 4.0;

            // Recommendation (truncated)
            let rec = if finding.recommendation.len() > 95 {
                format!("Rec: {}...", &finding.recommendation[..89])
            } else {
                format!("Rec: {}", finding.recommendation)
            };
            current_page_layer.use_text(&rec, 7.0, Mm(margin + 4.0), Mm(writer.y), &font);
            writer.y -= 6.0;
        }
    }

    if result.findings.is_empty() {
        current_page_layer.use_text("No vulnerabilities detected.", 9.0, Mm(margin), Mm(writer.y), &font);
        writer.y -= 8.0;
    }

    // Disclaimer on final page
    if writer.needs_new_page(25.0) {
        let (new_page, new_layer) = doc.add_page(Mm(210.0), Mm(297.0), "Privacy & Information");
        current_page_layer = doc.get_page(new_page).get_layer(new_layer);
        writer.y = 272.0;
    }

    writer.y -= 6.0;
    let line2 = Line {
        points: vec![
            (Point::new(Mm(margin), Mm(writer.y)), false),
            (Point::new(Mm(page_width - margin), Mm(writer.y)), false),
        ],
        is_closed: false,
    };
    current_page_layer.add_line(line2);
    writer.y -= 6.0;

    current_page_layer.use_text("PRIVACY & INFORMATION", 9.0, Mm(margin), Mm(writer.y), &font_bold);
    writer.y -= 5.0;
    let disclaimer_lines = vec![
        "All results should be reviewed by a qualified security professional.",
        "",
        "PRIVACY: No source code was uploaded to any server during this scan.",
        "All analysis was performed locally on the user's device.",
    ];
    for dl in &disclaimer_lines {
        current_page_layer.use_text(*dl, 7.0, Mm(margin), Mm(writer.y), &font);
        writer.y -= 4.0;
    }

    // Save
    let pdf_file = File::create(output_path)
        .map_err(|e| format!("Failed to create PDF file: {}", e))?;

    doc.save(&mut std::io::BufWriter::new(pdf_file))
        .map_err(|e| format!("Failed to write PDF: {}", e))?;

    Ok(())
}

/// Generate executive summary text
fn generate_executive_summary(result: &ScanResult, critical: usize, high: usize, medium: usize, low: usize) -> String {
    let risk_desc = match result.risk_score {
        0..=14 => "The repository appears to have a low risk profile with minimal security concerns.",
        15..=39 => "The repository has a low-to-moderate risk profile. Security patterns indicate review is recommended.",
        40..=74 => "The repository has a high risk profile. A security review is recommended to evaluate detected patterns.",
        _ => "The repository has critical threat indicators. Immediate review is strongly recommended before proceeding.",
    };

    format!(
        "{} ShadowRepo Shield scanned {} files and identified {} security findings across the repository \"{}\". \
        Breakdown: {} Critical, {} High, {} Medium, {} Low severity issues. \
        The overall security risk score is {}/100 ({:?}). \
        All scanning was performed locally — no source code was uploaded to any server.",
        risk_desc,
        result.total_files,
        result.total_findings,
        result.name,
        critical, high, medium, low,
        result.risk_score,
        result.risk_level
    )
}

/// Helper to escape HTML characters
fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Helper to wrap text to a given character width
fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.len() + word.len() + 1 > max_width {
            if !current_line.is_empty() {
                lines.push(current_line.clone());
                current_line.clear();
            }
        }
        if !current_line.is_empty() {
            current_line.push(' ');
        }
        current_line.push_str(word);
    }
    if !current_line.is_empty() {
        lines.push(current_line);
    }
    lines
}
