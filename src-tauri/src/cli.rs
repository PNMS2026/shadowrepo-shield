//! ShadowRepo Shield CLI — Standalone scanner for CI/CD pipelines
//!
//! This binary runs the same deterministic scanner engine used by the desktop app.
//! It is designed to be executed by GitHub Actions or other CI/CD systems.
//!
//! Usage:
//!   shadowrepo-cli <directory_path> [--name <scan_name>] [--mode local|verified] [--output <path>]
//!
//! Exit codes:
//!   0 = Low risk (score 0-20)
//!   1 = Review recommended (score 21-49)
//!   2 = High risk (score 50-79)
//!   3 = Critical threat indicators found (score 80-100)
//!
//! Security rules:
//! - No source code is uploaded to any external server
//! - AI features are disabled in CLI mode
//! - Score is always computed deterministically by the regex engine
//! - The scanner_signature field is set from the environment (e.g., GITHUB_RUN_ID)
//! - Verified mode (--mode verified) is only trusted when executed by the official
//!   GitHub Action using the official release binary and checksum verification.
//!   A locally executed --mode verified scan must not be treated as public proof.

use std::path::Path;
use std::process;

// Import the scanner library (same engine as desktop app)
use shadowrepo_shield_lib::scanner;
use shadowrepo_shield_lib::scanner::types::ScanMode;
use shadowrepo_shield_lib::report;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_usage();
        process::exit(if args.len() < 2 { 1 } else { 0 });
    }

    let scan_path_str = &args[1];
    let scan_path = Path::new(scan_path_str);

    if !scan_path.exists() {
        eprintln!("Error: Directory does not exist: {}", scan_path_str);
        process::exit(1);
    }

    if !scan_path.is_dir() {
        eprintln!("Error: Path is not a directory: {}", scan_path_str);
        process::exit(1);
    }

    // Parse optional arguments
    let mut scan_name = scan_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unnamed")
        .to_string();
    let mut scan_mode = ScanMode::Local;
    let mut output_path: Option<String> = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                i += 1;
                if i < args.len() {
                    scan_name = args[i].clone();
                }
            }
            "--mode" => {
                i += 1;
                if i < args.len() {
                    scan_mode = match args[i].as_str() {
                        "verified" => ScanMode::Verified,
                        "local" => ScanMode::Local,
                        other => {
                            eprintln!("Warning: Unknown scan mode '{}', defaulting to 'local'", other);
                            ScanMode::Local
                        }
                    };
                }
            }
            "--output" | "-o" => {
                i += 1;
                if i < args.len() {
                    output_path = Some(args[i].clone());
                }
            }
            other => {
                eprintln!("Warning: Unknown argument '{}', ignoring", other);
            }
        }
        i += 1;
    }

    // Build scanner signature from CI environment variables (if available)
    let scanner_signature = build_scanner_signature();

    let scan_id = uuid::Uuid::new_v4().to_string();

    eprintln!("ShadowRepo Shield CLI v1.4.0");
    eprintln!("Scanning: {}", scan_path_str);
    eprintln!("Scan mode: {:?}", scan_mode);
    eprintln!("Scan ID: {}", scan_id);
    eprintln!();

    // Run the deterministic scanner (same engine as desktop app)
    let result = match scanner::run_scan(scan_path, &scan_id, &scan_name, scan_mode, scanner_signature) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: Scan failed — {}", e);
            process::exit(1);
        }
    };

    eprintln!("Scan complete.");
    eprintln!("  Files scanned: {}", result.total_files);
    eprintln!("  Findings: {}", result.total_findings);
    eprintln!("  Risk score: {}/100", result.risk_score);
    eprintln!("  Risk level: {:?}", result.risk_level);
    eprintln!("  Repo hash: {}", result.repo_hash);
    eprintln!("  Report hash: {}", result.report_hash);
    eprintln!();

    // Output JSON report
    if let Some(ref out_path) = output_path {
        let out = Path::new(out_path);

        // Determine format from extension
        if out_path.ends_with(".html") {
            if let Err(e) = report::export_to_html(&result, out) {
                eprintln!("Error: Failed to export HTML report — {}", e);
                process::exit(1);
            }
            eprintln!("HTML report saved to: {}", out_path);
        } else if out_path.ends_with(".pdf") {
            if let Err(e) = report::export_to_pdf(&result, out) {
                eprintln!("Error: Failed to export PDF report — {}", e);
                process::exit(1);
            }
            eprintln!("PDF report saved to: {}", out_path);
        } else {
            // Default to JSON
            if let Err(e) = report::export_to_json(&result, out) {
                eprintln!("Error: Failed to export JSON report — {}", e);
                process::exit(1);
            }
            eprintln!("JSON report saved to: {}", out_path);
        }
    } else {
        // Print JSON to stdout
        match serde_json::to_string_pretty(&result) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!("Error: Failed to serialize result — {}", e);
                process::exit(1);
            }
        }
    }

    // Exit with risk-based code
    let exit_code = match result.risk_score {
        0..=20 => 0,
        21..=49 => 1,
        50..=79 => 2,
        _ => 3,
    };

    process::exit(exit_code);
}

/// Build a scanner signature from CI environment variables
/// This identifies which CI runner produced the scan but does NOT
/// constitute cryptographic signing or attestation
fn build_scanner_signature() -> Option<String> {
    // GitHub Actions environment
    if let Ok(run_id) = std::env::var("GITHUB_RUN_ID") {
        let repo = std::env::var("GITHUB_REPOSITORY").unwrap_or_default();
        let sha = std::env::var("GITHUB_SHA").unwrap_or_default();
        let actor = std::env::var("GITHUB_ACTOR").unwrap_or_default();
        return Some(format!(
            "github-action:repo={},run={},sha={},actor={}",
            repo, run_id, sha, actor
        ));
    }

    // GitLab CI environment
    if let Ok(job_id) = std::env::var("CI_JOB_ID") {
        let project = std::env::var("CI_PROJECT_PATH").unwrap_or_default();
        return Some(format!("gitlab-ci:project={},job={}", project, job_id));
    }

    // Generic CI detection
    if std::env::var("CI").is_ok() {
        return Some("ci:unknown-runner".to_string());
    }

    None
}

fn print_usage() {
    eprintln!("ShadowRepo Shield CLI v1.4.0");
    eprintln!("Local-first security scanner for Web3 repositories");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("    shadowrepo-cli <directory_path> [OPTIONS]");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("    --name <name>       Name for the scan (default: directory name)");
    eprintln!("    --mode <mode>       Scan mode: 'local' or 'verified' (default: local)");
    eprintln!("                        Note: verified scans are only authoritative when executed");
    eprintln!("                        by the official GitHub Action runner using checksum validation.");
    eprintln!("    --output, -o <path> Output report file path (.json, .html, or .pdf)");
    eprintln!("    --help, -h          Show this help message");
    eprintln!();
    eprintln!("EXIT CODES:");
    eprintln!("    0 = Low risk (score 0-20)");
    eprintln!("    1 = Review recommended (score 21-49)");
    eprintln!("    2 = High risk (score 50-79)");
    eprintln!("    3 = Critical threat indicators found (score 80-100)");
    eprintln!();
    eprintln!("SECURITY:");
    eprintln!("    - No source code is uploaded to any external server");
    eprintln!("    - Score is computed deterministically by the regex engine");
    eprintln!("    - AI features are disabled in CLI mode");
    eprintln!("    - Verified mode (--mode verified) is only trusted when executed by the");
    eprintln!("      official GitHub Action using the official release binary and checksum");
    eprintln!("      verification. A locally executed scan must not be treated as public proof.");
}
