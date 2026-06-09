use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tauri_plugin_dialog::DialogExt;
use zip::ZipArchive;

use super::db;
use super::report;
use super::scanner;
use super::scanner::types::{DashboardStats, ScanResult, ScanSummary, Settings};
use super::scanner::types::ScanMode;

/// Helper to get the database path
fn get_db_path(app_handle: &tauri::AppHandle) -> PathBuf {
    let app_dir = super::get_app_dir(app_handle);
    app_dir.join("shadowrepo_shield.db")
}

#[tauri::command]
pub async fn start_scan(
    path: String,
    scan_name: String,
    app_handle: tauri::AppHandle,
) -> Result<ScanResult, String> {
    super::log_message(&app_handle, "INFO", &format!("Starting folder scan for: {}", path));
    let scan_path = Path::new(&path);
    if !scan_path.exists() {
        let err_msg = "Target scanning directory does not exist".to_string();
        super::log_message(&app_handle, "ERROR", &err_msg);
        return Err(err_msg);
    }

    let scan_id = uuid::Uuid::new_v4().to_string();
    let result = scanner::run_scan(scan_path, &scan_id, &scan_name, ScanMode::Local, None);

    let result = match result {
        Ok(r) => r,
        Err(e) => {
            super::log_message(&app_handle, "ERROR", &format!("Folder scan failed: {}", e));
            return Err(e);
        }
    };

    // Save to database
    let db_path = get_db_path(&app_handle);
    if let Err(e) = db::save_scan(&db_path, &result) {
        let err_msg = format!("Database error: {}", e);
        super::log_message(&app_handle, "ERROR", &err_msg);
        return Err(err_msg);
    }

    super::log_message(&app_handle, "INFO", &format!("Folder scan completed successfully. ID: {}", scan_id));
    Ok(result)
}

#[tauri::command]
pub async fn upload_and_scan(
    zip_path: String,
    scan_name: String,
    app_handle: tauri::AppHandle,
) -> Result<ScanResult, String> {
    super::log_message(&app_handle, "INFO", &format!("Starting ZIP scan for: {}", zip_path));
    let zip_file_path = Path::new(&zip_path);
    if !zip_file_path.exists() {
        let err_msg = format!("ZIP file does not exist at path: {}", zip_path);
        super::log_message(&app_handle, "ERROR", &err_msg);
        return Err(err_msg);
    }

    // Create a secure temp directory inside app AppData
    let app_dir = super::get_app_dir(&app_handle);
    let temp_dir = app_dir.join("temp");
    fs::create_dir_all(&temp_dir).map_err(|e| {
        let err_msg = format!("Failed to create temp directory: {}", e);
        super::log_message(&app_handle, "ERROR", &err_msg);
        err_msg
    })?;

    let temp_dir_name = format!("scan-{}", uuid::Uuid::new_v4());
    let extract_to = temp_dir.join(temp_dir_name);
    fs::create_dir_all(&extract_to).map_err(|e| {
        let err_msg = format!("Failed to create extraction path: {}", e);
        super::log_message(&app_handle, "ERROR", &err_msg);
        err_msg
    })?;

    // Extract zip file securely
    let file = fs::File::open(zip_file_path).map_err(|e| {
        let err_msg = format!("Failed to open ZIP file: {}", e);
        super::log_message(&app_handle, "ERROR", &err_msg);
        err_msg
    })?;
    let mut archive = ZipArchive::new(file).map_err(|e| {
        let err_msg = format!("Invalid ZIP archive: {}", e);
        super::log_message(&app_handle, "ERROR", &err_msg);
        err_msg
    })?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| {
            let err_msg = format!("Failed to read ZIP index {}: {}", i, e);
            super::log_message(&app_handle, "ERROR", &err_msg);
            err_msg
        })?;
        let outpath = match file.enclosed_name() {
            Some(path) => extract_to.join(path),
            None => continue, // Skip path traversal attacks
        };

        if file.name().contains("..") {
            continue; // Extra safety check
        }

        if (*file.name()).ends_with('/') {
            fs::create_dir_all(&outpath).ok();
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(p).ok();
                }
            }
            let mut outfile = fs::File::create(&outpath).map_err(|e| {
                let err_msg = format!("Failed to extract file {:?}: {}", outpath, e);
                super::log_message(&app_handle, "ERROR", &err_msg);
                err_msg
            })?;
            std::io::copy(&mut file, &mut outfile).map_err(|e| {
                let err_msg = format!("Failed to write file contents: {}", e);
                super::log_message(&app_handle, "ERROR", &err_msg);
                err_msg
            })?;
        }
    }

    // Run scanner on extracted directory
    let scan_id = uuid::Uuid::new_v4().to_string();
    let scan_result = scanner::run_scan(&extract_to, &scan_id, &scan_name, ScanMode::Local, None);

    // Load settings to check auto-delete flag
    let db_path = get_db_path(&app_handle);
    let settings = db::get_settings(&db_path).unwrap_or_default();

    // Clean up temp directory if enabled
    if settings.auto_delete_temp {
        fs::remove_dir_all(&extract_to).ok();
    }

    let result = match scan_result {
        Ok(r) => r,
        Err(e) => {
            let err_msg = format!("Scan processing failed: {}", e);
            super::log_message(&app_handle, "ERROR", &err_msg);
            return Err(err_msg);
        }
    };

    // Save to database
    if let Err(e) = db::save_scan(&db_path, &result) {
        let err_msg = format!("Database error: {}", e);
        super::log_message(&app_handle, "ERROR", &err_msg);
        return Err(err_msg);
    }

    super::log_message(&app_handle, "INFO", &format!("ZIP scan completed successfully. ID: {}", scan_id));
    Ok(result)
}

#[tauri::command]
pub async fn scan_git_url(
    url: String,
    scan_name: String,
    app_handle: tauri::AppHandle,
) -> Result<ScanResult, String> {
    super::log_message(&app_handle, "INFO", &format!("Starting GitHub URL scan for: {}", url));

    // Validate URL
    let parsed_url = validate_github_url(&url)?;

    // Build ZIP download URL
    let zip_url = format!("{}/archive/refs/heads/main.zip", parsed_url);
    let zip_url_fallback = format!("{}/archive/refs/heads/master.zip", parsed_url);

    super::log_message(&app_handle, "INFO", &format!("Downloading ZIP from: {}", zip_url));

    // Create temp directory
    let app_dir = super::get_app_dir(&app_handle);
    let temp_dir = app_dir.join("temp");
    fs::create_dir_all(&temp_dir).map_err(|e| {
        let err_msg = format!("Failed to create temp directory: {}", e);
        super::log_message(&app_handle, "ERROR", &err_msg);
        err_msg
    })?;

    let temp_zip = temp_dir.join(format!("github-{}.zip", uuid::Uuid::new_v4()));

    // Download ZIP (try main, fallback to master)
    let download_result = download_file(&zip_url, &temp_zip)
        .or_else(|_| {
            super::log_message(&app_handle, "INFO", "main branch not found, trying master...");
            download_file(&zip_url_fallback, &temp_zip)
        });

    match download_result {
        Ok(_) => {
            super::log_message(&app_handle, "INFO", "GitHub ZIP downloaded successfully");
        }
        Err(e) => {
            let err_msg = format!("Failed to download repository: {}. Make sure the URL is a valid public GitHub repository.", e);
            super::log_message(&app_handle, "ERROR", &err_msg);
            return Err(err_msg);
        }
    }

    // Extract ZIP
    let extract_dir = temp_dir.join(format!("scan-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&extract_dir).map_err(|e| {
        let _ = fs::remove_file(&temp_zip);
        format!("Failed to create extraction directory: {}", e)
    })?;

    let file = fs::File::open(&temp_zip).map_err(|e| {
        let _ = fs::remove_file(&temp_zip);
        format!("Failed to open downloaded ZIP: {}", e)
    })?;

    let mut archive = ZipArchive::new(file).map_err(|e| {
        let _ = fs::remove_file(&temp_zip);
        format!("Invalid ZIP archive from GitHub: {}", e)
    })?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| format!("ZIP extraction error: {}", e))?;
        let outpath = match file.enclosed_name() {
            Some(path) => extract_dir.join(path),
            None => continue,
        };
        if file.name().contains("..") { continue; }
        if (*file.name()).ends_with('/') {
            fs::create_dir_all(&outpath).ok();
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() { fs::create_dir_all(p).ok(); }
            }
            let mut outfile = fs::File::create(&outpath)
                .map_err(|e| format!("Failed to extract file: {}", e))?;
            std::io::copy(&mut file, &mut outfile)
                .map_err(|e| format!("Failed to write extracted file: {}", e))?;
        }
    }

    // Remove downloaded ZIP
    fs::remove_file(&temp_zip).ok();

    // Run scanner
    let scan_id = uuid::Uuid::new_v4().to_string();
    let scan_result = scanner::run_scan(&extract_dir, &scan_id, &scan_name, ScanMode::Local, None);

    // Clean up extracted files
    let db_path = get_db_path(&app_handle);
    let settings = db::get_settings(&db_path).unwrap_or_default();
    if settings.auto_delete_temp {
        fs::remove_dir_all(&extract_dir).ok();
    }

    let result = match scan_result {
        Ok(r) => r,
        Err(e) => {
            let err_msg = format!("Scan processing failed: {}", e);
            super::log_message(&app_handle, "ERROR", &err_msg);
            return Err(err_msg);
        }
    };

    // Save to database
    if let Err(e) = db::save_scan(&db_path, &result) {
        let err_msg = format!("Database error: {}", e);
        super::log_message(&app_handle, "ERROR", &err_msg);
        return Err(err_msg);
    }

    super::log_message(&app_handle, "INFO", &format!("GitHub URL scan completed successfully. ID: {}", scan_id));
    Ok(result)
}

/// Validate a GitHub URL and return the normalized base URL
fn validate_github_url(url: &str) -> Result<String, String> {
    let url = url.trim();

    // Block dangerous protocols
    let blocked_protocols = ["file://", "ftp://", "ssh://", "git://", "data:", "javascript:"];
    for proto in &blocked_protocols {
        if url.to_lowercase().starts_with(proto) {
            return Err(format!("Unsupported protocol: {}. Only HTTPS GitHub URLs are supported.", proto));
        }
    }

    // Must be HTTPS
    if !url.starts_with("https://") {
        return Err("Only HTTPS URLs are supported. Example: https://github.com/owner/repo".to_string());
    }

    // Must be github.com
    if !url.contains("github.com/") {
        return Err("Only GitHub repositories are supported. Enter a URL like: https://github.com/owner/repo".to_string());
    }

    // Extract owner/repo
    let after_github = url.split("github.com/").nth(1)
        .ok_or("Invalid GitHub URL format")?;

    let parts: Vec<&str> = after_github.trim_end_matches('/').trim_end_matches(".git").split('/').collect();
    if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err("Invalid GitHub URL. Expected format: https://github.com/owner/repo".to_string());
    }

    let owner = parts[0];
    let repo = parts[1];

    // Validate characters
    if !owner.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return Err("Invalid GitHub owner name".to_string());
    }
    if !repo.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return Err("Invalid GitHub repository name".to_string());
    }

    Ok(format!("https://github.com/{}/{}", owner, repo))
}

/// Download a file from a URL to a local path
fn download_file(url: &str, dest: &Path) -> Result<(), String> {
    let response = reqwest::blocking::get(url)
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("HTTP {} — {}", response.status(), url));
    }

    let bytes = response.bytes()
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    let mut file = fs::File::create(dest)
        .map_err(|e| format!("Failed to create file: {}", e))?;

    file.write_all(&bytes)
        .map_err(|e| format!("Failed to write file: {}", e))?;

    Ok(())
}

#[tauri::command]
pub async fn get_scan_history(app_handle: tauri::AppHandle) -> Result<Vec<ScanSummary>, String> {
    let db_path = get_db_path(&app_handle);
    db::get_scan_history(&db_path).map_err(|e| format!("Database error: {}", e))
}

#[tauri::command]
pub async fn get_scan_result(
    scan_id: String,
    app_handle: tauri::AppHandle,
) -> Result<ScanResult, String> {
    let db_path = get_db_path(&app_handle);
    let scan = db::get_scan(&db_path, &scan_id).map_err(|e| format!("Database error: {}", e))?;
    scan.ok_or_else(|| "Scan not found".to_string())
}

#[tauri::command]
pub async fn delete_scan(scan_id: String, app_handle: tauri::AppHandle) -> Result<bool, String> {
    let db_path = get_db_path(&app_handle);
    db::delete_scan(&db_path, &scan_id)
        .map(|_| true)
        .map_err(|e| format!("Database error: {}", e))
}

#[tauri::command]
pub async fn export_report(
    scan_id: String,
    format: String,
    app_handle: tauri::AppHandle,
) -> Result<String, String> {
    let db_path = get_db_path(&app_handle);
    let scan = db::get_scan(&db_path, &scan_id)
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "Scan result not found".to_string())?;

    let settings = db::get_settings(&db_path).unwrap_or_default();
    let export_dir = Path::new(&settings.storage_path);
    fs::create_dir_all(export_dir).map_err(|e| format!("Failed to create export directory: {}", e))?;

    let filename = format!("report-{}.{}", scan_id, format);
    let file_path = export_dir.join(filename);

    match format.as_str() {
        "json" => report::export_to_json(&scan, &file_path)?,
        "html" => report::export_to_html(&scan, &file_path)?,
        "pdf" => report::export_to_pdf(&scan, &file_path)?,
        _ => return Err("Unsupported report format".to_string()),
    }

    Ok(file_path.to_string_lossy().to_string())
}

#[tauri::command]
pub async fn get_settings(app_handle: tauri::AppHandle) -> Result<Settings, String> {
    let db_path = get_db_path(&app_handle);
    db::get_settings(&db_path).map_err(|e| format!("Database error: {}", e))
}

#[tauri::command]
pub async fn update_settings(
    settings: Settings,
    app_handle: tauri::AppHandle,
) -> Result<bool, String> {
    let db_path = get_db_path(&app_handle);
    db::update_settings(&db_path, &settings)
        .map(|_| true)
        .map_err(|e| format!("Database error: {}", e))
}

#[tauri::command]
pub async fn update_blockchain_tx(
    scan_id: String,
    tx_hash: String,
    network: String,
    app_handle: tauri::AppHandle,
) -> Result<bool, String> {
    let db_path = get_db_path(&app_handle);
    db::update_blockchain_tx(&db_path, &scan_id, &tx_hash, &network)
        .map(|_| true)
        .map_err(|e| format!("Database error: {}", e))
}

#[tauri::command]
pub async fn get_dashboard_stats(app_handle: tauri::AppHandle) -> Result<DashboardStats, String> {
    let db_path = get_db_path(&app_handle);
    db::get_dashboard_stats(&db_path).map_err(|e| format!("Database error: {}", e))
}

#[tauri::command]
pub async fn select_folder(app_handle: tauri::AppHandle) -> Result<Option<String>, String> {
    let folder = app_handle
        .dialog()
        .file()
        .blocking_pick_folder();

    match folder {
        Some(file_path) => {
            let path_buf = file_path.into_path().map_err(|e| e.to_string())?;
            super::log_message(&app_handle, "INFO", &format!("Folder selected via dialog: {:?}", path_buf));
            Ok(Some(path_buf.to_string_lossy().to_string()))
        }
        None => {
            super::log_message(&app_handle, "INFO", "Folder selection dialog cancelled");
            Ok(None)
        }
    }
}

#[tauri::command]
pub async fn select_zip_file(app_handle: tauri::AppHandle) -> Result<Option<String>, String> {
    let file = app_handle
        .dialog()
        .file()
        .add_filter("ZIP Archives", &["zip"])
        .blocking_pick_file();

    match file {
        Some(file_path) => {
            let path_buf = file_path.into_path().map_err(|e| e.to_string())?;
            super::log_message(&app_handle, "INFO", &format!("ZIP file selected via dialog: {:?}", path_buf));
            Ok(Some(path_buf.to_string_lossy().to_string()))
        }
        None => {
            super::log_message(&app_handle, "INFO", "ZIP file selection dialog cancelled");
            Ok(None)
        }
    }
}

#[tauri::command]
pub async fn reveal_in_explorer(path: String, app_handle: tauri::AppHandle) -> Result<(), String> {
    super::log_message(&app_handle, "INFO", &format!("Revealing path in explorer: {}", path));
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        Command::new("explorer")
            .arg("/select,")
            .arg(&path)
            .spawn()
            .map_err(|e| {
                let err_msg = format!("Failed to spawn explorer: {}", e);
                super::log_message(&app_handle, "ERROR", &err_msg);
                err_msg
            })?;
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let parent = Path::new(&path).parent().unwrap_or(Path::new("/"));
        Command::new("xdg-open")
            .arg(parent)
            .spawn()
            .map_err(|e| {
                let err_msg = format!("Failed to open directory with xdg-open: {}", e);
                super::log_message(&app_handle, "ERROR", &err_msg);
                err_msg
            })?;
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let parent = Path::new(&path).parent().unwrap_or(Path::new("/"));
        Command::new("open")
            .arg(parent)
            .spawn()
            .map_err(|e| {
                let err_msg = format!("Failed to open directory: {}", e);
                super::log_message(&app_handle, "ERROR", &err_msg);
                err_msg
            })?;
        Ok(())
    }
}

#[tauri::command]
pub async fn explain_finding(
    model: String,
    finding: scanner::ai::FindingExplanationRequest,
    app_handle: tauri::AppHandle,
) -> Result<String, String> {
    super::log_message(&app_handle, "INFO", &format!("AI Explanation requested using model: {}", model));
    scanner::ai::explain_finding(&model, finding).await
}

#[tauri::command]
pub async fn generate_executive_summary(
    model: String,
    req: scanner::ai::ExecutiveSummaryRequest,
    app_handle: tauri::AppHandle,
) -> Result<String, String> {
    super::log_message(&app_handle, "INFO", &format!("AI Executive Summary requested using model: {}", model));
    scanner::ai::generate_executive_summary_ai(&model, req).await
}

#[tauri::command]
pub async fn verify_report_hash(
    scan_id: String,
    app_handle: tauri::AppHandle,
) -> Result<String, String> {
    super::log_message(&app_handle, "INFO", &format!("Report integrity check requested for scan: {}", scan_id));

    let db_path = get_db_path(&app_handle);
    let scan = db::get_scan(&db_path, &scan_id)
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "Scan not found".to_string())?;

    // Recompute report hash from the stored scan data
    // We must temporarily clear report_hash to match original computation
    let mut temp_result = scan.clone();
    temp_result.report_hash = String::new();

    let report_json = serde_json::to_string(&temp_result)
        .map_err(|e| format!("Failed to serialize result: {}", e))?;
    let recomputed_hash = scanner::hasher::hash_string(&report_json);

    if recomputed_hash == scan.report_hash {
        super::log_message(&app_handle, "INFO", "Report integrity check: PASSED");
        Ok("Integrity check passed — Report hash valid".to_string())
    } else {
        super::log_message(&app_handle, "WARN", "Report integrity check: FAILED — Hash mismatch");
        Ok("Integrity check failed — Hash mismatch. Report data may have been modified after generation.".to_string())
    }
}

/// AI advisory analysis — does NOT modify score, severity, grade, or risk level
#[tauri::command]
pub async fn request_ai_analysis(
    model: String,
    scan_name: String,
    risk_score: u32,
    risk_level: String,
    findings: Vec<scanner::ai::FindingSummaryInfo>,
    app_handle: tauri::AppHandle,
) -> Result<scanner::ai::AiAnalysisResponse, String> {
    super::log_message(&app_handle, "INFO", &format!(
        "AI advisory analysis requested for '{}' using model: {} (advisory only — does not affect score)",
        scan_name, model
    ));
    scanner::ai::ai_risk_analysis(&model, &scan_name, risk_score, &risk_level, findings).await
}

