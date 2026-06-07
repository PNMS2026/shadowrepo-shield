pub mod commands;
pub mod db;
pub mod report;
pub mod scanner;

use tauri::Manager;
use std::path::PathBuf;

/// Resolve the application base directory inside AppData/Local
pub fn get_app_dir(app_handle: &tauri::AppHandle) -> PathBuf {
    let mut app_dir = app_handle
        .path()
        .local_data_dir()
        .unwrap_or_else(|_| std::env::temp_dir());
    app_dir.push("ShadowRepoShield");
    app_dir
}

/// Simple logger writing to C:\Users\<User>\AppData\Local\ShadowRepoShield\logs\app.log
pub fn log_message(app_handle: &tauri::AppHandle, level: &str, message: &str) {
    let app_dir = get_app_dir(app_handle);
    let log_dir = app_dir.join("logs");
    let _ = std::fs::create_dir_all(&log_dir);

    let log_file = log_dir.join("app.log");
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let log_line = format!("[{}] [{}] {}\n", timestamp, level, message);

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file)
    {
        use std::io::Write;
        let _ = file.write_all(log_line.as_bytes());
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let app_handle = app.handle();
            let app_dir = get_app_dir(app_handle);
            
            // Create directories defensively
            std::fs::create_dir_all(&app_dir).ok();
            std::fs::create_dir_all(app_dir.join("temp")).ok();
            std::fs::create_dir_all(app_dir.join("reports")).ok();
            std::fs::create_dir_all(app_dir.join("logs")).ok();

            let db_path = app_dir.join("shadowrepo_shield.db");

            log_message(app_handle, "INFO", &format!("Initializing database at {:?}", db_path));

            // Initialize DB and run migrations
            if let Err(e) = db::init_db(&db_path) {
                log_message(app_handle, "ERROR", &format!("Database initialization failed: {}", e));
                panic!("Failed to initialize database: {}", e);
            }

            // Populate storage path if empty
            if let Ok(settings) = db::get_settings(&db_path) {
                if settings.storage_path.is_empty() {
                    let reports_dir = app_dir.join("reports");
                    let mut updated = settings;
                    updated.storage_path = reports_dir.to_string_lossy().to_string();
                    let _ = db::update_settings(&db_path, &updated);
                }
            }

            log_message(app_handle, "INFO", "Application setup completed successfully");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::start_scan,
            commands::upload_and_scan,
            commands::get_scan_history,
            commands::get_scan_result,
            commands::delete_scan,
            commands::export_report,
            commands::get_settings,
            commands::update_settings,
            commands::update_blockchain_tx,
            commands::get_dashboard_stats,
            commands::select_folder,
            commands::select_zip_file,
            commands::reveal_in_explorer,
            commands::scan_git_url
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
