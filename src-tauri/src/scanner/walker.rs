use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Directories to skip during scanning
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "build",
    "dist",
    "cache",
    ".cache",
    "target",
    "__pycache__",
    ".next",
    ".nuxt",
    "vendor",
    "coverage",
    ".nyc_output",
    "out",
    ".svn",
    ".hg",
];

/// Subdirectories inside .git to skip (scan .git/hooks but not objects/refs)
const GIT_SKIP_SUBDIRS: &[&str] = &[
    "objects",
    "refs",
    "logs",
    "info",
    "packed-refs",
    "COMMIT_EDITMSG",
];

/// Binary file extensions to skip
const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp", "avif",
    "mp3", "mp4", "avi", "mov", "mkv", "wav", "flac", "ogg",
    "zip", "tar", "gz", "bz2", "xz", "7z", "rar",
    "exe", "dll", "so", "dylib", "bin", "o", "obj",
    "woff", "woff2", "ttf", "otf", "eot",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "pyc", "pyo", "class", "jar",
    "wasm", "map",
    "lock",
];

/// Maximum file size to scan (5 MB)
const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024;

/// Walk a directory and return all scannable file paths
pub fn walk_directory(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !should_skip_dir(e, root))
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();

        // Skip binary files by extension
        if is_binary_extension(path) {
            continue;
        }

        // Skip files larger than MAX_FILE_SIZE
        if let Ok(metadata) = entry.metadata() {
            if metadata.len() > MAX_FILE_SIZE {
                continue;
            }
        }

        files.push(path.to_path_buf());
    }

    files
}

/// Check if a directory entry should be skipped
fn should_skip_dir(entry: &walkdir::DirEntry, root: &Path) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    let name = entry.file_name().to_string_lossy();

    // Standard skip dirs
    if SKIP_DIRS.iter().any(|skip| name == *skip) {
        return true;
    }

    // For .git directory: allow .git/hooks but skip other subdirs
    let rel = entry.path().strip_prefix(root).unwrap_or(entry.path());
    let rel_str = rel.to_string_lossy().replace('\\', "/");

    // If we're inside .git/, skip certain subdirs
    if rel_str.starts_with(".git/") {
        let sub = rel_str.trim_start_matches(".git/");
        if GIT_SKIP_SUBDIRS.iter().any(|s| sub.starts_with(s)) {
            return true;
        }
    }

    false
}

/// Check if a file has a binary extension
fn is_binary_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| BINARY_EXTENSIONS.contains(&ext.to_lowercase().as_str()))
        .unwrap_or(false)
}

/// Check if a filename matches suspicious file patterns
pub fn is_suspicious_filename(path: &Path) -> Option<&'static str> {
    let filename = path.file_name()?.to_str()?.to_lowercase();

    match filename.as_str() {
        ".env" | ".env.local" | ".env.production" | ".env.development" => {
            Some("Sensitive environment file detected")
        }
        "wallet.json" => Some("Wallet file detected"),
        "keystore.json" => Some("Keystore file detected"),
        "private.key" | "private.pem" => Some("Private key file detected"),
        "mnemonic.txt" => Some("Mnemonic phrase file detected"),
        "secret.txt" | "secrets.txt" => Some("Secrets file detected"),
        ".gitlab-ci.yml" | ".gitlab-ci.yaml" => Some("GitLab CI pipeline configuration detected"),
        "jenkinsfile" => Some("Jenkinsfile pipeline configuration detected"),
        _ => None,
    }
}

/// Check if a file is a shell script (by extension)
pub fn is_shell_script(path: &Path) -> Option<&'static str> {
    let ext = path.extension()?.to_str()?.to_lowercase();
    match ext.as_str() {
        "sh" => Some("Shell script file detected (.sh)"),
        "bat" => Some("Windows batch script file detected (.bat)"),
        "cmd" => Some("Windows command script file detected (.cmd)"),
        "ps1" => Some("PowerShell script file detected (.ps1)"),
        _ => None,
    }
}

/// Check if a file is in a hook or CI/CD path
pub fn is_hook_or_ci_path(path: &Path) -> Option<&'static str> {
    let path_str = path.to_string_lossy().replace('\\', "/");

    if path_str.contains(".husky/") {
        return Some("Husky git hook script detected");
    }
    if path_str.contains(".git/hooks/") {
        return Some("Git hook script detected");
    }
    if path_str.contains(".github/workflows/") {
        return Some("GitHub Actions workflow detected");
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_binary_extension_detection() {
        assert!(is_binary_extension(Path::new("image.png")));
        assert!(is_binary_extension(Path::new("app.exe")));
        assert!(!is_binary_extension(Path::new("code.rs")));
        assert!(!is_binary_extension(Path::new("index.js")));
        assert!(!is_binary_extension(Path::new("contract.sol")));
    }

    #[test]
    fn test_suspicious_filename() {
        assert!(is_suspicious_filename(Path::new(".env")).is_some());
        assert!(is_suspicious_filename(Path::new("wallet.json")).is_some());
        assert!(is_suspicious_filename(Path::new("mnemonic.txt")).is_some());
        assert!(is_suspicious_filename(Path::new("package.json")).is_none());
        assert!(is_suspicious_filename(Path::new("index.ts")).is_none());
    }

    #[test]
    fn test_shell_script_detection() {
        assert!(is_shell_script(Path::new("setup.sh")).is_some());
        assert!(is_shell_script(Path::new("build.bat")).is_some());
        assert!(is_shell_script(Path::new("run.cmd")).is_some());
        assert!(is_shell_script(Path::new("script.ps1")).is_some());
        assert!(is_shell_script(Path::new("index.js")).is_none());
    }

    #[test]
    fn test_hook_ci_path() {
        assert!(is_hook_or_ci_path(Path::new(".husky/pre-commit")).is_some());
        assert!(is_hook_or_ci_path(Path::new(".git/hooks/pre-push")).is_some());
        assert!(is_hook_or_ci_path(Path::new(".github/workflows/ci.yml")).is_some());
        assert!(is_hook_or_ci_path(Path::new("src/main.rs")).is_none());
    }
}
