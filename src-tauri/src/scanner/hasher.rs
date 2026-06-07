use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Compute SHA-256 hash of a file using buffered reading
pub fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Compute SHA-256 hash of a string (for report hashing)
pub fn hash_string(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute a combined repo hash from sorted file paths and their individual hashes
pub fn compute_repo_hash(file_hashes: &mut Vec<(String, String)>) -> String {
    // Sort by file path for deterministic hashing
    file_hashes.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha256::new();
    for (path, hash) in file_hashes.iter() {
        hasher.update(path.as_bytes());
        hasher.update(b":");
        hasher.update(hash.as_bytes());
        hasher.update(b"\n");
    }

    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_string() {
        let hash = hash_string("hello world");
        assert_eq!(hash.len(), 64); // SHA-256 produces 64 hex chars
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_compute_repo_hash_deterministic() {
        let mut hashes1 = vec![
            ("file_b.txt".into(), "hash_b".into()),
            ("file_a.txt".into(), "hash_a".into()),
        ];
        let mut hashes2 = vec![
            ("file_a.txt".into(), "hash_a".into()),
            ("file_b.txt".into(), "hash_b".into()),
        ];

        let hash1 = compute_repo_hash(&mut hashes1);
        let hash2 = compute_repo_hash(&mut hashes2);

        assert_eq!(hash1, hash2, "Repo hash should be deterministic regardless of input order");
    }
}
