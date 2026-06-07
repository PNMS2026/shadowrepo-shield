# Security Policy

## Security Philosophy

ShadowRepo Shield is built for security-conscious Web3 developers. Our architecture is designed around two core principles:

1. **Zero Execution:** Scanned code is strictly analyzed statically. The scanner does not run any scripts, build tools (`npm install`, `cargo build`, etc.), or executables from the target repository. This prevents malicious codes from executing during the scan.
2. **Local-First Privacy:** All file parsing, directory walking, SQLite persistence, and HTML report exporting are executed entirely on your local machine. No source code, filenames, or findings are uploaded to any external servers.

---

## Supported Versions

Security updates are actively applied to the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| v0.1.x  | :white_check_mark: |

---

## Reporting a Vulnerability

If you discover a security vulnerability in ShadowRepo Shield, please report it immediately.

**Do not open a public GitHub issue.** Instead, please submit your report to our security team via:
- Email: `security@shadowrepo.shield` (Mock for development)
- Encrypted message: PGP Key available in `KEYS.md` (Mock for development)

### Please include:
- A detailed description of the vulnerability.
- A proof of concept (PoC) target directory or ZIP that triggers the vulnerability.
- Steps to reproduce the issue.
- Possible remediation steps if known.

We aim to acknowledge receipt of all vulnerability reports within **48 hours** and provide a plan for resolution within **7 days**.

---

## Local Scan Constraints & Limitations

To guarantee security, ShadowRepo Shield enforces the following constraints during directory traversal:

- **Large File Exclusion:** Files exceeding 10MB are skipped to prevent memory exhaustion (DoS).
- **Binary Detection:** Known binary extensions and non-text files are ignored to prevent buffer overflow vulnerabilities.
- **Symbolic Link Protection:** The directory walker does not follow symbolic links pointing outside the scan root directory (preventing directory traversal attacks).
- **Safe Path Extraction:** During ZIP upload scans, path components containing `..` or leading slashes are rejected to prevent file writing outside the temporary directory.
