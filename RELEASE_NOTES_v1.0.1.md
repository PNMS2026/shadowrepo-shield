# ShadowRepo Shield v1.0.1 — Security Patch Release Notes

**Release Date:** June 7, 2026
**Release Type:** Security Patch

---

## Summary

ShadowRepo Shield **v1.0.1** is a focused security patch that adds real-world **Git hook malware detection** to the scanning engine. This release addresses an emerging class of supply-chain attacks where malicious payloads are hidden inside `.git/hooks` directories of archived repositories.

---

## What's New

### Git Hook Malware Detection Engine

- **Active `.git/hooks` scanning**: Detects active (non-sample) Git hook files including `commit-msg`, `pre-push`, `post-checkout`, `post-merge`, `pre-commit`, `pre-rebase`, and `post-rewrite`.
- **Git metadata directory detection**: Flags archived repositories containing `.git` metadata directories with a warning to review hooks before running Git commands.
- **Remote payload execution detection**: Identifies dangerous patterns like `curl URL | sh`, `wget URL | bash`, and `Invoke-WebRequest` piped to execution.
- **Hidden PowerShell execution detection**: Detects `powershell.exe -WindowStyle Hidden`, `Start-Process cmd`, `cmd.exe /c`, and `curl.exe` piped into `cmd`.
- **Self-deleting hook behavior detection**: Catches hooks that attempt to remove themselves after execution (`rm -f "$0"`, `rm -f pre-push`, etc.).
- **Hook chaining detection**: Identifies hooks that execute other hook sample files or chain script executions.
- **Background silent execution detection**: Flags `>/dev/null 2>&1 &` patterns that hide activity from the user.
- **OS-targeted payload loader detection**: Catches `uname -s` conditional branches targeting Linux, Darwin, MINGW, MSYS, and CYGWIN platforms.
- **Marker file behavior detection**: Identifies scripts writing status markers to temporary directories or `.git-checker` files.
- **Suspicious remote domain detection**: Flags hardcoded URLs inside Git hook scripts and shell files.

### Combined Threat Heuristics

When multiple indicators are found together, the scanner automatically escalates to **Critical Threat Indicators Found** (score 100):

- Active Git hook + remote download + execution + self-delete
- Background silent execution + remote payload download
- OS-targeted payload loader + remote download
- Marker file behavior + self-deletion or execution
- Suspicious remote domain inside Git hook + execution

### False-Positive Prevention

- New Git hook malware rules are **scoped exclusively** to shell scripts and files within `.git/hooks/` or `.husky/` directories. Standard source code files (JavaScript, Solidity, etc.) are not affected by these rules.

---

## Privacy & Security Guarantees

- **No source code upload.** Your code stays on your device.
- **No cloud dependency.** All scanning runs locally.
- **No telemetry.** No usage data or analytics are collected.
- **No internet required.** Scanning works fully offline.

---

## Technical Details

- **App Version**: `1.0.1`
- **Target OS**: Windows 10/11 (x64)
- **Tauri Desktop Runtime**: `v2.11.2`
- **Vite & React Frontend**: `v7.3.5` + TypeScript
- **Smart Contract Compiler**: Solidity `^0.8.28`

---

## Verification & Installers

The compiled installer binaries for this release are located at:
- **NSIS Standalone Setup Executable:**
  `release\v1.0.1\windows\ShadowRepo-Shield-v1.0.1-Setup.exe`
- **MSI Installer Package:**
  `release\v1.0.1\windows\ShadowRepo-Shield-v1.0.1.msi`
- **SHA256 Checksums:**
  `release\v1.0.1\windows\SHA256SUMS.txt`

---

## Upgrade Path

This is a drop-in replacement for v1.0.0. No configuration changes are required. Simply install the new version over the existing installation.

---

## Test Results

| Test Suite | Result |
|---|---|
| Cargo unit tests | 37 passed |
| Hardhat smart contract tests | 4 passed |
| TypeScript compilation | 0 errors |
| Frontend production build | Success |
| Tauri production build | Success |
