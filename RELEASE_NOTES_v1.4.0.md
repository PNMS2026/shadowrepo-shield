# ShadowRepo Shield v1.4.0 — Verified Trust Update

**Release Date:** June 2026

---

## What's New

### Scan Trust Separation

ShadowRepo Shield now distinguishes between two scan trust levels:

| Scan Mode | Description | Trust Level |
|-----------|------------|-------------|
| 🟡 **Local Scan** | User-initiated scan from the desktop app | Self-reported, not independently verified |
| 🟢 **Verified Scan** | Scan run by official ShadowRepo Shield CLI binary in CI/CD | Higher trust — uses official binary |

### CLI Binary (`shadowrepo-cli`)

A new standalone CLI binary for running scans in CI/CD pipelines:

```bash
shadowrepo-cli /path/to/repo --mode verified --output report.json
```

Features:
- Same deterministic scanner engine as the desktop app
- Exit codes map to risk levels (0=low, 1=review, 2=high, 3=critical)
- Outputs JSON, HTML, or PDF reports
- Picks up CI environment variables for runner identification
- No source code uploads — everything runs locally

### GitHub Action Workflow

New `.github/workflows/shadowrepo-scan.yml` template:
- Downloads and runs the **official** ShadowRepo Shield binary from releases
- Does **NOT** run scanner code from the user's repository
- Posts scan results as PR comments
- Uploads report JSON as workflow artifact

### Report Integrity Verification

New `verify_report_hash` command that:
- Recomputes report hash from stored data
- Returns "Integrity check passed — Report hash valid" or "Hash mismatch"
- Does NOT claim "officially signed" or "fully verified"

### AI Advisory Analysis

New AI advisory feature (`request_ai_analysis`):
- Explains findings and suggests practical fixes
- **NEVER** modifies score, severity, grade, or risk level
- Only sends finding metadata (descriptions, file paths, redacted content)
- Does NOT send full source code to any external server
- Clearly labeled "Advisory — not authoritative"

---

## Security Model

```
LOCAL SCAN (Desktop)
├─ Initiated by user on their machine
├─ Score: deterministic regex engine
├─ Trust: 🟡 self-reported, not independently verified
└─ Wording: "Integrity check passed" only

VERIFIED SCAN (GitHub Action / CI)
├─ Runs OFFICIAL binary from OFFICIAL release
├─ Does NOT run code from user's repo
├─ Score: same deterministic regex engine
├─ Trust: 🟢 higher trust (official binary)
└─ Wording: "Scanned by official CI runner"

AI ADVISORY
├─ Explains findings, suggests fixes
├─ NEVER modifies score/severity/grade/risk
├─ Does NOT send full source code
└─ Clearly labeled "Advisory — not authoritative"
```

---

## Files Changed

### Rust Backend
- `scanner/types.rs` — Added `ScanMode` enum, updated `ScanResult`, `ScanSummary`, `DashboardStats`
- `scanner/mod.rs` — Updated `run_scan()` to accept `ScanMode` parameter
- `scanner/ai.rs` — Added `AiAnalysisResponse` struct and `ai_risk_analysis()` function
- `commands.rs` — All desktop commands pass `ScanMode::Local`, added `verify_report_hash` and `request_ai_analysis`
- `db.rs` — Added `scan_mode` and `scanner_signature` columns with migration
- `report.rs` — HTML reports show scan mode badge
- `lib.rs` — Registered new commands
- `cli.rs` — **NEW** standalone CLI binary

### Frontend
- `types/index.ts` — Added `ScanMode`, `AiAnalysis` types
- `lib/tauri.ts` — Updated mock data, added `verifyReportHash()` wrapper
- `pages/ScanResult.tsx` — Scan mode badge (Local/Verified)
- `pages/ScanHistory.tsx` — Mode column in history table
- `pages/NewScan.tsx` — Local scan mode info banner
- `pages/Dashboard.tsx` — Verified scans stat card
- `pages/VerifyProof.tsx` — Corrected wording: "Integrity check passed"

### CI/CD
- `.github/workflows/shadowrepo-scan.yml` — **NEW** GitHub Action template
- `Cargo.toml` — Added CLI `[[bin]]` target, bumped to v1.4.0
- `package.json` — Bumped to v1.4.0

---

## Privacy & Security

- ✅ No source code is uploaded to any external server
- ✅ AI mode does not send full source code (only finding metadata, redacted)
- ✅ GitHub Action runs official binary, not user's code
- ✅ Score is always computed deterministically by regex engine
- ✅ No malicious code, tracking, hidden data upload, wallet access, or backdoors

---

## Smart Contract (Deferred)

Smart contract changes for `isVerified` trust flags are **deferred** to a future release. The current contract does not distinguish scan modes because:

1. A user can fake `isVerified: true` by calling the contract directly
2. Proper verified proof requires a trusted verifier wallet/attestation system
3. This needs careful cryptographic design before deployment

Smart contract demo-only changes will be addressed in v1.5.0 with proper `trustedVerifier` address patterns.
