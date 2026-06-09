# ShadowRepo Shield

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tauri](https://img.shields.io/badge/Desktop-Tauri_v2-df004f?logo=tauri)](https://tauri.app/)
[![Solidity](https://img.shields.io/badge/Smart_Contract-Solidity_v0.8.28-363636?logo=solidity)](https://soliditylang.org/)
[![Rust](https://img.shields.io/badge/Backend-Rust_v1.96-000000?logo=rust)](https://www.rust-lang.org/)

**ShadowRepo Shield** is a local-first, privacy-preserving repository scanner for Web3 developers. It scans untrusted or suspicious code repositories on the user's local device, calculates a detailed risk report, stores the scan history in a local SQLite database, and anchors cryptographic verification proofs to the blockchain.

> [!IMPORTANT]
> **Privacy First:** Private source code never leaves your device. Only the cryptographic hash of the repository and the security report are published on-chain to verify the scan's integrity. No remote server uploads, no telemetry, no data leaks.

---

## Download ShadowRepo Shield

The application is officially supported on Windows and Debian-based Linux distributions.

### 🏁 Windows (Stable v1.4.0)
* **Recommended installer:** `ShadowRepo-Shield-v1.4.0-Setup.exe`
* **Alternative installer:** `ShadowRepo-Shield-v1.4.0.msi`
* Refer to [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md) for Windows configuration.

### 🐧 Linux (Release v1.4.0)
* **Debian/Ubuntu/Kali package:** `ShadowRepo-Shield-v1.4.0.deb`
* **AppImage package:** `ShadowRepo-Shield-v1.4.0.AppImage`
* **Portable package:** `ShadowRepo-Shield-v1.4.0.tar.gz`
* Refer to [INSTALLATION_GUIDE_LINUX.md](INSTALLATION_GUIDE_LINUX.md) for step-by-step distribution instructions (Ubuntu, Debian, Kali Linux, Linux Mint, Pop!_OS).

**Download Releases from:**
[https://github.com/PNMS2026/shadowrepo-shield/releases](https://github.com/PNMS2026/shadowrepo-shield/releases)

---

## Key Features

- **Dual Scan Modes (v1.4.0):**
  - **Local Scan:** Desktop scans run directly on the user's computer; labeled as "Local Scan — Not independently verified" to prevent misleading trust assumptions.
  - **Verified Scan:** Security checks executed inside an official CI/CD runner (GitHub Actions), generating a verifiable signature based on the run context.
- **Standalone CLI Binary (v1.4.0):** A native binary (`shadowrepo-cli`) to execute fast, headless scans in terminals or build tasks, supporting customized exit codes mapped to risk assessments.
- **Report Hash Integrity (v1.4.0):** Recompute report hashes to verify that findings, risk levels, and scan modes have not been modified after generation.
- **AI Security Advisory (v1.4.0):** Explains findings and suggests fixes without modifying the deterministic scan score. Includes local regex-based privacy redaction (`redact_secrets()`) to protect private API keys, mnemonic seeds, and credentials.
- **GitHub Action Workflow:** Runs verified scans inside PR pipeline runs, uploads official reports, and comments metrics on pull requests.
- **Static Security Walker:** Recursively traverses directories, skipping binary structures and standard dependency folders (e.g., `node_modules`, `.git`, `dist`, `build`).
- **Web3 Threat Engine:** Detects dangerous lifecycle scripts (e.g., preinstall hooks), shell execution imports (`child_process`), wallet drainer APIs (`setApprovalForAll`, `MaxUint256`), permit abuses, and Solidity security risks (`delegatecall`, `tx.origin`, `selfdestruct`).
- **Git Hook Malware Detection (v1.0.1):**
  - Active `.git/hooks` detection
  - Hook chaining detection
  - Remote `curl`/`wget` pipe-to-shell execution detection
  - Hidden PowerShell execution detection
  - Self-deleting hook behavior detection
  - Heuristic escalation to Critical on indicator overlap
- **Interactive Risk Dashboard:** Visualization of threats with high-impact category gauges, severity filters, and recommended remediations.
- **Blockchain Proof Anchoring (Demo-Only):** Generates deterministic repository hashes using SHA-256 and registers them to a Solidity smart contract mapping.
- **Report Export:** Generates JSON, HTML, and real PDF security reports for local review and sharing.

---

## Architecture Overview

```mermaid
graph TD
    A[User Code Directory / ZIP File] -->|Traverse / Walk| B[Rust Scanner Engine]
    B -->|Regex Pattern Search| C[Vulnerability Analysis]
    C -->|Calculate Hazard Index| D[Risk Score (0 - 100)]
    D -->|Hash Inputs| E[Cryptographic Hash Generator]
    E -->|Repo Hash & Report Hash| F[Local SQLite Database]
    E -->|Only Hashes & Score| G[Ethers.js v6 Interface]
    G -->|Anchor Proof| H[ShadowRepoProof Smart Contract]
    F -->|Render| I[React + TS Frontend]
    H -->|Query & Validate| J[Verify Proof Page]
```

---

## Technical Stack

- **Desktop Framework:** [Tauri v2](https://tauri.app/) (cross-platform desktop runtime)
- **Frontend:** [React](https://react.dev/), [TypeScript](https://www.typescriptlang.org/), [Tailwind CSS v4](https://tailwindcss.com/)
- **Backend Core:** [Rust](https://www.rust-lang.org/) (for secure, high-performance static analysis)
- **Local Storage:** [SQLite](https://sqlite.org/) via `rusqlite`
- **Blockchain Integration:** [Ethers.js v6](https://ethers.org/), [Solidity](https://soliditylang.org/), [Hardhat](https://hardhat.org/)

---

## Development Setup

### Prerequisites
- Node.js (v18+)
- Rust (v1.96+)
- Windows C++ Build Tools (MSVC targets) or GCC/Clang on Unix systems

### 1. Install Dependencies
```bash
npm install
```

### 2. Compile and Test Smart Contracts
Initialize a local Hardhat network and deploy the contract:
```bash
# Run unit tests
npx hardhat --config hardhat.config.cjs test

# Start local blockchain node
npx hardhat --config hardhat.config.cjs node

# Deploy to local node
npx hardhat --config hardhat.config.cjs run scripts/deploy.cjs --network localhost
```

### 3. Run the App in Development Mode
To start the Tauri application locally:
```bash
npm run tauri dev
```

### 4. Run Rust Backend Tests
To execute Rust scanner unit tests and validation suites:
```bash
cd src-tauri
cargo test
```

### 5. Compile and Run the Standalone CLI
To build and execute the fast command-line scanner:
```bash
# Build the CLI target in release mode
cd src-tauri
cargo build --release --bin shadowrepo-cli

# Scan a local folder in local mode
./target/release/shadowrepo-cli.exe ../path/to/repo --name "my-scan" --mode local

# Scan a local folder in verified mode
./target/release/shadowrepo-cli.exe ../path/to/repo --name "my-scan" --mode verified
```

### 6. Build Desktop App for Production
To package the desktop GUI as a standalone installer/executable:
```bash
npm run tauri build
```

---

## Security Guarantees
- **Zero Execution Policy:** The scanner uses static string analysis and regular expression tokenization. It never executes the scanned code, avoiding malicious trigger codes.
- **Exclusion Filters:** Automatically avoids loading files inside binary caches, packages, or large binaries to prevent memory denial-of-service issues.

---

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
