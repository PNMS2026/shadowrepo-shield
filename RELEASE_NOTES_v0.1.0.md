# ShadowRepo Shield v0.1.0 MVP Release Notes

We are excited to release the initial MVP prototype of **ShadowRepo Shield** (v0.1.0), the local-first, privacy-preserving repository scanner for Web3 developers.

## Core Positioning & Privacy Guarantee
> **"Your code stays on your device. Only proof goes on-chain."**
> This tool operates entirely on your local machine. Under no circumstances is private source code, directory structures, or detailed security findings transmitted to any remote servers, cloud infrastructure, or telemetry trackers.

---

## Features In This Release

- **Local Directory static scanning**: Recursive traversal of target repositories. Highly efficient folder pruning (`node_modules`, `.git`, `dist`, `build`, etc.) and binary file exclusions.
- **Web3 Threat Engine**: Detection of malicious patterns including:
  - Risky package scripts (preinstall/postinstall hooks).
  - Dangerous Node.js system commands (`child_process`, `exec`, `eval`).
  - Wallet-drainer signatures (`setApprovalForAll`, `MaxUint256` token approvals, permit abuse signatures).
  - Solidity contract risks (`tx.origin` auth, `delegatecall` vulnerabilities, unchecked low-level calls, `selfdestruct`).
- **Hazard Index Scoring**: Calculates a normalized 0-100 risk score based on pattern severity with modifiers for hook inclusions and sensitive file detections (like `.env` files).
- **SQLite scan history**: Local-first scan history tracking, allowing developers to inspect details and track score trends over time.
- **On-chain Proof Anchoring**: Bridges to EVM-compatible blockchains to record the proof of scan (`repoHash`, `reportHash`, and `riskScore`) without exposing the code content.
- **Dark-Theme HTML Exports**: Export printable standalone HTML reports with a premium styling for audit sharing.

---

## Technical Details

- **App Version**: `0.1.0`
- **Target OS**: Windows 10/11 (x64)
- **Tauri Desktop Runtime**: `v2.11.2`
- **Vite & React Frontend**: `v7.3.5` + TypeScript
- **Smart Contract Compiler**: Solidity `^0.8.20`
- **Local Database**: SQLite

---

## Verification Paths & Installers

The compiled installer binaries for this release are located at:
- **MSI Installer Package:**
  `\src-tauri\target\release\bundle\msi\ShadowRepo Shield_0.1.0_x64_en-US.msi`
- **NSIS Standalone Setup Executable:**
  `\src-tauri\target\release\bundle\nsis\ShadowRepo Shield_0.1.0_x64-setup.exe`

---

## Free Developer Demo Constraints

To facilitate easy testing and a zero-cost demo environment for review, please note the following configuration:
1. **Local Testnet:** The application is pre-configured to query and submit proofs on a local Hardhat node (`http://127.0.0.1:8545`).
2. **Mock Wallet Account:** Submissions are anchored using the standard Hardhat developer signer Account #0 (`0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`) for zero-gas mainnet simulation.
3. **No Paid Services/Cloud:** No mainnet credentials, paid RPC nodes, telemetry tracking, or user registrations are required or implemented in this MVP.
