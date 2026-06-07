# ShadowRepo Shield — Final Validation Report (v1.0.0)

This report documents the verification and validation tests performed for **ShadowRepo Shield** (v1.0.0) on Windows.

---

## 1. Automated Tests Summary

All backend, integration, and blockchain contract test suites compile and pass successfully:

| Suite | Command | Total Tests | Passed | Failed | Status |
| ----- | ------- | ----------- | ------ | ------ | ------ |
| Rust Core | `cargo test --lib` | 29 | 29 | 0 | :white_check_mark: PASS |
| Rust Integration | `cargo test --test integration_test` | 1 | 1 | 0 | :white_check_mark: PASS |
| EVM Contracts | `npx hardhat --config hardhat.config.cjs test` | 4 | 4 | 0 | :white_check_mark: PASS |
| TypeScript Compiler | `npx tsc --noEmit` | N/A | N/A | 0 | :white_check_mark: PASS |
| Frontend Bundler | `npm run build` (Vite) | N/A | N/A | 0 | :white_check_mark: PASS |

---

## 2. End-to-End Headless Verification

An automated integration flow is implemented in `src-tauri/tests/integration_test.rs` to execute a complete headless verification run:

### 2.1 Threat Pattern Detection Results
A mock repository ZIP file (`malicious.zip`) was generated containing:
- `package.json` with a `"postinstall"` lifecycle script.
- `index.js` containing `child_process` imports, `exec` commands, and `.env` read calls.
- `drainer.ts` containing `setApprovalForAll` and `MaxUint256` token approvals.
- `.env` file containing a raw private key, mnemonics, and seed phrases.

The scanner successfully detected all malicious threat indicators:
1. `pkg-postinstall` (Risky install lifecycle hook) — **Detected**
2. `js-child-process` (Process execution import) — **Detected**
3. `js-env-read` (Direct reading of .env file) — **Detected**
4. `web3-approval-all` (setApprovalForAll wallet drainer API) — **Detected**
5. `web3-approve-max` (Unlimited token approval MaxUint256) — **Detected**
6. `web3-hardcoded-key` (Hardcoded private key with quotes) — **Detected**

### 2.2 Risk Scoring & Categorization
- **Risk Score:** `100` (capped correctly based on pattern severity rules and hook weighting bonuses).
- **Risk Level:** `Critical` (Correctly mapped from 100 score).
- **Sensitive Filename Detection:** Matches `.env` and issues a `Category::SensitiveFile` warning.

### 2.3 Local Storage & Exporting
- **SQLite Database Persistence:** Scan metadata, statistics, and all findings successfully persisted in the database and loaded back with matching hashes and scores.
- **Report Exports:**
  - `report.json` was generated and contains raw structured data.
  - `report.html` was generated and includes a print-ready dark theme visualization of findings.
- **Temporary Folder Cleanup:** The unzipped scan folder is fully deleted from the temp directory immediately after scan completion.

---

## 3. Blockchain Proof Verification

Using the local Hardhat testnet node, we executed the `scripts/verify-proof.cjs` script to verify on-chain proof anchoring:
1. **Contract Deployed:** `ShadowRepoProof` deployed at `0x5FbDB2315678afecb367f032d93F642f64180aa3` (Local Hardhat network).
2. **Proof Anchored:** A cryptographic proof was submitted containing:
   - **Repository Hash:** `0xf12f986fb3ab19150c61a460e7c7c9639bd2e8bfdee98dc7a2b4516e5ce0b450`
   - **Report Hash:** `0xacc310fe91a9946816154cdf28020ee3350879af675a602d56455be3df581ccf`
   - **Risk Score:** `100`
   - **Transaction Hash:** `0x781dd2b5c322b987ba481eea9426409293823c4940d361b71c3c05cbbdda70fd` (Mock Hash)
3. **On-Chain Verification:** Calling `verifyProof` on the smart contract successfully returned the registered details matching submitted hashes and score.
4. **Offline Error Handling:** When the Hardhat network is offline, the app displays a clear user warning: `"⚠️ Local Hardhat blockchain node is offline. Start it in your terminal: npx hardhat node"`.

---

## 4. Distribution Installers

Running `npm run tauri build` successfully completed release compiling and generated cross-platform installer packages under `release/v1.0.0/windows/`:

1. **Windows Setup Executable:** `ShadowRepo-Shield-v1.0.0-Setup.exe` (NSIS Installer)
2. **Windows MSI Installer:** `ShadowRepo-Shield-v1.0.0.msi` (MSI Installer Package)

---

## 5. Security & Privacy Guarantees

1. **Zero Execution Policy:** The scanner uses static string analysis and regular expression tokenization. It never executes the scanned code, avoiding malicious trigger codes.
2. **Exclusion Filters:** Automatically avoids loading files inside binary caches, packages, or large binaries to prevent memory denial-of-service issues.
3. **AppData Restriction:** Writable files, logs, temp extractions, database, and reports are all strictly managed within the secure Windows AppData path:
   `C:\Users\<User>\AppData\Local\ShadowRepoShield`
