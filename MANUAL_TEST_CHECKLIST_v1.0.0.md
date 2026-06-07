# ShadowRepo Shield v1.0.0 Manual Test Checklist

Follow this checklist to verify the full functionality of the installed **ShadowRepo Shield** application on Windows.

---

## 1. Application Launch & UI Theme

- [ ] **Launch Application:** Double-click the desktop shortcut or find "ShadowRepo Shield" in the Start Menu. Verify it opens instantly.
- [ ] **Aesthetic Theme Check:** Verify the monochromatic dark theme displays properly. Look for crisp fonts (Outfit/Inter style), clean cards, and polished glassmorphic side navigation.
- [ ] **Empty State:** Confirm that the Dashboard displays `0` total scans and a clean welcome state if no scans have been performed yet.

---

## 2. Directory & ZIP Scanning

- [ ] **Select Local Repository:**
  1. Click **New Scan** in the sidebar.
  2. Click **Browse Directory** or **Browse ZIP**. Confirm that a native Windows Explorer folder/file picker dialog opens.
  3. Select the `malicious.zip` archive or any local repository folder.
- [ ] **Scan Execution:**
  1. Click **Start Security Scan**.
  2. Confirm the scan starts and the loading skeleton/progress bar is displayed.
  3. Verify you are automatically redirected to the **Scan Result** page upon completion.
- [ ] **Scanned Path Privacy:**
  - Verify that the path displayed in the header does **not** expose the absolute temp extraction path (e.g. `AppData\Local\Temp\...`).
  - It should display a generic label like: `Local scan (temporary files)` or the folder name for local folders.

---

## 3. Results & Threat Indicators

- [ ] **Risk Score:** Verify the score is `100` and the badge shows **Critical**.
- [ ] **Filter Severity:**
  - Click the **Critical**, **High**, **Medium**, and **Low** filters.
  - Verify the list of findings filters instantly.
- [ ] **Findings Analysis:** Confirm the presence of key detections:
  - `pkg-postinstall` (Risky install hooks)
  - `js-child-process` (Process execution import)
  - `web3-approval-all` (setApprovalForAll wallet drainer signature)
  - `web3-hardcoded-key` (Private key / secret leak)
  - `shell-curl-exec` or shell script category flags.

---

## 4. Reports & Exports

- [ ] **JSON Export:**
  1. Click **Export JSON**.
  2. Confirm a success notification banner appears at the bottom.
  3. Confirm Windows Explorer automatically opens and highlights the newly generated `report-[id].json` file.
- [ ] **HTML Export:**
  1. Click **Export HTML**.
  2. Confirm the success banner appears and Explorer highlights the file.
  3. Open the HTML report in a browser. Verify the executive summary, disclaimers, and severity layout render with rich styling.
- [ ] **PDF Export:**
  1. Click **Export PDF**.
  2. Verify the success banner appears and Explorer highlights the generated PDF file.
  3. Open the PDF in a PDF reader. Confirm it is a native PDF document with clean page structure, disclaimers, and formatted text.

---

## 5. Blockchain Proof Anchoring

- [ ] **Submit Proof:**
  1. Make sure your local Hardhat node is running in a terminal.
  2. Click **Submit Proof to Blockchain** (or **Anchor Proof**).
  3. Verify a transaction hash is generated and displayed on the UI.
- [ ] **Offline Network Graceful Degradation:**
  1. Shut down the Hardhat terminal node.
  2. Click **Submit Proof to Blockchain**.
  3. Verify that the app catches the error and displays a clear message: `"⚠️ Local Hardhat blockchain node is offline. Start it in your terminal: npx hardhat node"`.
- [ ] **Proof Verification Page:**
  1. Copy the **Report Hash** from the result page.
  2. Go to **Verify Proof** in the sidebar.
  3. Paste the hash and click **Verify On-Chain**.
  4. Confirm that the registered proof is loaded directly from the smart contract with correct score, repo hash, and timestamp.

---

## 6. History & Local Persistence

- [ ] **Scan History Table:**
  1. Go to **Scan History** in the sidebar.
  2. Verify your completed scan is listed with the correct score, timestamp, and transaction status.
  3. Verify the path column shows a privacy-filtered relative path instead of full AppData paths.
- [ ] **Data Persistence:**
  1. Close the application.
  2. Reopen the application.
  3. Go to **Scan History** and verify the database record is retained and loads correctly.
