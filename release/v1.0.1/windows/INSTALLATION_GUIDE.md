# ShadowRepo Shield — Windows Installation & Setup Guide (v1.0.0)

This guide walks you through installing, setting up, and running the **ShadowRepo Shield** desktop application on Windows 10 or 11.

---

## 1. Prerequisites

To use the on-chain proof anchoring features during this local demo:
- Ensure **Node.js** (v18 or newer) is installed on your system.
- Open a terminal and run `node -v` to confirm.

---

## 2. Installation Options

The release contains two Windows installer options:

### Option A: MSI Installer (Recommended)
1. Double-click the MSI installer package:
   `release\v1.0.0\windows\ShadowRepo-Shield-v1.0.0.msi`
2. Follow the standard Windows Setup Wizard instructions to install.
3. Locate **ShadowRepo Shield** in your Windows Start Menu to run the app.

### Option B: NSIS Setup Executable
1. Double-click the setup file:
   `release\v1.0.0\windows\ShadowRepo-Shield-v1.0.0-Setup.exe`
2. The installer will install the app and launch it immediately.

---

## 3. Running the Blockchain Demo Environment

For the MVP proof anchoring demo to connect successfully, you need to run the local Hardhat blockchain node. 

1. Navigate to the project directory in your terminal:
   ```bash
   cd shadowrepo-shield
   ```
2. Start the local Ethereum testnet node:
   ```bash
   npx hardhat --config hardhat.config.cjs node
   ```
   *Keep this terminal window open. It runs a local node at `http://127.0.0.1:8545` and provides 20 test accounts pre-funded with 10,000 mock ETH.*
3. (First time setup only) Deploy the smart contract in a separate terminal:
   ```bash
   npx hardhat --config hardhat.config.cjs run scripts/deploy.cjs --network localhost
   ```
   *The contract will deploy to address: `0x5FbDB2315678afecb367f032d93F642f64180aa3`.*

---

## 4. Manual App Testing Checklist

Once the app is launched and the local testnet is running, follow this checklist to verify functionality:

- [ ] **Launch App**: Open ShadowRepo Shield. You should see a dark-themed Dashboard with statistics showing 0 scans.
- [ ] **Scan Zip Repository**:
  1. Click on **New Scan** in the sidebar.
  2. Drag and drop or browse to select the `malicious.zip` file located at your project root.
  3. Click **Start Security Scan**.
  4. Verify the scanning animation runs, and you are automatically redirected to the **Scan Result** page.
- [ ] **Inspect Findings**:
  - Verify the **Risk Score** is `100` and **Risk Level** is **Critical**.
  - Confirm the findings include a postinstall script, process spawn imports, and wallet drainer functions.
- [ ] **Export Reports**:
  - Click **Export JSON**. Check that a `report-[id].json` file is saved to your default download directory.
  - Click **Export HTML**. Confirm a `report-[id].html` file is saved and can be opened in any web browser.
  - Click **Export PDF**. Confirm a professional native `report-[id].pdf` file is saved and can be opened.
- [ ] **Anchor Proof On-Chain**:
  - Click the **Anchor Proof** button.
  - Confirm that the status updates to **Transaction Submitted**, showing the transaction hash and local network.
- [ ] **Verify Proof Page**:
  - Go to the **Verify Proof** page in the sidebar.
  - Copy the **Report Hash** from your scan result.
  - Paste it into the search input and click **Verify On-Chain**.
  - Check that the contract returns the matching repository hash, risk score of `100`, and the scanner signature.
- [ ] **Scan History Persistence**:
  - Click **Scan History** in the sidebar.
  - Verify your completed scan is listed with the correct score, timestamp, and transaction status.
  - Close and restart the app, then check Scan History to verify the data persisted.
