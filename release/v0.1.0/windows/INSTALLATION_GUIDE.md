# ShadowRepo Shield — Windows Installation Guide (v0.1.0)

This guide walks you through installing and running **ShadowRepo Shield** on Windows 10 or 11.

---

## 1. Installation Packages

In this directory, the following installer packages are available:
- **Recommended (Standalone Setup):**
  [ShadowRepo-Shield-v0.1.0-Setup.exe](ShadowRepo-Shield-v0.1.0-Setup.exe) (NSIS-based single-file installer)
- **Alternative (Enterprise Package):**
  [ShadowRepo-Shield-v0.1.0.msi](ShadowRepo-Shield-v0.1.0.msi) (WiX-based MSI installer)

---

## 2. Integrity Verification (Optional)

You can verify the integrity of your downloaded files using the SHA256 checksums provided in [SHA256SUMS.txt](SHA256SUMS.txt).

To verify the checksum in PowerShell:
```powershell
Get-FileHash -Algorithm SHA256 .\ShadowRepo-Shield-v0.1.0-Setup.exe
Get-FileHash -Algorithm SHA256 .\ShadowRepo-Shield-v0.1.0.msi
```

Ensure they match the values:
- `ShadowRepo-Shield-v0.1.0-Setup.exe`: `8DACCEEE589B8E7FB908D5386EFF44E7F9C12C68144A638A33C2544AC22BB71A`
- `ShadowRepo-Shield-v0.1.0.msi`: `B528E188295A940D00AE59314E4AF28F30F16A738436C3EB9336E3B24DF3A2D9`

---

## 3. Launching and Running the Local Demo

ShadowRepo Shield is a **local-first MVP prototype**. Under this release, blockchain proofs are registered on a local Ethereum network to support a free, gas-less developer demo.

### Step 3.1 Start Local Testnet
1. Open a terminal in the project root:
   ```bash
   cd shadowrepo-shield
   ```
2. Launch the local Hardhat blockchain network:
   ```bash
   npx hardhat --config hardhat.config.cjs node
   ```
   *(Keep this terminal window running in the background).*
3. Deploy the anchoring smart contract in a separate terminal:
   ```bash
   npx hardhat --config hardhat.config.cjs run scripts/deploy.cjs --network localhost
   ```
   *(The contract will deploy to `0x5FbDB2315678afecb367f032d93F642f64180aa3`)*

### Step 3.2 Launch App & Run Scan
1. Double-click the installed **ShadowRepo Shield** application to launch it.
2. Go to **New Scan** in the sidebar.
3. Drag and drop the `malicious.zip` file (found at the workspace root) into the uploader.
4. Click **Start Security Scan**.
5. Once complete, view the risk score (`97`) and security findings.
6. Click **Anchor Proof** to submit the scan proof to the smart contract.
7. Go to **Verify Proof**, paste the **Report Hash**, and click **Verify On-Chain** to read the state back.
