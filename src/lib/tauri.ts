import { invoke } from "@tauri-apps/api/core";
import type { ScanResult, ScanSummary, Settings } from "../types";

// ============================================================
// Tauri IPC Command Wrappers
// ============================================================

// Mock data for UI development before Rust backend is wired
const MOCK_SCANS: ScanSummary[] = [
  {
    id: "scan-001",
    name: "suspicious-defi-protocol",
    path: "C:\\repos\\suspicious-defi",
    scan_date: new Date(Date.now() - 3600000).toISOString(),
    risk_score: 87,
    risk_level: "critical",
    total_files: 234,
    total_findings: 18,
    status: "completed",
    blockchain_tx: "0x1a2b3c...def",
  },
  {
    id: "scan-002",
    name: "token-swap-contract",
    path: "C:\\repos\\token-swap",
    scan_date: new Date(Date.now() - 86400000).toISOString(),
    risk_score: 45,
    risk_level: "review_recommended",
    total_files: 89,
    total_findings: 6,
    status: "completed",
    blockchain_tx: null,
  },
  {
    id: "scan-003",
    name: "nft-marketplace",
    path: "C:\\repos\\nft-marketplace",
    scan_date: new Date(Date.now() - 172800000).toISOString(),
    risk_score: 12,
    risk_level: "low",
    total_files: 156,
    total_findings: 2,
    status: "completed",
    blockchain_tx: "0x4e5f6a...789",
  },
  {
    id: "scan-004",
    name: "yield-aggregator",
    path: "C:\\repos\\yield-agg",
    scan_date: new Date(Date.now() - 259200000).toISOString(),
    risk_score: 72,
    risk_level: "high",
    total_files: 312,
    total_findings: 14,
    status: "completed",
    blockchain_tx: null,
  },
  {
    id: "scan-005",
    name: "bridge-protocol",
    path: "C:\\repos\\bridge",
    scan_date: new Date(Date.now() - 345600000).toISOString(),
    risk_score: 93,
    risk_level: "critical",
    total_files: 445,
    total_findings: 27,
    status: "completed",
    blockchain_tx: "0x7d8e9f...abc",
  },
];

const MOCK_FINDINGS = [
  {
    id: "f-001",
    scan_id: "scan-001",
    pattern_id: "sol-delegatecall",
    severity: "critical" as const,
    category: "solidity_audit_risk" as const,
    description: "Usage of delegatecall detected — potential proxy exploit vector",
    file_path: "contracts/Proxy.sol",
    line_number: 45,
    matched_content: "address(target).delegatecall(data)",
    recommendation:
      "Review delegatecall usage carefully. Ensure the target address is trusted and cannot be manipulated by an attacker.",
  },
  {
    id: "f-002",
    scan_id: "scan-001",
    pattern_id: "web3-approval-all",
    severity: "critical" as const,
    category: "malicious_indicator" as const,
    description: "setApprovalForAll detected — potential wallet drainer pattern",
    file_path: "src/utils/approve.ts",
    line_number: 23,
    matched_content: "contract.setApprovalForAll(spender, true)",
    recommendation:
      "Verify that setApprovalForAll is intended and the spender address is trusted. This function grants full access to all tokens.",
  },
  {
    id: "f-003",
    scan_id: "scan-001",
    pattern_id: "js-child-process",
    severity: "high" as const,
    category: "hook_execution_risk" as const,
    description: "child_process import detected — code execution risk",
    file_path: "scripts/deploy.js",
    line_number: 3,
    matched_content: "const { exec } = require('child_process')",
    recommendation:
      "Review why child_process is being used. This module can execute arbitrary commands on the user's system.",
  },
  {
    id: "f-004",
    scan_id: "scan-001",
    pattern_id: "pkg-postinstall",
    severity: "high" as const,
    category: "hook_execution_risk" as const,
    description: "Risky postinstall script found in package.json",
    file_path: "package.json",
    line_number: 12,
    matched_content: '"postinstall": "node scripts/setup.js"',
    recommendation:
      "Inspect the postinstall script carefully before running npm install. Malicious packages often use postinstall hooks.",
  },
  {
    id: "f-005",
    scan_id: "scan-001",
    pattern_id: "sol-tx-origin",
    severity: "medium" as const,
    category: "solidity_audit_risk" as const,
    description: "Usage of tx.origin for authorization — phishing vulnerability",
    file_path: "contracts/Auth.sol",
    line_number: 18,
    matched_content: "require(tx.origin == owner)",
    recommendation:
      "Replace tx.origin with msg.sender. tx.origin can be exploited through phishing attacks via malicious contracts.",
  },
  {
    id: "f-006",
    scan_id: "scan-001",
    pattern_id: "sensitive-env",
    severity: "medium" as const,
    category: "secret_handling_warning" as const,
    description: "Sensitive .env file found in repository",
    file_path: ".env",
    line_number: null,
    matched_content: null,
    recommendation:
      "Remove .env files from version control. Add .env to .gitignore and use environment variables or a secrets manager.",
  },
  {
    id: "f-007",
    scan_id: "scan-001",
    pattern_id: "js-eval",
    severity: "high" as const,
    category: "hook_execution_risk" as const,
    description: "eval() usage detected — arbitrary code execution risk",
    file_path: "src/parser.ts",
    line_number: 67,
    matched_content: "eval(userInput)",
    recommendation:
      "Never use eval() with user input. Use safer alternatives like JSON.parse() or a sandboxed execution environment.",
  },
  {
    id: "f-008",
    scan_id: "scan-001",
    pattern_id: "web3-private-key",
    severity: "critical" as const,
    category: "malicious_indicator" as const,
    description: "Hardcoded private key pattern detected",
    file_path: "src/config.ts",
    line_number: 5,
    matched_content: 'const pk = "0x1a2b3c4d5e6f..."',
    recommendation:
      "Never hardcode private keys. Use environment variables, hardware wallets, or a secure key management system.",
  },
];

const MOCK_RESULT: ScanResult = {
  id: "scan-001",
  name: "suspicious-defi-protocol",
  path: "C:\\repos\\suspicious-defi",
  scan_date: new Date(Date.now() - 3600000).toISOString(),
  risk_score: 87,
  risk_level: "critical",
  total_files: 234,
  total_findings: 18,
  repo_hash: "a3f2b7c9d1e4f5a6b8c0d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3",
  report_hash: "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
  status: "completed",
  findings: MOCK_FINDINGS,
  blockchain_tx: null,
  blockchain_network: null,
};

// Detect if running inside Tauri or browser
function isTauri(): boolean {
  return !!(window as any).__TAURI_INTERNALS__;
}

export async function startScan(
  path: string,
  scanName: string
): Promise<ScanResult> {
  if (!isTauri()) {
    // Simulate scan for UI development
    await new Promise((r) => setTimeout(r, 3000));
    return { ...MOCK_RESULT, name: scanName, path };
  }
  return await invoke("start_scan", { path, scanName });
}

export async function uploadAndScan(
  zipPath: string,
  scanName: string
): Promise<ScanResult> {
  if (!isTauri()) {
    await new Promise((r) => setTimeout(r, 4000));
    return { ...MOCK_RESULT, name: scanName };
  }
  return await invoke("upload_and_scan", { zipPath, scanName });
}

export async function scanGitUrl(
  url: string,
  scanName: string
): Promise<ScanResult> {
  if (!isTauri()) {
    await new Promise((r) => setTimeout(r, 5000));
    return { ...MOCK_RESULT, name: scanName, path: url };
  }
  return await invoke("scan_git_url", { url, scanName });
}

export async function getScanHistory(): Promise<ScanSummary[]> {
  if (!isTauri()) return MOCK_SCANS;
  return await invoke("get_scan_history");
}

export async function getScanResult(scanId: string): Promise<ScanResult> {
  if (!isTauri()) {
    const result = { ...MOCK_RESULT, id: scanId };
    return result;
  }
  return await invoke("get_scan_result", { scanId });
}

export async function deleteScan(scanId: string): Promise<boolean> {
  if (!isTauri()) return true;
  return await invoke("delete_scan", { scanId });
}

export async function exportReport(
  scanId: string,
  format: string
): Promise<string> {
  if (!isTauri()) return `/reports/report-${scanId}.${format}`;
  return await invoke("export_report", { scanId, format });
}

export async function updateBlockchainTx(
  scanId: string,
  txHash: string,
  network: string
): Promise<boolean> {
  if (!isTauri()) return true;
  return await invoke("update_blockchain_tx", { scanId, txHash, network });
}

export async function getSettings(): Promise<Settings> {
  if (!isTauri()) {
    return {
      storage_path: "C:\\Users\\user\\.shadowrepo",
      offline_mode: false,
      auto_delete_temp: true,
      blockchain_network: "hardhat",
      contract_address: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
      rpc_url: "http://127.0.0.1:8545",
    };
  }
  return await invoke("get_settings");
}

export async function updateSettings(settings: Settings): Promise<boolean> {
  if (!isTauri()) return true;
  return await invoke("update_settings", { settings });
}

export async function selectFolder(): Promise<string | null> {
  if (!isTauri()) return "C:\\repos\\selected-folder";
  return await invoke("select_folder");
}

export async function selectZipFile(): Promise<string | null> {
  if (!isTauri()) return "C:\\repos\\selected-file.zip";
  return await invoke("select_zip_file");
}

export async function revealInExplorer(path: string): Promise<void> {
  if (!isTauri()) return;
  await invoke("reveal_in_explorer", { path });
}

export async function getDashboardStats() {
  if (!isTauri()) {
    return {
      total_scans: MOCK_SCANS.length,
      critical_findings: MOCK_SCANS.filter((s) => s.risk_level === "critical")
        .length,
      average_risk: Math.round(
        MOCK_SCANS.reduce((sum, s) => sum + s.risk_score, 0) /
          MOCK_SCANS.length
      ),
      repos_scanned: MOCK_SCANS.length,
    };
  }
  return await invoke("get_dashboard_stats");
}
