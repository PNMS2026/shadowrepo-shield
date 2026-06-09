import { useEffect, useState } from "react";
import {
  Save,
  FolderOpen,
  Globe,
  HardDrive,
  Shield,
  Sparkles,
} from "lucide-react";
import { getSettings, updateSettings, selectFolder } from "../lib/tauri";
import type { Settings as SettingsType } from "../types";

export default function Settings() {
  const [settings, setSettings] = useState<SettingsType>({
    storage_path: "",
    offline_mode: false,
    auto_delete_temp: true,
    blockchain_network: "hardhat",
    contract_address: "",
    rpc_url: "",
    ai_enabled: false,
    ai_model: "mock",
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    loadSettings();
  }, []);

  async function loadSettings() {
    try {
      const data = await getSettings();
      setSettings(data);
    } catch (err) {
      console.error("Failed to load settings:", err);
    } finally {
      setLoading(false);
    }
  }

  async function handleSelectPath() {
    try {
      const folder = await selectFolder();
      if (folder) {
        updateField("storage_path", folder);
      }
    } catch (err) {
      console.error("Failed to select folder:", err);
    }
  }

  async function handleSave() {
    setSaving(true);
    setSaved(false);
    try {
      await updateSettings(settings);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (err) {
      console.error("Failed to save settings:", err);
    } finally {
      setSaving(false);
    }
  }

  function updateField<K extends keyof SettingsType>(
    key: K,
    value: SettingsType[K]
  ) {
    setSettings((prev) => ({ ...prev, [key]: value }));
  }

  const NETWORK_PRESETS: Record<
    string,
    { rpc: string; contract: string; label: string }
  > = {
    hardhat: {
      rpc: "http://127.0.0.1:8545",
      contract: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
      label: "Hardhat Local",
    },
    sepolia: {
      rpc: "https://sepolia.infura.io/v3/YOUR_KEY",
      contract: "",
      label: "Sepolia Testnet",
    },
    custom: {
      rpc: "",
      contract: "",
      label: "Custom Network",
    },
  };

  function handleNetworkChange(network: string) {
    updateField("blockchain_network", network);
    const preset = NETWORK_PRESETS[network];
    if (preset) {
      updateField("rpc_url", preset.rpc);
      if (preset.contract) {
        updateField("contract_address", preset.contract);
      }
    }
  }

  if (loading) {
    return (
      <div className="page-container flex-center" style={{ height: "100vh" }}>
        <div className="spinner" />
      </div>
    );
  }

  return (
    <div className="page-container animate-fade-in">
      <div className="page-header">
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div>
            <h1>Settings</h1>
            <p>Configure ShadowRepo Shield preferences.</p>
          </div>
          <button
            id="save-settings-btn"
            className="btn btn-primary"
            onClick={handleSave}
            disabled={saving}
          >
            <Save size={16} />
            {saving ? "Saving..." : saved ? "Saved ✓" : "Save Settings"}
          </button>
        </div>
      </div>

      {/* Storage Settings */}
      <div className="card" style={{ marginBottom: "16px" }}>
        <div className="settings-group">
          <h3>
            <HardDrive size={16} />
            Storage
          </h3>

          <div className="setting-row">
            <div className="setting-info">
              <div className="setting-label">Storage Path</div>
              <div className="setting-description">
                Where scan data and reports are stored locally
              </div>
            </div>
            <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
              <input
                type="text"
                className="input input-mono"
                style={{ width: "280px" }}
                value={settings.storage_path}
                onChange={(e) => updateField("storage_path", e.target.value)}
              />
              <button className="btn btn-ghost btn-sm" onClick={handleSelectPath}>
                <FolderOpen size={14} />
              </button>
            </div>
          </div>

          <div className="setting-row">
            <div className="setting-info">
              <div className="setting-label">Auto-Delete Temp Files</div>
              <div className="setting-description">
                Automatically clean up extracted repository files after scan
              </div>
            </div>
            <label className="toggle">
              <input
                type="checkbox"
                checked={settings.auto_delete_temp}
                onChange={(e) =>
                  updateField("auto_delete_temp", e.target.checked)
                }
              />
              <span className="toggle-slider" />
            </label>
          </div>
        </div>
      </div>

      {/* Network Settings */}
      <div className="card" style={{ marginBottom: "16px" }}>
        <div className="settings-group">
          <h3>
            <Globe size={16} />
            Blockchain Network
          </h3>

          <div className="setting-row">
            <div className="setting-info">
              <div className="setting-label">Offline Mode</div>
              <div className="setting-description">
                Disable all blockchain interactions — scan and report locally
                only
              </div>
            </div>
            <label className="toggle">
              <input
                type="checkbox"
                checked={settings.offline_mode}
                onChange={(e) =>
                  updateField("offline_mode", e.target.checked)
                }
              />
              <span className="toggle-slider" />
            </label>
          </div>

          {!settings.offline_mode && (
            <>
              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">Network</div>
                  <div className="setting-description">
                    Select blockchain network for proof submission
                  </div>
                </div>
                <select
                  className="select"
                  value={settings.blockchain_network}
                  onChange={(e) => handleNetworkChange(e.target.value)}
                >
                  <option value="hardhat">Hardhat Local Node</option>
                  <option value="sepolia">Sepolia Testnet</option>
                  <option value="custom">Custom Network</option>
                </select>
              </div>

              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">RPC URL</div>
                  <div className="setting-description">
                    JSON-RPC endpoint for the blockchain network
                  </div>
                </div>
                <input
                  type="text"
                  className="input input-mono"
                  style={{ width: "320px" }}
                  value={settings.rpc_url}
                  onChange={(e) => updateField("rpc_url", e.target.value)}
                  placeholder="http://127.0.0.1:8545"
                />
              </div>

              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">Contract Address</div>
                  <div className="setting-description">
                    Address of the ShadowRepoProof contract
                  </div>
                </div>
                <input
                  type="text"
                  className="input input-mono"
                  style={{ width: "320px" }}
                  value={settings.contract_address}
                  onChange={(e) =>
                    updateField("contract_address", e.target.value)
                  }
                  placeholder="0x..."
                />
              </div>
            </>
          )}
        </div>
      </div>

      {/* AI Explanations Settings */}
      <div className="card" style={{ marginBottom: "16px" }}>
        <div className="settings-group">
          <h3>
            <Sparkles size={16} />
            AI Security Explanations
          </h3>

          <div className="setting-row">
            <div className="setting-info">
              <div className="setting-label">Enable AI Explanations</div>
              <div className="setting-description">
                Allows explaining findings, lifecycle hook scripts, and remediation recommendations using AI.
              </div>
            </div>
            <label className="toggle">
              <input
                type="checkbox"
                checked={settings.ai_enabled}
                onChange={(e) =>
                  updateField("ai_enabled", e.target.checked)
                }
              />
              <span className="toggle-slider" />
            </label>
          </div>

          {settings.ai_enabled && (
            <>
              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">AI Model</div>
                  <div className="setting-description">
                    Select which model the application will invoke for analyses
                  </div>
                </div>
                <select
                  className="select"
                  value={settings.ai_model}
                  onChange={(e) => updateField("ai_model", e.target.value)}
                  style={{
                    background: "var(--color-surface-700)",
                    border: "1px solid var(--color-surface-600)",
                    borderRadius: "6px",
                    color: "var(--color-text-primary)",
                    padding: "8px 12px",
                    width: "280px",
                    outline: "none"
                  }}
                >
                  <option value="mock">Local Mock Model (Offline Testing)</option>
                  <option value="gemini-2.0-flash">Gemini 2.0 Flash</option>
                  <option value="gemini-1.5-flash">Gemini 1.5 Flash</option>
                  <option value="gemini-1.5-pro">Gemini 1.5 Pro</option>
                  <option value="gpt-4o-mini">GPT-4o-Mini</option>
                  <option value="gpt-4o">GPT-4o</option>
                  <option value="gpt-3.5-turbo">GPT-3.5 Turbo</option>
                  <option value="meta/llama3-70b-instruct">Llama 3 70B (NVIDIA NIM)</option>
                  <option value="mistralai/mixtral-8x22b-instruct">Mixtral 8x22B (NVIDIA NIM)</option>
                  <option value="anthropic/claude-3.5-sonnet">Claude 3.5 Sonnet (OpenRouter)</option>
                  <option value="meta/llama-3.1-405b-instruct">Llama 3.1 405B (OpenRouter)</option>
                </select>
              </div>

              <div
                style={{
                  fontSize: "12px",
                  color: "var(--color-warning)",
                  background: "rgba(210, 153, 34, 0.05)",
                  border: "1px solid var(--color-warning)",
                  borderRadius: "6px",
                  padding: "12px",
                  marginTop: "12px",
                  lineHeight: "1.5"
                }}
              >
                ⚠️ <strong>Privacy Notice:</strong> AI explanations may send redacted finding metadata to the configured AI provider. Source code and secrets (such as private keys and seed phrases) are automatically redacted before upload.
              </div>
            </>
          )}
        </div>
      </div>

      {/* Security Info */}
      <div className="card" style={{ marginBottom: "16px" }}>
        <div className="settings-group" style={{ marginBottom: 0 }}>
          <h3>
            <Shield size={16} />
            Security & Privacy
          </h3>
          <div
            style={{
              fontSize: "13px",
              color: "var(--color-text-secondary)",
              lineHeight: 1.7,
            }}
          >
            <p style={{ marginBottom: "8px" }}>
              ✅ <strong>Local-first by default</strong> — all scans run
              entirely on your device
            </p>
            <p style={{ marginBottom: "8px" }}>
              ✅ <strong>No source code upload</strong> — your code never
              leaves this machine
            </p>
            <p style={{ marginBottom: "8px" }}>
              ✅ <strong>No cloud database</strong> — all data stored in local
              SQLite
            </p>
            <p style={{ marginBottom: "8px" }}>
              ✅ <strong>No telemetry</strong> — zero tracking or analytics
            </p>
            <p style={{ marginBottom: "8px" }}>
              ✅ <strong>No code execution</strong> — scanned repos are never
              executed
            </p>
            <p>
              ✅ <strong>Only hashes on-chain</strong> — blockchain stores
              only proof hashes, never source code
            </p>
          </div>
        </div>
      </div>


    </div>
  );
}
