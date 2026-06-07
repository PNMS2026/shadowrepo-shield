import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  ArrowLeft,
  Link as LinkIcon,
  FileText,
  FileCode2,
  File,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Hash,
  Clock,
  FolderOpen,
  Loader2,
} from "lucide-react";
import RiskGauge from "../components/RiskGauge";
import FindingCard from "../components/FindingCard";
import RiskBadge from "../components/RiskBadge";
import { getScanResult, exportReport, updateBlockchainTx, revealInExplorer } from "../lib/tauri";
import { submitProof, shortenHash } from "../lib/blockchain";
import type { ScanResult, Severity, Finding } from "../types";

export default function ScanResultPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();

  function getDisplayPath(path: string): string {
    if (!path) return "Local scan";
    if (path.startsWith("https://") || path.includes("github.com")) {
      const parts = path.split("github.com/");
      if (parts[1]) {
        return `GitHub: ${parts[1].replace(".git", "")}`;
      }
      return "GitHub Repository";
    }
    const lower = path.toLowerCase();
    if (lower.includes("appdata") || lower.includes("temp") || lower.includes("shadowrepo")) {
      return "Local scan (temporary files)";
    }
    const parts = path.split(/[/\\]/);
    return parts[parts.length - 1] || parts[parts.length - 2] || "Local repository";
  }

  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState<Severity | "all">(
    "all"
  );
  const [submittingProof, setSubmittingProof] = useState(false);
  const [proofTx, setProofTx] = useState<string | null>(null);
  const [proofError, setProofError] = useState<string | null>(null);
  const [exportingFormat, setExportingFormat] = useState<string | null>(null);
  const [exportSuccessPath, setExportSuccessPath] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  useEffect(() => {
    loadResult();
  }, [scanId]);

  async function loadResult() {
    try {
      if (scanId) {
        const data = await getScanResult(scanId);
        setResult(data);
        if (data.blockchain_tx) setProofTx(data.blockchain_tx);
      }
    } catch (err) {
      console.error("Failed to load scan result:", err);
    } finally {
      setLoading(false);
    }
  }

  async function handleExport(format: string) {
    if (!scanId) return;
    setExportingFormat(format);
    setExportSuccessPath(null);
    setExportError(null);
    try {
      const path = await exportReport(scanId, format);
      setExportSuccessPath(path);
      await revealInExplorer(path);
    } catch (err) {
      console.error("Failed to export report:", err);
      setExportError(err instanceof Error ? err.message : String(err));
    } finally {
      setExportingFormat(null);
    }
  }

  async function handleSubmitProof() {
    if (!result) return;
    setSubmittingProof(true);
    setProofError(null);
    try {
      const { txHash } = await submitProof(
        "0x5FbDB2315678afecb367f032d93F642f64180aa3",
        "http://127.0.0.1:8545",
        result.repo_hash,
        result.report_hash,
        result.risk_score
      );
      await updateBlockchainTx(result.id, txHash, "hardhat");
      setProofTx(txHash);
    } catch (err: any) {
      console.error("Submit proof error:", err);
      let errMsg = "Failed to submit proof. Check wallet and network.";
      const errStr = String(err.message || err);
      if (errStr.includes("fetch") || errStr.includes("NetworkError") || errStr.includes("could not coalesce error") || errStr.includes("refused") || errStr.includes("undici") || errStr.includes("connect")) {
        errMsg = "⚠️ Local Hardhat blockchain node is offline. Start it in your terminal: npx hardhat node";
      } else {
        errMsg = errStr;
      }
      setProofError(errMsg);
    } finally {
      setSubmittingProof(false);
    }
  }

  const filteredFindings: Finding[] = result
    ? filterSeverity === "all"
      ? result.findings
      : result.findings.filter((f) => f.severity === filterSeverity)
    : [];

  const severityCounts = result
    ? {
        critical: result.findings.filter((f) => f.severity === "critical")
          .length,
        high: result.findings.filter((f) => f.severity === "high").length,
        medium: result.findings.filter((f) => f.severity === "medium").length,
        low: result.findings.filter((f) => f.severity === "low").length,
      }
    : { critical: 0, high: 0, medium: 0, low: 0 };

  if (loading) {
    return (
      <div className="page-container flex-center" style={{ height: "100vh" }}>
        <div className="spinner" />
      </div>
    );
  }

  if (!result) {
    return (
      <div className="page-container">
        <div className="empty-state">
          <h3>Scan not found</h3>
          <button className="btn btn-primary" onClick={() => navigate("/")}>
            Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="page-container animate-fade-in">
      {/* Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "12px",
          marginBottom: "24px",
        }}
      >
        <button className="btn btn-ghost btn-sm" onClick={() => navigate(-1)}>
          <ArrowLeft size={16} />
        </button>
        <div style={{ flex: 1 }}>
          <h1
            style={{
              fontSize: "22px",
              fontWeight: 700,
              letterSpacing: "-0.03em",
              marginBottom: "2px",
            }}
          >
            {result.name}
          </h1>
          <div
            className="text-mono"
            style={{ fontSize: "12px", color: "var(--color-text-muted)" }}
            title={result.path}
          >
            {getDisplayPath(result.path)}
          </div>
        </div>
        <RiskBadge riskLevel={result.risk_level} />
      </div>

      {/* Top Grid: Risk Gauge + Summary Stats */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "240px 1fr",
          gap: "16px",
          marginBottom: "16px",
        }}
      >
        {/* Risk Gauge */}
        <div className="card flex-center" style={{ flexDirection: "column" }}>
          <RiskGauge score={result.risk_score} size={160} />
          <div
            style={{
              marginTop: "16px",
              fontSize: "12px",
              color: "var(--color-text-muted)",
              textAlign: "center",
            }}
          >
            Security Risk Assessment
          </div>
        </div>

        {/* Summary Info */}
        <div className="card">
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(2, 1fr)",
              gap: "16px",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "10px",
              }}
            >
              <FileCode2 size={18} color="var(--color-brand-accent)" />
              <div>
                <div
                  style={{
                    fontSize: "18px",
                    fontWeight: 700,
                    color: "var(--color-text-primary)",
                  }}
                >
                  {result.total_files}
                </div>
                <div
                  style={{
                    fontSize: "11px",
                    color: "var(--color-text-muted)",
                  }}
                >
                  Files Scanned
                </div>
              </div>
            </div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "10px",
              }}
            >
              <AlertTriangle size={18} color="var(--color-danger)" />
              <div>
                <div
                  style={{
                    fontSize: "18px",
                    fontWeight: 700,
                    color: "var(--color-text-primary)",
                  }}
                >
                  {result.total_findings}
                </div>
                <div
                  style={{
                    fontSize: "11px",
                    color: "var(--color-text-muted)",
                  }}
                >
                  Findings
                </div>
              </div>
            </div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "10px",
              }}
            >
              <Clock size={18} color="var(--color-text-secondary)" />
              <div>
                <div
                  style={{
                    fontSize: "13px",
                    fontWeight: 600,
                    color: "var(--color-text-primary)",
                  }}
                >
                  {new Date(result.scan_date).toLocaleString()}
                </div>
                <div
                  style={{
                    fontSize: "11px",
                    color: "var(--color-text-muted)",
                  }}
                >
                  Scan Date
                </div>
              </div>
            </div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "10px",
              }}
            >
              <FolderOpen size={18} color="var(--color-text-secondary)" />
              <div>
                <div
                  style={{
                    fontSize: "13px",
                    fontWeight: 600,
                    color: "var(--color-text-primary)",
                  }}
                >
                  {result.status}
                </div>
                <div
                  style={{
                    fontSize: "11px",
                    color: "var(--color-text-muted)",
                  }}
                >
                  Status
                </div>
              </div>
            </div>
          </div>

          {/* Hashes */}
          <div
            style={{
              marginTop: "16px",
              paddingTop: "16px",
              borderTop: "1px solid rgba(99,102,241,0.06)",
            }}
          >
            <div
              style={{
                display: "flex",
                gap: "16px",
                fontSize: "11px",
              }}
            >
              <div>
                <span style={{ color: "var(--color-text-muted)" }}>
                  <Hash size={10} style={{ display: "inline" }} /> Repo Hash:{" "}
                </span>
                <span className="text-mono" style={{ color: "var(--color-text-secondary)" }}>
                  {shortenHash(result.repo_hash, 10)}
                </span>
              </div>
              <div>
                <span style={{ color: "var(--color-text-muted)" }}>
                  <Hash size={10} style={{ display: "inline" }} /> Report Hash:{" "}
                </span>
                <span className="text-mono" style={{ color: "var(--color-text-secondary)" }}>
                  {shortenHash(result.report_hash, 10)}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Action Buttons */}
      <div
        style={{
          display: "flex",
          gap: "10px",
          marginBottom: "16px",
          flexWrap: "wrap",
        }}
      >
        <button
          className="btn btn-secondary btn-sm"
          onClick={() => handleExport("json")}
          disabled={exportingFormat === "json"}
        >
          <FileText size={14} />
          {exportingFormat === "json" ? "Exporting..." : "Export JSON"}
        </button>
        <button
          className="btn btn-secondary btn-sm"
          onClick={() => handleExport("html")}
          disabled={exportingFormat === "html"}
        >
          <FileCode2 size={14} />
          {exportingFormat === "html" ? "Exporting..." : "Export HTML"}
        </button>
        <button
          className="btn btn-secondary btn-sm"
          onClick={() => handleExport("pdf")}
          disabled={exportingFormat === "pdf"}
        >
          <File size={14} />
          {exportingFormat === "pdf" ? "Exporting..." : "Export PDF"}
        </button>
        <div style={{ flex: 1 }} />
        {proofTx ? (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              padding: "6px 14px",
              background: "rgba(16, 185, 129, 0.1)",
              borderRadius: "8px",
              fontSize: "12px",
              color: "var(--color-success)",
            }}
          >
            <ShieldCheck size={14} />
            Proof on-chain: {shortenHash(proofTx)}
          </div>
        ) : (
          <button
            className="btn btn-primary btn-sm"
            onClick={handleSubmitProof}
            disabled={submittingProof}
          >
            {submittingProof ? (
              <>
                <Loader2 size={14} className="animate-spin" />
                Submitting...
              </>
            ) : (
              <>
                <LinkIcon size={14} />
                Submit Proof to Blockchain
              </>
            )}
          </button>
        )}
      </div>

      {exportSuccessPath && (
        <div
          style={{
            padding: "10px 14px",
            background: "rgba(16, 185, 129, 0.1)",
            border: "1px solid rgba(16, 185, 129, 0.2)",
            borderRadius: "8px",
            color: "var(--color-success)",
            fontSize: "12px",
            marginBottom: "16px",
            wordBreak: "break-all",
          }}
        >
          ✅ Report successfully exported and opened: <strong>{exportSuccessPath}</strong>
        </div>
      )}

      {exportError && (
        <div
          style={{
            padding: "10px 14px",
            background: "rgba(239, 68, 68, 0.1)",
            border: "1px solid rgba(239, 68, 68, 0.2)",
            borderRadius: "8px",
            color: "#ef4444",
            fontSize: "12px",
            marginBottom: "16px",
          }}
        >
          ❌ Export failed: {exportError}
        </div>
      )}

      {proofError && (
        <div
          style={{
            padding: "10px 14px",
            background: "rgba(239, 68, 68, 0.1)",
            border: "1px solid rgba(239, 68, 68, 0.2)",
            borderRadius: "8px",
            color: "#ef4444",
            fontSize: "12px",
            marginBottom: "16px",
          }}
        >
          {proofError}
        </div>
      )}

      {/* Severity Breakdown */}
      <div
        style={{
          display: "flex",
          gap: "8px",
          marginBottom: "16px",
          flexWrap: "wrap",
        }}
      >
        <button
          className={`btn btn-sm ${filterSeverity === "all" ? "btn-primary" : "btn-secondary"}`}
          onClick={() => setFilterSeverity("all")}
        >
          All ({result.total_findings})
        </button>
        {severityCounts.critical > 0 && (
          <button
            className={`btn btn-sm ${filterSeverity === "critical" ? "btn-primary" : "btn-secondary"}`}
            onClick={() => setFilterSeverity("critical")}
          >
            <ShieldAlert size={12} />
            Critical ({severityCounts.critical})
          </button>
        )}
        {severityCounts.high > 0 && (
          <button
            className={`btn btn-sm ${filterSeverity === "high" ? "btn-primary" : "btn-secondary"}`}
            onClick={() => setFilterSeverity("high")}
          >
            High ({severityCounts.high})
          </button>
        )}
        {severityCounts.medium > 0 && (
          <button
            className={`btn btn-sm ${filterSeverity === "medium" ? "btn-primary" : "btn-secondary"}`}
            onClick={() => setFilterSeverity("medium")}
          >
            Medium ({severityCounts.medium})
          </button>
        )}
        {severityCounts.low > 0 && (
          <button
            className={`btn btn-sm ${filterSeverity === "low" ? "btn-primary" : "btn-secondary"}`}
            onClick={() => setFilterSeverity("low")}
          >
            Low ({severityCounts.low})
          </button>
        )}
      </div>

      {/* Findings List */}
      <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
        {filteredFindings.length === 0 ? (
          <div className="card" style={{ textAlign: "center", padding: "40px" }}>
            <ShieldCheck
              size={32}
              color="var(--color-success)"
              style={{ margin: "0 auto 12px" }}
            />
            <h3 style={{ fontSize: "15px", fontWeight: 600, marginBottom: "4px" }}>
              No findings in this category
            </h3>
            <p style={{ fontSize: "13px", color: "var(--color-text-muted)" }}>
              Try selecting a different severity filter
            </p>
          </div>
        ) : (
          filteredFindings.map((finding) => (
            <FindingCard key={finding.id} finding={finding} />
          ))
        )}
      </div>
    </div>
  );
}
