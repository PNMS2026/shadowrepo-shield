import { useState } from "react";
import {
  Search,
  ShieldCheck,
  ShieldX,
  Hash,
  User,
  Clock,
  AlertTriangle,
  FileSearch,
} from "lucide-react";
import { verifyProof, shortenHash } from "../lib/blockchain";
import type { BlockchainProof } from "../types";
import RiskBadge from "../components/RiskBadge";
import { getRiskLevel } from "../types";

export default function VerifyProof() {
  const [hashInput, setHashInput] = useState("");
  const [verifying, setVerifying] = useState(false);
  const [proof, setProof] = useState<BlockchainProof | null>(null);
  const [verified, setVerified] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleVerify() {
    if (!hashInput.trim()) {
      setError("Please enter a report hash or transaction hash");
      return;
    }

    setVerifying(true);
    setError(null);
    setProof(null);
    setVerified(null);

    try {
      const result = await verifyProof(
        "0x5FbDB2315678afecb367f032d93F642f64180aa3",
        "http://127.0.0.1:8545",
        hashInput
      );
      setProof(result);
      setVerified(result.exists);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Verification failed. Check hash and network connection."
      );
    } finally {
      setVerifying(false);
    }
  }

  return (
    <div className="page-container animate-fade-in">
      <div className="page-header">
        <h1>Verify Proof</h1>
        <p>
          Check a scan report's integrity by looking up its on-chain hash record.
        </p>
      </div>

      {/* Verification Input */}
      <div className="card" style={{ marginBottom: "16px" }}>
        <label
          style={{
            display: "block",
            fontSize: "13px",
            fontWeight: 600,
            marginBottom: "8px",
          }}
        >
          Report Hash or Transaction Hash
        </label>
        <div style={{ display: "flex", gap: "10px" }}>
          <input
            id="verify-hash-input"
            type="text"
            className="input input-mono"
            placeholder="0x..."
            value={hashInput}
            onChange={(e) => setHashInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleVerify()}
          />
          <button
            id="verify-btn"
            className="btn btn-primary"
            onClick={handleVerify}
            disabled={verifying}
            style={{ minWidth: "120px" }}
          >
            {verifying ? (
              <>
                <div className="spinner" style={{ width: 16, height: 16, borderWidth: 2 }} />
                Verifying...
              </>
            ) : (
              <>
                <Search size={16} />
                Verify
              </>
            )}
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div
          style={{
            padding: "12px 16px",
            background: "rgba(248, 81, 73, 0.1)",
            border: "1px solid rgba(248, 81, 73, 0.2)",
            borderRadius: "6px",
            color: "var(--color-danger)",
            fontSize: "13px",
            marginBottom: "16px",
            display: "flex",
            alignItems: "center",
            gap: "8px",
          }}
        >
          <AlertTriangle size={16} />
          {error}
        </div>
      )}

      {/* Verification Result */}
      {verified === true && proof && (
        <div className="verify-result verified animate-fade-in">
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "12px",
              marginBottom: "20px",
            }}
          >
            <div
              style={{
                width: "48px",
                height: "48px",
                borderRadius: "6px",
                background: "rgba(46, 160, 67, 0.15)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <ShieldCheck size={24} color="var(--color-success)" />
            </div>
            <div>
              <h3
                style={{
                  fontSize: "18px",
                  fontWeight: 700,
                  color: "var(--color-success)",
                  marginBottom: "2px",
                }}
              >
                Integrity Check Passed ✓
              </h3>
              <p
                style={{
                  fontSize: "13px",
                  color: "var(--color-text-secondary)",
                }}
              >
                Report hash found on-chain — data has not been modified since submission
              </p>
            </div>
          </div>

          <div className="verify-field">
            <span className="verify-field-label">
              <Hash size={12} style={{ display: "inline", marginRight: 4 }} />
              Repo Hash
            </span>
            <span className="verify-field-value">
              {shortenHash(proof.repo_hash, 12)}
            </span>
          </div>
          <div className="verify-field">
            <span className="verify-field-label">
              <Hash size={12} style={{ display: "inline", marginRight: 4 }} />
              Report Hash
            </span>
            <span className="verify-field-value">
              {shortenHash(proof.report_hash, 12)}
            </span>
          </div>
          <div className="verify-field">
            <span className="verify-field-label">
              <AlertTriangle
                size={12}
                style={{ display: "inline", marginRight: 4 }}
              />
              Risk Score
            </span>
            <span className="verify-field-value">
              <RiskBadge
                riskLevel={getRiskLevel(proof.risk_score)}
                size="sm"
              />
              <span style={{ marginLeft: "8px" }}>{proof.risk_score}/100</span>
            </span>
          </div>
          <div className="verify-field">
            <span className="verify-field-label">
              <User size={12} style={{ display: "inline", marginRight: 4 }} />
              Scanner
            </span>
            <span className="verify-field-value">
              {shortenHash(proof.scanner, 8)}
            </span>
          </div>
          <div className="verify-field">
            <span className="verify-field-label">
              <Clock size={12} style={{ display: "inline", marginRight: 4 }} />
              Timestamp
            </span>
            <span className="verify-field-value">
              {new Date(proof.timestamp * 1000).toLocaleString()}
            </span>
          </div>

          {/* Trust disclaimer */}
          <div
            style={{
              marginTop: "16px",
              padding: "10px 14px",
              background: "rgba(245, 158, 11, 0.06)",
              border: "1px solid rgba(245, 158, 11, 0.12)",
              borderRadius: "6px",
              fontSize: "11px",
              color: "var(--color-text-muted)",
              lineHeight: 1.6,
            }}
          >
            <strong style={{ color: "var(--color-text-secondary)" }}>⚠️ Note:</strong>{" "}
            Hash verification confirms report data integrity only. It does not prove
            the report was generated by the official ShadowRepo Shield scanner or that
            the scan was independently verified. Check the scan mode field for trust level.
          </div>
        </div>
      )}

      {verified === false && (
        <div className="verify-result not-found animate-fade-in">
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "12px",
            }}
          >
            <div
              style={{
                width: "48px",
                height: "48px",
                borderRadius: "6px",
                background: "rgba(248, 81, 73, 0.15)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <ShieldX size={24} color="var(--color-danger)" />
            </div>
            <div>
              <h3
                style={{
                  fontSize: "18px",
                  fontWeight: 700,
                  color: "var(--color-danger)",
                  marginBottom: "2px",
                }}
              >
                Proof Not Found
              </h3>
              <p
                style={{
                  fontSize: "13px",
                  color: "var(--color-text-secondary)",
                }}
              >
                No on-chain proof exists for this hash. The report may not have
                been submitted to blockchain.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Info Card */}
      {verified === null && !verifying && (
        <div className="card" style={{ textAlign: "center", padding: "48px 24px" }}>
          <div
            style={{
              width: "64px",
              height: "64px",
              margin: "0 auto 16px",
              borderRadius: "16px",
              background: "var(--color-surface-700)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <FileSearch size={28} color="var(--color-text-muted)" />
          </div>
          <h3 style={{ fontSize: "16px", fontWeight: 600, marginBottom: "8px" }}>
            Enter a Hash to Verify
          </h3>
          <p
            style={{
              fontSize: "13px",
              color: "var(--color-text-muted)",
              maxWidth: "420px",
              margin: "0 auto",
            }}
          >
            Paste a report hash from a ShadowRepo Shield scan to verify its
            integrity against the blockchain proof. Only hashes are stored
            on-chain — no source code or private data.
          </p>
        </div>
      )}
    </div>
  );
}
