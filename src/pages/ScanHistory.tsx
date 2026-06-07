import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Search,
  Trash2,
  ArrowRight,
  History,
  ScanSearch,
  Link as LinkIcon,
} from "lucide-react";
import RiskBadge from "../components/RiskBadge";
import { getScanHistory, deleteScan } from "../lib/tauri";
import type { ScanSummary } from "../types";

export default function ScanHistory() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [sortBy, setSortBy] = useState<"date" | "risk">("date");

  useEffect(() => {
    loadScans();
  }, []);

  async function loadScans() {
    try {
      const data = await getScanHistory();
      setScans(data);
    } catch (err) {
      console.error("Failed to load scan history:", err);
    } finally {
      setLoading(false);
    }
  }

  async function handleDelete(e: React.MouseEvent, scanId: string) {
    e.stopPropagation();
    if (confirm("Delete this scan and all its findings?")) {
      try {
        await deleteScan(scanId);
        setScans((prev) => prev.filter((s) => s.id !== scanId));
      } catch (err) {
        console.error("Failed to delete scan:", err);
      }
    }
  }

  const filteredScans = scans
    .filter(
      (s) =>
        s.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        s.path.toLowerCase().includes(searchQuery.toLowerCase())
    )
    .sort((a, b) => {
      if (sortBy === "risk") return b.risk_score - a.risk_score;
      return new Date(b.scan_date).getTime() - new Date(a.scan_date).getTime();
    });

  function formatDate(iso: string): string {
    return new Date(iso).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }

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
        <h1>Scan History</h1>
        <p>View and manage your past repository security scans.</p>
      </div>

      {/* Search + Filter Bar */}
      <div
        style={{
          display: "flex",
          gap: "12px",
          marginBottom: "16px",
          alignItems: "center",
        }}
      >
        <div style={{ flex: 1, position: "relative" }}>
          <Search
            size={16}
            style={{
              position: "absolute",
              left: "12px",
              top: "50%",
              transform: "translateY(-50%)",
              color: "var(--color-text-muted)",
            }}
          />
          <input
            id="history-search-input"
            type="text"
            className="input"
            placeholder="Search scans by name or path..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ paddingLeft: "36px" }}
          />
        </div>
        <select
          className="select"
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as "date" | "risk")}
        >
          <option value="date">Sort by Date</option>
          <option value="risk">Sort by Risk</option>
        </select>
        <button
          className="btn btn-primary"
          onClick={() => navigate("/scan")}
        >
          <ScanSearch size={16} />
          New Scan
        </button>
      </div>

      {/* Scan Table */}
      {filteredScans.length === 0 ? (
        <div className="table-container">
          <div className="empty-state">
            <div className="empty-state-icon">
              <History size={28} />
            </div>
            <h3>{searchQuery ? "No matching scans" : "No scans yet"}</h3>
            <p>
              {searchQuery
                ? "Try adjusting your search query"
                : "Start your first repository security scan"}
            </p>
            {!searchQuery && (
              <button
                className="btn btn-primary"
                onClick={() => navigate("/scan")}
              >
                <ScanSearch size={16} />
                Start Scanning
              </button>
            )}
          </div>
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Repository</th>
                <th>Risk Score</th>
                <th>Findings</th>
                <th>Files</th>
                <th>Date</th>
                <th>Proof</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredScans.map((scan) => (
                <tr
                   key={scan.id}
                   onClick={() => navigate(`/result/${scan.id}`)}
                   title={`Scan ID: ${scan.id}`}
                >
                  <td>
                    <div
                      style={{
                        fontWeight: 600,
                        color: "var(--color-text-primary)",
                        marginBottom: "2px",
                      }}
                    >
                      {scan.name}
                    </div>
                    <div
                      className="text-mono truncate"
                      style={{
                        fontSize: "11px",
                        color: "var(--color-text-muted)",
                        maxWidth: "220px",
                      }}
                    >
                      {getDisplayPath(scan.path)}
                    </div>
                  </td>
                  <td>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                      }}
                    >
                      <span
                        style={{
                          fontWeight: 700,
                          fontFamily: "var(--font-mono)",
                          fontSize: "14px",
                        }}
                      >
                        {scan.risk_score}
                      </span>
                      <RiskBadge riskLevel={scan.risk_level} size="sm" />
                    </div>
                  </td>
                  <td>{scan.total_findings}</td>
                  <td>{scan.total_files}</td>
                  <td style={{ whiteSpace: "nowrap" }}>
                    {formatDate(scan.scan_date)}
                  </td>
                  <td>
                    {scan.blockchain_tx ? (
                      <span
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: "4px",
                          color: "var(--color-success)",
                          fontSize: "12px",
                        }}
                      >
                        <LinkIcon size={12} />
                        On-chain
                      </span>
                    ) : (
                      <span
                        style={{
                          color: "var(--color-text-muted)",
                          fontSize: "12px",
                        }}
                      >
                        —
                      </span>
                    )}
                  </td>
                  <td>
                    <div
                      style={{
                        display: "flex",
                        gap: "4px",
                        alignItems: "center",
                      }}
                    >
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={(e) => handleDelete(e, scan.id)}
                        title="Delete scan"
                      >
                        <Trash2 size={14} color="var(--color-danger)" />
                      </button>
                      <ArrowRight
                        size={14}
                        color="var(--color-text-muted)"
                      />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
