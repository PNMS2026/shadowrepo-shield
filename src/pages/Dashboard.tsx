import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Shield,
  AlertTriangle,
  Activity,
  FolderSearch,
  ArrowRight,
  ScanSearch,
  CheckCircle2,
} from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import StatCard from "../components/StatCard";
import RiskBadge from "../components/RiskBadge";
import { getScanHistory, getDashboardStats } from "../lib/tauri";
import type { ScanSummary, DashboardStats } from "../types";

export default function Dashboard() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [stats, setStats] = useState<DashboardStats>({
    total_scans: 0,
    critical_findings: 0,
    average_risk: 0,
    repos_scanned: 0,
    verified_scans: 0,
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [scanData, statsData] = await Promise.all([
          getScanHistory(),
          getDashboardStats(),
        ]);
        setScans(scanData);
        setStats(statsData as DashboardStats);
      } catch (err) {
        console.error("Failed to load dashboard data:", err);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const riskDistribution = [
    {
      name: "Critical",
      value: scans.filter((s) => s.risk_level === "critical").length,
      color: "#f85149",
    },
    {
      name: "High",
      value: scans.filter((s) => s.risk_level === "high").length,
      color: "#db6d28",
    },
    {
      name: "Review Recommended",
      value: scans.filter((s) => s.risk_level === "review_recommended").length,
      color: "#d29922",
    },
    {
      name: "Low",
      value: scans.filter((s) => s.risk_level === "low").length,
      color: "#2ea043",
    },
  ].filter((d) => d.value > 0);

  function formatDate(iso: string): string {
    const d = new Date(iso);
    const now = new Date();
    const diff = now.getTime() - d.getTime();
    const hours = Math.floor(diff / 3600000);
    if (hours < 1) return "Just now";
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    if (days < 7) return `${days}d ago`;
    return d.toLocaleDateString();
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
        <h1>Dashboard</h1>
        <p>
          Overview of your repository security scans. Your code stays on your
          device.
        </p>
      </div>

      {/* Stats Grid */}
      <div className="stats-grid">
        <StatCard
          icon={<FolderSearch size={20} />}
          value={stats.total_scans}
          label="Total Scans"
          color="var(--color-brand-accent)"
          bgColor="var(--color-surface-700)"
        />
        <StatCard
          icon={<AlertTriangle size={20} />}
          value={stats.critical_findings}
          label="Critical Findings"
          color="var(--color-danger)"
          bgColor="rgba(248, 81, 73, 0.1)"
        />
        <StatCard
          icon={<Activity size={20} />}
          value={stats.average_risk}
          label="Avg Risk Score"
          color="var(--color-warning)"
          bgColor="rgba(210, 153, 34, 0.1)"
        />
        <StatCard
          icon={<Shield size={20} />}
          value={stats.repos_scanned}
          label="Repos Scanned"
          color="var(--color-success)"
          bgColor="rgba(46, 160, 67, 0.1)"
        />
        <StatCard
          icon={<CheckCircle2 size={20} />}
          value={stats.verified_scans}
          label="Verified Scans"
          color="#10b981"
          bgColor="rgba(16, 185, 129, 0.1)"
        />
      </div>

      {/* Main Content Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 320px", gap: "16px" }}>
        {/* Recent Scans Table */}
        <div className="table-container">
          <div className="table-header">
            <h2>Recent Scans</h2>
            <button
              className="btn btn-sm btn-secondary"
              onClick={() => navigate("/scan")}
            >
              <ScanSearch size={14} />
              New Scan
            </button>
          </div>
          {scans.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">
                <FolderSearch size={28} />
              </div>
              <h3>No scans yet</h3>
              <p>Start your first repository security scan</p>
              <button
                className="btn btn-primary"
                onClick={() => navigate("/scan")}
              >
                <ScanSearch size={16} />
                Start Scanning
              </button>
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Repository</th>
                  <th>Risk</th>
                  <th>Findings</th>
                  <th>Files</th>
                  <th>When</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 5).map((scan) => (
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
                          maxWidth: "200px",
                        }}
                      >
                        {getDisplayPath(scan.path)}
                      </div>
                    </td>
                    <td>
                      <RiskBadge riskLevel={scan.risk_level} size="sm" />
                    </td>
                    <td>{scan.total_findings}</td>
                    <td>{scan.total_files}</td>
                    <td>{formatDate(scan.scan_date)}</td>
                    <td>
                      <ArrowRight
                        size={14}
                        color="var(--color-text-muted)"
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Risk Distribution */}
        <div className="card">
          <h3
            style={{
              fontSize: "14px",
              fontWeight: 600,
              marginBottom: "16px",
            }}
          >
            Risk Distribution
          </h3>
          {riskDistribution.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={riskDistribution}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {riskDistribution.map((entry, index) => (
                      <Cell key={index} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "var(--color-surface-700)",
                      border: "1px solid rgba(99,102,241,0.1)",
                      borderRadius: "8px",
                      fontSize: "12px",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div
                style={{
                  display: "flex",
                  flexWrap: "wrap",
                  gap: "12px",
                  justifyContent: "center",
                  marginTop: "8px",
                }}
              >
                {riskDistribution.map((d) => (
                  <div
                    key={d.name}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                      fontSize: "12px",
                      color: "var(--color-text-secondary)",
                    }}
                  >
                    <div
                      style={{
                        width: "8px",
                        height: "8px",
                        borderRadius: "2px",
                        background: d.color,
                      }}
                    />
                    {d.name} ({d.value})
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div
              className="flex-center"
              style={{
                height: 200,
                color: "var(--color-text-muted)",
                fontSize: "13px",
              }}
            >
              No data yet
            </div>
          )}
        </div>
      </div>


    </div>
  );
}
