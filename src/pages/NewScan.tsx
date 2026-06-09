import { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  Upload,
  FolderOpen,
  ScanSearch,
  FileArchive,
  X,
  Globe,
} from "lucide-react";
import ScanProgress from "../components/ScanProgress";
import { startScan, uploadAndScan, scanGitUrl, selectFolder, selectZipFile } from "../lib/tauri";
import type { ScanResult } from "../types";

export default function NewScan() {
  const navigate = useNavigate();

  const [scanName, setScanName] = useState("");
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [selectedGitUrl, setSelectedGitUrl] = useState<string | null>(null);
  const [gitUrlInput, setGitUrlInput] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [filesScanned, setFilesScanned] = useState(0);
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFolderSelect = useCallback(async () => {
    try {
      const folder = await selectFolder();
      if (folder) {
        setSelectedPath(folder);
        setSelectedFile(null);
        setSelectedGitUrl(null);
        setError(null);
        if (!scanName) {
          const parts = folder.split(/[/\\]/);
          setScanName(parts[parts.length - 1] || "");
        }
      }
    } catch (err) {
      setError("Failed to open folder picker");
    }
  }, [scanName]);

  const handleZipSelect = useCallback(async () => {
    try {
      const file = await selectZipFile();
      if (file) {
        setSelectedFile(file);
        setSelectedPath(null);
        setSelectedGitUrl(null);
        setError(null);
        if (!scanName) {
          const parts = file.split(/[/\\]/);
          const filename = parts[parts.length - 1] || "";
          setScanName(filename.replace(".zip", ""));
        }
      }
    } catch (err) {
      setError("Failed to open file picker");
    }
  }, [scanName]);

  const handleFileDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);

      const files = e.dataTransfer.files;
      if (files.length > 0) {
        const file = files[0];
        if (file.name.endsWith(".zip")) {
          setSelectedFile(file.name);
          setSelectedPath(null);
          setSelectedGitUrl(null);
          setError(null);
          if (!scanName) {
            setScanName(file.name.replace(".zip", ""));
          }
        } else {
          setError("Please upload a .zip file");
        }
      }
    },
    [scanName]
  );

  const handleGitSelect = useCallback(() => {
    setSelectedPath(null);
    setSelectedFile(null);
    setSelectedGitUrl("");
    setError(null);
  }, []);

  const handleStartScan = useCallback(async () => {
    const targetGitUrl = selectedGitUrl !== null ? gitUrlInput.trim() : null;

    if (!selectedPath && !selectedFile && !targetGitUrl) {
      setError("Please select a folder, upload a ZIP file, or enter a GitHub URL");
      return;
    }
    if (!scanName.trim()) {
      setError("Please enter a scan name");
      return;
    }

    setIsScanning(true);
    setProgress(0);
    setFilesScanned(0);
    setError(null);

    // Simulate progress for UI feedback
    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 90) return prev;
        return prev + Math.random() * 15;
      });
      setFilesScanned((prev) => prev + Math.floor(Math.random() * 20));
    }, 500);

    try {
      let result: ScanResult;
      if (selectedPath) {
        result = await startScan(selectedPath, scanName);
      } else if (selectedFile) {
        result = await uploadAndScan(selectedFile!, scanName);
      } else {
        result = await scanGitUrl(targetGitUrl!, scanName);
      }

      clearInterval(progressInterval);
      setProgress(100);

      // Navigate to result after brief delay
      setTimeout(() => {
        navigate(`/result/${result.id}`);
      }, 500);
    } catch (err) {
      clearInterval(progressInterval);
      setIsScanning(false);
      const errorMsg = typeof err === "string"
        ? err
        : err instanceof Error
          ? err.message
          : (err && typeof err === "object" && "message" in err)
            ? String((err as any).message)
            : JSON.stringify(err);
      setError(errorMsg || "Scan failed. Please try again.");
    }
  }, [selectedPath, selectedFile, selectedGitUrl, gitUrlInput, scanName, navigate]);

  const clearSelection = () => {
    setSelectedPath(null);
    setSelectedFile(null);
    setSelectedGitUrl(null);
    setGitUrlInput("");
    setError(null);
  };

  return (
    <div className="page-container animate-fade-in">
      <div className="page-header">
        <h1>New Scan</h1>
        <p>
          Upload a ZIP repository or select a local folder to scan for security
          threats.
        </p>
      </div>

      {/* Scan Mode Info */}
      <div
        style={{
          display: "flex",
          alignItems: "flex-start",
          gap: "12px",
          padding: "14px 16px",
          background: "rgba(245, 158, 11, 0.06)",
          border: "1px solid rgba(245, 158, 11, 0.12)",
          borderRadius: "8px",
          marginBottom: "16px",
          fontSize: "12px",
          color: "var(--color-text-secondary)",
          lineHeight: 1.5,
        }}
      >
        <span style={{ fontSize: "18px", flexShrink: 0 }}>🟡</span>
        <div>
          <strong style={{ color: "var(--color-text-primary)" }}>
            Local Scan Mode
          </strong>
          <div style={{ marginTop: "4px" }}>
            All scans from this desktop app are classified as{" "}
            <strong>Local Scans</strong> — self-reported and not independently
            verified. For trusted, independently verified scans, use the{" "}
            <strong>ShadowRepo Shield GitHub Action</strong> in your CI/CD
            pipeline.
          </div>
        </div>
      </div>

      {/* Scan Name */}
      <div className="card" style={{ marginBottom: "16px" }}>
        <label
          style={{
            display: "block",
            fontSize: "13px",
            fontWeight: 600,
            marginBottom: "8px",
          }}
        >
          Scan Name
        </label>
        <input
          id="scan-name-input"
          type="text"
          className="input"
          placeholder="e.g., suspicious-defi-protocol"
          value={scanName}
          onChange={(e) => setScanName(e.target.value)}
        />
      </div>

      {/* Source Selection */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "16px", marginBottom: "16px" }}>
        <div
          className={`drop-zone${dragOver ? " drag-over" : ""}`}
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleFileDrop}
          onClick={handleZipSelect}
        >
          <div className="drop-zone-icon">
            <Upload size={28} />
          </div>
          <h3>Select ZIP Repository</h3>
          <p>Choose a .zip archive from your device</p>
        </div>

        {/* Folder Selector */}
        <div
          className="drop-zone"
          onClick={handleFolderSelect}
          style={{ cursor: "pointer" }}
        >
          <div className="drop-zone-icon">
            <FolderOpen size={28} />
          </div>
          <h3>Select Local Folder</h3>
          <p>Choose a repository folder from your device</p>
        </div>

        {/* GitHub URL Selector */}
        <div
          className={`drop-zone${selectedGitUrl !== null ? " drag-over" : ""}`}
          onClick={handleGitSelect}
          style={{ cursor: "pointer" }}
        >
          <div className="drop-zone-icon">
            <Globe size={28} />
          </div>
          <h3>Scan GitHub URL</h3>
          <p>Download and scan a public GitHub repository</p>
        </div>
      </div>

      {/* GitHub URL Input */}
      {selectedGitUrl !== null && (
        <div className="card animate-slide-in" style={{ marginBottom: "16px" }}>
          <label
            style={{
              display: "block",
              fontSize: "13px",
              fontWeight: 600,
              marginBottom: "8px",
            }}
          >
            GitHub Repository HTTPS URL
          </label>
          <input
            id="github-url-input"
            type="text"
            className="input"
            placeholder="e.g., https://github.com/owner/repository"
            value={gitUrlInput}
            onChange={(e) => {
              const val = e.target.value;
              setGitUrlInput(val);
              if (val.includes("github.com/")) {
                const parts = val.split("github.com/")[1]?.split("/");
                if (parts && parts[1]) {
                  const repoName = parts[1].replace(".git", "");
                  if (!scanName) {
                    setScanName(repoName);
                  }
                }
              }
            }}
          />
          <p style={{ fontSize: "11px", color: "var(--color-text-muted)", marginTop: "6px" }}>
            Only public repositories are supported. Downloaded and scanned locally.
          </p>
        </div>
      )}

      {/* Selection Status */}
      {(selectedPath || selectedFile || (selectedGitUrl !== null && gitUrlInput)) && (
        <div
          className="card animate-slide-in"
          style={{
            marginBottom: "16px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            {selectedFile ? (
              <FileArchive size={20} color="var(--color-brand-accent)" />
            ) : selectedPath ? (
              <FolderOpen size={20} color="var(--color-brand-accent)" />
            ) : (
              <Globe size={20} color="var(--color-brand-accent)" />
            )}
            <div>
              <div
                style={{
                  fontSize: "13px",
                  fontWeight: 600,
                  color: "var(--color-text-primary)",
                }}
              >
                {selectedFile ? "ZIP File Selected" : selectedPath ? "Folder Selected" : "GitHub Repository Target"}
              </div>
              <div
                className="text-mono"
                style={{
                  fontSize: "12px",
                  color: "var(--color-text-muted)",
                }}
              >
                {selectedFile || selectedPath || gitUrlInput}
              </div>
            </div>
          </div>
          <button className="btn btn-ghost btn-sm" onClick={clearSelection}>
            <X size={14} />
          </button>
        </div>
      )}

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
          }}
        >
          {error}
        </div>
      )}

      {/* Start Scan Button */}
      <button
        id="start-scan-btn"
        className="btn btn-primary btn-lg"
        style={{ width: "100%" }}
        onClick={handleStartScan}
        disabled={isScanning || (!selectedPath && !selectedFile && !(selectedGitUrl !== null && gitUrlInput.trim()))}
      >
        <ScanSearch size={18} />
        {isScanning ? "Scanning..." : "Start Security Scan"}
      </button>

      {/* Security Notice */}
      <div className="disclaimer" style={{ marginTop: "20px" }}>
        <strong>🔒 Privacy Guarantee:</strong> Your code is scanned entirely on
        this device. No source code is ever uploaded to any server. Only
        cryptographic hashes may be submitted to blockchain for proof
        verification.
      </div>

      <ScanProgress
        isScanning={isScanning}
        progress={progress}
        filesScanned={filesScanned}
      />
    </div>
  );
}
