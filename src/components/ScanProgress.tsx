interface ScanProgressProps {
  isScanning: boolean;
  progress: number;
  filesScanned: number;
  currentFile?: string;
}

export default function ScanProgress({
  isScanning,
  progress,
  filesScanned,
  currentFile,
}: ScanProgressProps) {
  if (!isScanning) return null;

  return (
    <div className="scan-progress-overlay">
      <div className="scan-progress-card animate-fade-in">
        <div className="spinner" style={{ margin: "0 auto 20px" }} />
        <h3
          style={{
            fontSize: "18px",
            fontWeight: 700,
            marginBottom: "8px",
          }}
        >
          Scanning Repository...
        </h3>
        <p
          style={{
            fontSize: "13px",
            color: "var(--color-text-secondary)",
            marginBottom: "20px",
          }}
        >
          Analyzing files for security threats. Your code never leaves this
          device.
        </p>

        <div className="progress-bar" style={{ marginBottom: "12px" }}>
          <div className="progress-fill" style={{ width: `${progress}%` }} />
        </div>

        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            fontSize: "12px",
            color: "var(--color-text-muted)",
          }}
        >
          <span>{filesScanned} files scanned</span>
          <span>{Math.round(progress)}%</span>
        </div>

        {currentFile && (
          <div
            className="text-mono truncate"
            style={{
              marginTop: "12px",
              fontSize: "11px",
              color: "var(--color-text-muted)",
              maxWidth: "360px",
            }}
          >
            {currentFile}
          </div>
        )}
      </div>
    </div>
  );
}
