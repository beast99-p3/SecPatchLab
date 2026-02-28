import { useEffect, useState } from "react";
import { runScan, validatePackage, listRuns, getRun, getRunLog, getArtifacts, listScans, getScan } from "./api";
import { Finding, ValidationRun } from "./types";

export default function App() {
  const [activeTab, setActiveTab] = useState<"scan" | "runs">("scan");
  const [topN, setTopN] = useState<number>(10);
  const [refreshFeeds, setRefreshFeeds] = useState<boolean>(false);
  const [scanFindings, setScanFindings] = useState<Finding[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanErrorMessage, setScanErrorMessage] = useState<string>("");
  const [scanInfo, setScanInfo] = useState<{ scan_id: string; codename: string; total_packages: number } | null>(null);
  const [availableScans, setAvailableScans] = useState<{ scan_id: string; codename: string; findings: number }[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [isValidateModalOpen, setIsValidateModalOpen] = useState(false);
  const [selectedPackage, setSelectedPackage] = useState<string>("");
  const [patchFilePath, setPatchFilePath] = useState<string>("");
  const [targetRelease, setTargetRelease] = useState<string>("");

  const [validationRuns, setValidationRuns] = useState<ValidationRun[]>([]);
  const [selectedValidationRun, setSelectedValidationRun] = useState<ValidationRun | null>(null);
  const [validationLog, setValidationLog] = useState<string>("");
  const [runArtifacts, setRunArtifacts] = useState<{ name: string; url: string }[]>([]);

  const fetchRuns = async () => {
    const data = await listRuns();
    setValidationRuns(data);
  };

  const fetchScans = async () => {
    const data = await listScans();
    setAvailableScans(data);
    if (!selectedScanId && data.length > 0) {
      setSelectedScanId(data[0].scan_id);
    }
  };

  const runScanNow = async () => {
    setIsScanning(true);
    setScanErrorMessage("");
    try {
      const res = await runScan(topN, refreshFeeds);
      setScanFindings(res.results.findings || []);
      setScanInfo({
        scan_id: res.results.scan_id,
        codename: res.results.codename,
        total_packages: res.results.total_packages,
      });
      await fetchScans();
    } catch (err: any) {
      setScanFindings([]);
      setScanInfo(null);
      setScanErrorMessage(err?.message || "Scan failed");
    } finally {
      setIsScanning(false);
    }
  };

  const loadSelectedScan = async () => {
    if (!selectedScanId) return;
    setScanErrorMessage("");
    try {
      const res = await getScan(selectedScanId);
      setScanFindings(res.findings || []);
      setScanInfo({
        scan_id: res.scan_id,
        codename: res.codename,
        total_packages: res.total_packages,
      });
    } catch (err: any) {
      setScanFindings([]);
      setScanInfo(null);
      setScanErrorMessage(err?.message || "Failed to load scan");
    }
  };

  const openValidationModal = (pkg: string) => {
    setSelectedPackage(pkg);
    setPatchFilePath("");
    setTargetRelease("");
    setIsValidateModalOpen(true);
  };

  const startValidationRun = async () => {
    await validatePackage(selectedPackage, patchFilePath || undefined, targetRelease || undefined);
    setIsValidateModalOpen(false);
    await fetchRuns();
    setActiveTab("runs");
  };

  const openValidationDetails = async (run: ValidationRun) => {
    const full = await getRun(run.run_id);
    setSelectedValidationRun(full);
    setValidationLog(await getRunLog(run.run_id));
    const arts = await getArtifacts(run.run_id);
    setRunArtifacts(arts.artifacts.map(a => ({ name: a.name, url: a.url })));
  };

  useEffect(() => {
    fetchRuns();
    fetchScans();
  }, []);

  return (
    <div className="container">
      <div className="header">
        <div className="brand">
          <div className="brand-badge">S</div>
          <div>
            <h2>SecPatchLab</h2>
            <div style={{ color: "#e0e7ff" }}>
              Security scans and patch validation in one place
            </div>
          </div>
        </div>
      </div>

      <div className="tabs">
        <div className={`tab ${activeTab === "scan" ? "active" : ""}`} onClick={() => setActiveTab("scan")}>Scan</div>
        <div className={`tab ${activeTab === "runs" ? "active" : ""}`} onClick={() => setActiveTab("runs")}>Validation Runs</div>
      </div>

      {activeTab === "scan" && (
        <div className="card">
          <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12 }}>
            <label>Top findings <input type="number" value={topN} onChange={(e) => setTopN(Number(e.target.value))} /></label>
            <label><input type="checkbox" checked={refreshFeeds} onChange={(e) => setRefreshFeeds(e.target.checked)} /> Refresh OVAL feeds</label>
            <button onClick={runScanNow} disabled={isScanning}>{isScanning ? "Scanning..." : "Run Scan"}</button>
          </div>

          <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12 }}>
            <label>
              Load previous scan{" "}
              <select value={selectedScanId} onChange={(e) => setSelectedScanId(e.target.value)} style={{ marginLeft: 8 }}>
                {availableScans.map((s) => (
                  <option key={s.scan_id} value={s.scan_id}>
                    {s.scan_id} ({s.codename}, {s.findings} findings)
                  </option>
                ))}
              </select>
            </label>
            <button className="secondary" onClick={loadSelectedScan} disabled={!selectedScanId}>Load</button>
          </div>

          {scanErrorMessage && (
            <div style={{ marginBottom: 12, color: "#b91c1c" }}>
              {scanErrorMessage}
            </div>
          )}
          {scanInfo && (
            <div style={{ marginBottom: 12 }}>
              Scan {scanInfo.scan_id} on {scanInfo.codename} ({scanInfo.total_packages} packages)
            </div>
          )}

          <table className="table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Package</th>
                <th>Installed</th>
                <th>Fixed</th>
                <th>USN/CVE</th>
                <th>Action</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {scanFindings.map((f) => (
                <tr key={`${f.package}-${f.fixed}`}>
                  <td>{f.severity}</td>
                  <td>{f.package}</td>
                  <td>{f.installed}</td>
                  <td>{f.fixed}</td>
                  <td>{[f.usn, ...(f.cves || [])].filter(Boolean).join(", ")}</td>
                  <td>{f.action}</td>
                  <td><button className="secondary" onClick={() => openValidationModal(f.package)}>Validate in Sandbox</button></td>
                </tr>
              ))}
              {scanFindings.length === 0 && scanInfo && (
                <tr>
                  <td colSpan={7}>No findings for this scan.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === "runs" && (
        <div className="card">
          <button onClick={fetchRuns} style={{ marginBottom: 12 }}>Refresh</button>
          <table className="table">
            <thead>
              <tr>
                <th>Run</th>
                <th>Package</th>
                <th>Status</th>
                <th>Started</th>
                <th>Finished</th>
              </tr>
            </thead>
            <tbody>
              {validationRuns.map((r) => (
                <tr key={r.run_id} onClick={() => openValidationDetails(r)} style={{ cursor: "pointer" }}>
                  <td>{r.run_id}</td>
                  <td>{r.package}</td>
                  <td><span className={`badge ${r.status}`}>{r.status}</span></td>
                  <td>{r.started_at || "-"}</td>
                  <td>{r.finished_at || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {selectedValidationRun && (
            <div style={{ marginTop: 16 }}>
              <h3>Run Details</h3>
              <p>Package: {selectedValidationRun.package}</p>
              <p>Status: {selectedValidationRun.status}</p>
              {selectedValidationRun.summary?.result && <p>Result: {selectedValidationRun.summary.result}</p>}

              <h4>Log</h4>
              <div className="log">{validationLog || "No log"}</div>

              <h4>Artifacts</h4>
              <ul>
                {runArtifacts.map((a) => (
                  <li key={a.name}><a href={a.url}>{a.name}</a></li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {isValidateModalOpen && (
        <div className="modal-backdrop" onClick={() => setIsValidateModalOpen(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>Validate {selectedPackage}</h3>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <label>Patch path on server (optional)</label>
              <input value={patchFilePath} onChange={(e) => setPatchFilePath(e.target.value)} placeholder="/path/to/patch.diff" />
              <label>Ubuntu release (optional)</label>
              <input value={targetRelease} onChange={(e) => setTargetRelease(e.target.value)} placeholder="noble" />
              <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                <button onClick={startValidationRun}>Start validation</button>
                <button className="secondary" onClick={() => setIsValidateModalOpen(false)}>Cancel</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
