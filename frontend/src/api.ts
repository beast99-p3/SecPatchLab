import { ScanResult, ValidationRun } from "./types";

export async function runScan(top?: number, refresh?: boolean): Promise<{ scan_id: string; results: ScanResult }> {
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ top, refresh })
  });
  if (!res.ok) {
    let detail = "Failed to run scan";
    try {
      const data = await res.json();
      if (data?.detail) detail = data.detail;
    } catch {
      try {
        const text = (await res.text()).trim();
        if (text) detail = text.length > 300 ? text.slice(0, 300) + "…" : text;
      } catch {
        // ignore
      }
    }
    throw new Error(detail);
  }
  return res.json();
}

export async function listScans(): Promise<any[]> {
  const res = await fetch("/api/scans");
  if (!res.ok) throw new Error("Failed to list scans");
  return res.json();
}

export async function getScan(scanId: string): Promise<ScanResult> {
  const res = await fetch(`/api/scans/${scanId}`);
  if (!res.ok) throw new Error("Failed to get scan");
  return res.json();
}

export async function validatePackage(pkg: string, patchPath?: string, release?: string): Promise<{ run_id: string; status: string }> {
  const res = await fetch("/api/validate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ package: pkg, patch_path: patchPath || null, release })
  });
  if (!res.ok) throw new Error("Failed to start validation");
  return res.json();
}

export async function listRuns(): Promise<ValidationRun[]> {
  const res = await fetch("/api/runs");
  if (!res.ok) throw new Error("Failed to list runs");
  return res.json();
}

export async function getRun(runId: string): Promise<ValidationRun> {
  const res = await fetch(`/api/runs/${runId}`);
  if (!res.ok) throw new Error("Failed to get run");
  return res.json();
}

export async function getRunLog(runId: string): Promise<string> {
  const res = await fetch(`/api/runs/${runId}/log`);
  if (!res.ok) throw new Error("Failed to get log");
  return res.text();
}

export async function getArtifacts(runId: string): Promise<{ artifacts: { name: string; path: string; url: string }[] }> {
  const res = await fetch(`/api/runs/${runId}/artifacts`);
  if (!res.ok) throw new Error("Failed to get artifacts");
  return res.json();
}
