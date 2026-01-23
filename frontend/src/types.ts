export type Finding = {
  severity: string;
  package: string;
  installed: string;
  fixed: string;
  usn?: string | null;
  cves: string[];
  action: string;
};

export type ScanResult = {
  scan_id: string;
  codename: string;
  total_packages: number;
  findings: Finding[];
};

export type ValidationRun = {
  run_id: string;
  package: string;
  status: string;
  started_at?: string | null;
  finished_at?: string | null;
  error?: string | null;
  summary?: {
    result: string;
    artifacts: string[];
  };
};
