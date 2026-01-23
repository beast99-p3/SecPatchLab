from __future__ import annotations

from pydantic import BaseModel
from typing import List, Optional


class Finding(BaseModel):
    severity: str
    package: str
    installed: str
    fixed: str
    usn: str | None = None
    cves: List[str] = []
    action: str


class ScanResult(BaseModel):
    scan_id: str
    codename: str
    total_packages: int
    findings: List[Finding]


class ValidationStatus(BaseModel):
    run_id: str
    package: str
    status: str
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None


class ValidationSummary(BaseModel):
    run_id: str
    package: str
    release: str
    result: str
    started_at: str
    finished_at: str
    commands: List[str]
    artifacts: List[str]
    log_path: str
    error: Optional[str] = None
