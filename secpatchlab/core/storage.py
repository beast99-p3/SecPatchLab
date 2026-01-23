from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime
from uuid import uuid4

from secpatchlab.core.models import ScanResult
from secpatchlab.core.utils import ensure_dir, write_json

BASE_DIR = Path(__file__).resolve().parents[2]
RUNS_DIR = BASE_DIR / "runs"


def create_scan_id() -> str:
    return _make_id("scan")


def create_validation_id() -> str:
    return _make_id("validate")


def _make_id(prefix: str) -> str:
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{ts}-{uuid4().hex[:8]}"


def store_scan(result: ScanResult) -> None:
    ensure_dir(RUNS_DIR)
    scan_dir = RUNS_DIR / result.scan_id
    ensure_dir(scan_dir)
    write_json(scan_dir / "scan.json", result.model_dump())


def list_scans() -> list[dict]:
    ensure_dir(RUNS_DIR)
    items = []
    for d in sorted(RUNS_DIR.iterdir(), reverse=True):
        if not d.is_dir() or not d.name.startswith("scan-"):
            continue
        meta = load_scan(d.name)
        if meta:
            items.append({
                "scan_id": d.name,
                "codename": meta.get("codename"),
                "findings": len(meta.get("findings", [])),
            })
    return items


def load_scan(scan_id: str) -> dict | None:
    scan_dir = RUNS_DIR / scan_id
    path = scan_dir / "scan.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def get_validation_run_dir(run_id: str) -> Path | None:
    run_dir = RUNS_DIR / run_id
    return run_dir if run_dir.exists() else None


def list_validation_runs() -> list[dict]:
    ensure_dir(RUNS_DIR)
    items = []
    for d in sorted(RUNS_DIR.iterdir(), reverse=True):
        if not d.is_dir() or not d.name.startswith("validate-"):
            continue
        status_path = d / "status.json"
        if status_path.exists():
            data = json.loads(status_path.read_text(encoding="utf-8"))
            items.append(data)
    return items


def load_validation_run(run_id: str) -> dict | None:
    run_dir = RUNS_DIR / run_id
    if not run_dir.exists():
        return None
    summary_path = run_dir / "summary.json"
    status_path = run_dir / "status.json"
    data = {}
    if status_path.exists():
        data.update(json.loads(status_path.read_text(encoding="utf-8")))
    if summary_path.exists():
        data["summary"] = json.loads(summary_path.read_text(encoding="utf-8"))
    return data


def get_run_log_path(run_id: str) -> Path | None:
    run_dir = RUNS_DIR / run_id
    if not run_dir.exists():
        return None
    return run_dir / "run.log"
