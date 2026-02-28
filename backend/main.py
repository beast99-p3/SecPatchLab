from __future__ import annotations

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, FileResponse
from pydantic import BaseModel
from pathlib import Path

from secpatchlab.core import scan as scan_mod
from secpatchlab.core import validation as validation_mod
from secpatchlab.core import storage
from secpatchlab.core.utils import CommandError

app = FastAPI(title="SecPatchLab API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


class ScanRequest(BaseModel):
    top: int | None = None
    refresh: bool | None = None


class ValidateRequest(BaseModel):
    package: str
    patch_path: str | None = None
    release: str | None = None


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/scan")
def run_scan(req: ScanRequest):
    try:
        scan_id, result = scan_mod.perform_scan(top=req.top, refresh=req.refresh or False)
        return {"scan_id": scan_id, "results": result.model_dump()}
    except CommandError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}")


@app.get("/api/scans")
def list_scans():
    return storage.list_scans()


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    data = storage.load_scan(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    return data


@app.post("/api/validate")
def validate(req: ValidateRequest, background_tasks: BackgroundTasks):
    run_id = validation_mod.schedule_validation(
        background_tasks=background_tasks,
        package=req.package,
        patch_path=req.patch_path,
        release=req.release
    )
    return {"run_id": run_id, "status": "started"}


@app.get("/api/runs")
def list_runs():
    return storage.list_validation_runs()


@app.get("/api/runs/{run_id}")
def get_run(run_id: str):
    data = storage.load_validation_run(run_id)
    if not data:
        raise HTTPException(status_code=404, detail="Run not found")
    return data


@app.get("/api/runs/{run_id}/log")
def get_log(run_id: str):
    log_path = storage.get_run_log_path(run_id)
    if not log_path or not log_path.exists():
        raise HTTPException(status_code=404, detail="Log not found")
    return PlainTextResponse(log_path.read_text(encoding="utf-8", errors="replace"))


@app.get("/api/runs/{run_id}/artifacts")
def get_artifacts(run_id: str):
    run_dir = storage.get_validation_run_dir(run_id)
    if not run_dir:
        raise HTTPException(status_code=404, detail="Run not found")
    artifacts_dir = run_dir / "artifacts"
    items = []
    if artifacts_dir.exists():
        for p in artifacts_dir.iterdir():
            if p.is_file():
                rel_path = str(p.relative_to(run_dir)).replace("\\", "/")
                items.append({
                    "name": p.name,
                    "path": rel_path,
                    "url": f"/api/runs/{run_id}/download?path={rel_path}",
                })
    return {"artifacts": items}


@app.get("/api/runs/{run_id}/download")
def download_artifact(run_id: str, path: str):
    run_dir = storage.get_validation_run_dir(run_id)
    if not run_dir:
        raise HTTPException(status_code=404, detail="Run not found")
    target = (run_dir / path).resolve()
    if not str(target).startswith(str(run_dir.resolve())):
        raise HTTPException(status_code=400, detail="Invalid path")
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(str(target))
