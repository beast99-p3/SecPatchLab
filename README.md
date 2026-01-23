# SecPatchLab

SecPatchLab is a full-stack Ubuntu security monitoring and patch-validation sandbox with a FastAPI backend and a React (Vite + TypeScript) frontend. It inventories installed packages, matches them against Canonical Ubuntu OVAL (USN) feeds, and can validate patches in a Docker-based build/test sandbox.

## Features
- Ubuntu Security Monitor (non-root): scans installed packages and compares against OVAL fixed versions.
- Patch-Validation Sandbox (Docker): builds and tests packages with optional patch application.
- FastAPI backend: REST endpoints for scans and validation runs.
- React frontend: scan results, run status, logs, and artifacts.

## Notes
- OVAL feed mapping is centralized. If Canonical changes file naming, update the mapping in `secpatchlab/core/oval.py`.
- Validation requires Docker. The tool fails gracefully if Docker isn’t available.

## Open‑Source Readiness
This project is safe to open source. It contains no hard‑coded secrets and uses public Ubuntu OVAL feeds by default. Keep local artifacts (runs/, .venv/, node_modules/) out of the repo, which is already handled by .gitignore.

## End‑to‑End Setup

### 0) Prerequisites
- Node.js 18+ for the frontend
- Docker Desktop for validation runs
- Ubuntu environment for scanning (WSL2 on Windows is recommended)

### 1) Open in VS Code
Open this folder in VS Code.

### 2) Windows + WSL (recommended)
Scanning requires Ubuntu (dpkg and /etc/os-release). Run the backend in WSL and the frontend in Windows.

#### 2.1) Install WSL (PowerShell as Admin)
```bash
wsl --install -d Ubuntu
```
Reboot and open the Ubuntu terminal.

#### 2.2) Ubuntu packages (WSL)
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-dev build-essential
```

### 3) Backend setup (WSL)
```bash
cd /mnt/c/Users/priye/OneDrive\ -\ The\ George\ Washington\ University/Documents/Projects/SecPatchLab
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 4) Run backend (WSL)
```bash
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

### 5) Frontend setup (Windows terminal)
```bash
cd frontend
npm install
```

### 6) Run frontend (Windows terminal)
```bash
npm run dev -- --host
```
Open http://localhost:5173

### 7) Run a scan (UI)
In the Scan tab, choose Top findings and press Run Scan.

### 8) Run a scan (CLI, in WSL)
```bash
secpatchlab scan --top 20
```

### 9) Trigger validation (CLI, in WSL)
```bash
secpatchlab validate --package openssl
```

### 10) Docker Compose (backend + frontend)
```bash
docker compose up --build
```

## Makefile Targets
- make scan
- make api
- make ui
- make dev
- make validate PKG=openssl PATCH=./patches/fix.patch

## Makefile Targets
- `make scan`
- `make api`
- `make ui`
- `make dev`
- `make validate PKG=openssl PATCH=./patches/fix.patch`

## Environment Variables
- `OVAL_BASE_URL` (default: https://security-metadata.canonical.com/oval/)

## Project Structure
- `secpatchlab/` — core Python package and CLI
- `backend/` — FastAPI app
- `frontend/` — Vite + React UI
- `docker/` — validation Dockerfile template
- `runs/` — scan and validation outputs

## Troubleshooting
- Scan stuck on Running: ensure the backend is running in WSL/Ubuntu and not Windows.
- /etc/os-release not found: you’re running the backend on Windows. Move backend to WSL.
- npm run dev -- --host fails: ensure the command has the space before --.
