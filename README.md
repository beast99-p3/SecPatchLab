# SecPatchLab

**Version 0.2.0**

SecPatchLab is a full-stack Ubuntu security monitoring and patch-validation sandbox with a FastAPI backend and a React (Vite + TypeScript) frontend. It inventories installed packages, matches them against Canonical Ubuntu OVAL (USN) feeds, and can validate patches in a Docker-based build/test sandbox.

## Features
- **Ubuntu Security Monitor (non-root)**: Scans installed packages and compares against OVAL fixed versions.
- **Patch-Validation Sandbox (Docker)**: Builds and tests packages with optional patch application.
- **FastAPI backend**: REST endpoints for scans and validation runs.
- **React frontend**: Scan results, run status, logs, and artifacts.
- **SARIF Export**: GitHub Security-compatible SARIF report generation.
- **SBOM Generation**: Software Bill of Materials for validated packages.
- **CLI & API**: Both command-line and REST API interfaces.
- **CVE Demonstration**: Complete CVE workflow demonstration mode.

## Notes
- OVAL feed mapping is centralized. If Canonical changes file naming, update the mapping in `secpatchlab/core/oval.py`.
- Validation requires Docker. The tool fails gracefully if Docker isn’t available.

## Sandbox Hardening
Validation runs use a hardened `docker run` configuration by default:
- Drops Linux capabilities (`--cap-drop ALL`)
- Resource limits (`--memory 512m`, `--cpus 1.0`, `--pids-limit 128`)
- Filesystem restrictions (`--read-only`, `--tmpfs /tmp:rw,noexec,nosuid,size=100m`)
- Network isolation (`--network none`)
- Optional seccomp profile: `docker/seccomp-secpatchlab.json`
- Optional AppArmor (when available): `--security-opt apparmor=docker-default`

If your Docker host doesn’t support one of these options, SecPatchLab falls back to a simpler `docker run` so the validation still executes, and the run log/summary reflects what happened.

## OVAL Feed Reliability
OVAL feeds are downloaded and cached locally in `~/.cache/secpatchlab`.
- Conditional requests via ETag (`If-None-Match`) when available
- Fallback mirrors (Canonical primary + secondary mirror)
- Basic content validation (must parse as OVAL XML)
- SHA256 hashing to detect feed changes/corruption and avoid unnecessary rewrites

Use `--refresh` to force a refresh.

## Version Semantics
Package vulnerability comparison uses Debian/Ubuntu version semantics (epochs, revisions, backports), not naive string comparison.

## Open‑Source Readiness
This project is safe to open source. It contains no hard‑coded secrets and uses public Ubuntu OVAL feeds by default. Keep local artifacts (runs/, .venv/, node_modules/) out of the repo, which is already handled by .gitignore.

## End‑to‑End Setup

### 0) Prerequisites
- Node.js 18+ for the frontend
- Docker Desktop for validation runs
- Python 3.11+ for the backend

### 1) Open in VS Code
Open this folder in VS Code.

### 2) Backend setup (Local Windows)

Run these in **PowerShell** (recommended on Windows):
```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -U pip
.\.venv\Scripts\python.exe -m pip install -e .
```

If you are using **Git Bash**, don’t run PowerShell cmdlets directly. Instead, either switch your VS Code terminal to PowerShell, or run Python via the venv path:
```bash
./.venv/Scripts/python.exe -m pip install -U pip
./.venv/Scripts/python.exe -m pip install -e .
```

### 3) Run backend (Local Windows)
```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

If you’re using **Git Bash**:
```bash
./.venv/Scripts/python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

### 4) Frontend setup (Windows terminal)
```bash
cd frontend
npm install
```

### 5) Run frontend (Windows terminal)
```bash
npm run dev -- --host
```
Open http://localhost:5173

### 6) Seed demo data (shows both success + failure)
If your machine is fully patched (or you’re not on Ubuntu), you can still demo the UI by seeding a scan with findings plus validation runs.
```bash
python -m secpatchlab.cli seed-demo
```

### 7) Show results in the UI
Open http://localhost:5173 and:
- In **Scan**, use **Load previous scan** and pick the `scan-demo-...` entry (it has findings)
- In **Validation Runs**, click `validate-demo-...-ok` (success) and `validate-demo-...-fail` (failure)

### 8) Docker Compose (backend + frontend)
```bash
docker compose up --build
```

## CLI Commands

### secpatchlab scan
Run a security vulnerability scan.
```bash
# Basic scan
secpatchlab scan

# Top 20 findings
secpatchlab scan --top 20

# Export to JSON
secpatchlab scan --format json --output results.json

# Export to SARIF (GitHub Security)
secpatchlab scan --format sarif --output results.sarif

# Refresh OVAL cache
secpatchlab scan --refresh
```

### secpatchlab validate
Run package validation in sandbox.
```bash
# Basic validation
secpatchlab validate --package openssl

# With custom patch
secpatchlab validate --package openssl --patch ./patches/fix.patch

# With specific Ubuntu release
secpatchlab validate --package sudo --release jammy

# Generate SBOM report
secpatchlab validate --package openssl --sbom
```

### secpatchlab demo
Run a complete CVE demonstration workflow.
```bash
# Demo with specific CVE
secpatchlab demo --cve CVE-2023-0464

# Generate reports
secpatchlab demo --cve CVE-2023-0464 --output-dir ./cve-reports

# Output formats
secpatchlab demo --cve CVE-2023-0464 --format sarif --output-dir ./reports
```

### secpatchlab run
Run end-to-end scan and validation workflow.
```bash
# Scan and validate top 3 packages
secpatchlab run --top 3
```

### secpatchlab seed-demo
Seed demo data under `runs/` (one scan with findings + one success run + one failure run) so the frontend can showcase both successful and failed validations.
```bash
secpatchlab seed-demo
```

## Makefile Targets
- `make scan` — Run vulnerability scan
- `make api` — Start FastAPI backend server
- `make ui` — Start React frontend dev server
- `make dev` — Run both backend and frontend
- `make validate PKG=openssl PATCH=./patches/fix.patch` — Validate a package

## Environment Variables
- `OVAL_BASE_URL` (default: https://security-metadata.canonical.com/oval/)

## API Endpoints

### Health Check
- `GET /api/health` — Check API status

### Vulnerability Scanning
- `POST /api/scan` — Run a vulnerability scan (body: `{"top": 20, "refresh": false}`)
- `GET /api/scans` — List all scan runs
- `GET /api/scans/{scan_id}` — Get scan results by ID

### Package Validation
- `POST /api/validate` — Start validation run (body: `{"package": "openssl", "patch_path": null, "release": null}`)
- `GET /api/runs` — List all validation runs
- `GET /api/runs/{run_id}` — Get validation run details
- `GET /api/runs/{run_id}/log` — Get validation run logs
- `GET /api/runs/{run_id}/artifacts` — List validation artifacts

## Testing
Run the test suite with pytest:
```bash
# Install pytest if not already installed
pip install pytest

# Run all tests
pytest

# Run specific test file
pytest tests/test_dpkg.py

# Run with verbose output
pytest -v
```

## Additional Documentation
See the `docs/` directory for detailed documentation:
- [correctness-evaluation.md](docs/correctness-evaluation.md) — Validation methodology and correctness
- [limitations.md](docs/limitations.md) — Known limitations and constraints
- [threat-model.md](docs/threat-model.md) — Security considerations and threat model

## Project Structure
- `secpatchlab/` — Core Python package and CLI
- `backend/` — FastAPI app
- `frontend/` — Vite + React UI
- `docker/` — Validation Dockerfile template and configs
- `runs/` — Scan and validation outputs
- `tests/` — Test suite (pytest)
- `docs/` — Additional documentation (limitations, threat model, correctness evaluation)

## Exporting to GitHub Security
Upload SARIF reports to GitHub Code Scanning.

For most repos, the most reliable approach is GitHub Actions using `github/codeql-action/upload-sarif`.

If you upload from the CLI, be aware GitHub’s API requirements can vary (for example: authentication scopes and whether the SARIF must be compressed/encoded). Treat the snippet below as an advanced option and verify against current GitHub docs for your repo.

Example CLI flow:
```bash
# Generate SARIF report
secpatchlab scan --format sarif --output results.sarif

# Upload to GitHub (requires gh CLI)
gh api repos/OWNER/REPO/code-scanning/sarifs \
  -F commit_sha=$(git rev-parse HEAD) \
  -F ref=refs/heads/main \
  -F sarif=@results.sarif
```

Or use the demo command with GitHub upload:
```bash
secpatchlab demo --cve CVE-2023-0464 --output-dir ./reports
gh api repos/OWNER/REPO/code-scanning/sarifs -F sarif=@./reports/cve-2023-0464-results.sarif
```

## Troubleshooting

### Common Issues
- **`/etc/os-release` not found**: You’re running a real scan on Windows (SecPatchLab’s scanner expects an Ubuntu-like environment). Use `seed-demo` to showcase the UI on Windows, or run scans from Ubuntu/WSL/Docker.
- **Frontend shows `POST http://127.0.0.1:5173/api/scan 500`**: In dev mode, Vite proxies `/api/*` to the backend at `http://127.0.0.1:8000`. Make sure the FastAPI server is running (Step 3) and that `http://127.0.0.1:8000/api/health` returns `{"status":"ok"}`.
- **`npm run dev -- --host` fails**: Ensure the command has the space before `--`.
- **`secpatchlab: command not found`**: The package isn't installed. Run `pip install -e .` in the project root.
- **Docker validation fails**: Ensure Docker Desktop is running.
- **OVAL cache errors**: Try running with `--refresh` to force refresh the OVAL cache.
- **Test failures**: Ensure you're in the correct Python environment and have installed test dependencies.

### Getting Help
Check the `docs/` directory for detailed information on limitations, threat model, and correctness evaluation.
