from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional

from secpatchlab.core import storage
from secpatchlab.core.utils import ensure_dir, run_cmd, write_json, utc_now, CommandError
from secpatchlab.core.models import ValidationSummary

BASE_DIR = Path(__file__).resolve().parents[2]
DOCKER_TEMPLATE = BASE_DIR / "docker" / "validator.Dockerfile"
DOCKER_ENTRYPOINT = BASE_DIR / "docker" / "validator-entrypoint.sh"


def _check_docker_available() -> None:
    try:
        run_cmd(["docker", "version"], timeout=20)
    except Exception as exc:
        raise CommandError("Docker not available") from exc


def _get_security_options(run_dir: Path) -> list[str]:
    """Build Docker security options with graceful fallback."""
    security_opts = []
    
    # Try to use seccomp profile
    seccomp_path = BASE_DIR / "docker" / "seccomp-secpatchlab.json"
    if seccomp_path.exists():
        security_opts.extend([
            "--security-opt", f"seccomp={seccomp_path}",
        ])
    else:
        # Fallback to default seccomp
        security_opts.extend([
            "--security-opt", "seccomp=unconfined",
        ])
    
    # Add AppArmor if available (Ubuntu/Debian)
    try:
        run_cmd(["which", "aa-status"], timeout=5)
        security_opts.extend([
            "--security-opt", "apparmor=docker-default",
        ])
    except:
        pass  # AppArmor not available, continue without it
    
    return security_opts


def _build_hardened_run_command(run_dir: Path, image_tag: str, package: str) -> list[str]:
    """Build hardened Docker run command with security controls."""
    cmd = [
        "docker", "run", "--rm",
        # Resource limits
        "--memory", "512m",
        "--cpus", "1.0",
        "--pids-limit", "128",
        # Security controls
        "--cap-drop", "ALL",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=100m",
        "--user", "1000:1000",
        # Volume mapping
        "-v", f"{str(run_dir)}:/out",
        # Network isolation
        "--network", "none",
    ]
    
    # Add security options with fallback
    security_opts = _get_security_options(run_dir)
    cmd.extend(security_opts)
    
    # Add image and command
    cmd.extend([image_tag, package])
    
    return cmd


def _write_status(run_dir: Path, data: dict) -> None:
    write_json(run_dir / "status.json", data)


def _build_context(run_dir: Path, patch_path: Optional[str]) -> Path:
    ctx = run_dir / "build-context"
    ensure_dir(ctx)
    shutil.copy(DOCKER_TEMPLATE, ctx / "Dockerfile")
    shutil.copy(DOCKER_ENTRYPOINT, ctx / "entrypoint.sh")

    patch_file = ctx / "patch.diff"
    if patch_path:
        shutil.copy(Path(patch_path), patch_file)
    else:
        patch_file.write_text("", encoding="utf-8")
    return ctx


def _run_validation(run_id: str, package: str, patch_path: Optional[str], release: Optional[str]) -> None:
    run_dir = storage.get_validation_run_dir(run_id)
    if not run_dir:
        return

    log_path = run_dir / "run.log"
    try:
        _check_docker_available()
    except CommandError as exc:
        _write_status(run_dir, {
            "run_id": run_id,
            "package": package,
            "status": "failure",
            "started_at": utc_now(),
            "finished_at": utc_now(),
            "error": str(exc),
        })
        return

    started = utc_now()
    _write_status(run_dir, {
        "run_id": run_id,
        "package": package,
        "status": "running",
        "started_at": started,
    })

    release = release or "jammy"
    build_ctx = _build_context(run_dir, patch_path)
    image_tag = f"secpatchlab-{run_id}"
    commands = []
    artifacts = []

    try:
        build_cmd = [
            "docker", "build",
            "-t", image_tag,
            "--build-arg", f"PACKAGE={package}",
            "--build-arg", f"RELEASE={release}",
            "--build-arg", "PATCH_FILE=patch.diff",
            str(build_ctx),
        ]
        commands.append(" ".join(build_cmd))
        run_cmd(build_cmd, timeout=3600, log_file=log_path)

        artifacts_dir = run_dir / "artifacts"
        ensure_dir(artifacts_dir)

        # Build hardened Docker run command
        hardened_run_cmd = _build_hardened_run_command(run_dir, image_tag, package)
        commands.append(" ".join(hardened_run_cmd))
        
        try:
            run_cmd(hardened_run_cmd, timeout=1800, log_file=log_path)
        except CommandError as exc:
            # Fallback to basic Docker run if hardened options fail
            if "unknown flag" in str(exc) or "not supported" in str(exc):
                basic_run_cmd = [
                    "docker", "run", "--rm",
                    "-v", f"{str(run_dir)}:/out",
                    "--memory", "512m",
                    "--cap-drop", "ALL",
                    image_tag,
                    package,
                ]
                commands.append(f"# Fallback: {' '.join(basic_run_cmd)}")
                run_cmd(basic_run_cmd, timeout=1800, log_file=log_path)
            else:
                raise

        for p in (run_dir / "artifacts").iterdir():
            if p.is_file():
                artifacts.append(p.name)

        finished = utc_now()
        summary = ValidationSummary(
            run_id=run_id,
            package=package,
            release=release,
            result="success",
            started_at=started,
            finished_at=finished,
            commands=commands,
            artifacts=artifacts,
            log_path=str(log_path),
        )
        write_json(run_dir / "summary.json", summary.model_dump())
        _write_status(run_dir, {
            "run_id": run_id,
            "package": package,
            "status": "success",
            "started_at": started,
            "finished_at": finished,
        })
    except Exception as exc:
        finished = utc_now()
        summary = ValidationSummary(
            run_id=run_id,
            package=package,
            release=release,
            result="failure",
            started_at=started,
            finished_at=finished,
            commands=commands,
            artifacts=artifacts,
            log_path=str(log_path),
            error=str(exc),
        )
        write_json(run_dir / "summary.json", summary.model_dump())
        _write_status(run_dir, {
            "run_id": run_id,
            "package": package,
            "status": "failure",
            "started_at": started,
            "finished_at": finished,
            "error": str(exc),
        })


def schedule_validation(background_tasks, package: str, patch_path: Optional[str], release: Optional[str]) -> str:
    run_id = storage.create_validation_id()
    run_dir = storage.RUNS_DIR / run_id
    ensure_dir(run_dir)
    _write_status(run_dir, {
        "run_id": run_id,
        "package": package,
        "status": "queued",
        "started_at": None,
        "finished_at": None,
    })
    background_tasks.add_task(_run_validation, run_id, package, patch_path, release)
    return run_id


def run_validation_sync(package: str, patch_path: Optional[str], release: Optional[str]) -> str:
    run_id = storage.create_validation_id()
    run_dir = storage.RUNS_DIR / run_id
    ensure_dir(run_dir)
    _write_status(run_dir, {
        "run_id": run_id,
        "package": package,
        "status": "queued",
        "started_at": None,
        "finished_at": None,
    })
    _run_validation(run_id, package, patch_path, release)
    return run_id
