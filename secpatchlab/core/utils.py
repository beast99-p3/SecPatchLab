from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Iterable


class CommandError(RuntimeError):
    pass


def is_windows() -> bool:
    return os.name == "nt"


def wsl_available() -> bool:
    if not is_windows():
        return False
    try:
        # Cheap check that WSL is installed and can run a command.
        subprocess.run(["wsl", "-e", "true"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def wsl_list_distros() -> list[str]:
    if not is_windows():
        return []
    try:
        # `-q` prints just distro names, one per line.
        cp = subprocess.run(["wsl", "-l", "-q"], check=True, capture_output=True, text=True)
        # On some Windows setups, stdout can contain NULs (looks like UTF-16LE when captured).
        out = (cp.stdout or "").replace("\x00", "")
        return [line.strip() for line in out.splitlines() if line.strip()]
    except Exception:
        return []


def pick_wsl_distro() -> str:
    """Pick a WSL distro suitable for Ubuntu scanning.

    Preference order:
    1) `SECPATCHLAB_WSL_DISTRO` env var
    2) First distro whose name starts with 'Ubuntu'
    3) First distro containing 'Ubuntu'
    4) If only one distro exists, use it
    """
    requested = os.environ.get("SECPATCHLAB_WSL_DISTRO", "").strip()
    distros = wsl_list_distros()

    if requested:
        if requested in distros:
            return requested
        raise CommandError(
            f"Requested WSL distro '{requested}' not found. Available: {', '.join(distros) if distros else '(none)'}"
        )

    for d in distros:
        if d.startswith("Ubuntu"):
            return d
    for d in distros:
        if "ubuntu" in d.lower():
            return d

    if len(distros) == 1:
        return distros[0]

    raise CommandError(
        "No Ubuntu WSL distro found. Install one (e.g. `wsl --install -d Ubuntu`) "
        "or set SECPATCHLAB_WSL_DISTRO to the name of your Ubuntu distro (see `wsl -l -q`). "
        "If you just want to demo the UI on Windows, run `python -m secpatchlab.cli seed-demo`."
    )


def utc_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def run_cmd(
    cmd: Iterable[str],
    timeout: int = 600,
    cwd: str | None = None,
    env: dict | None = None,
    log_file: Path | None = None,
) -> subprocess.CompletedProcess:
    process = subprocess.Popen(
        list(cmd),
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )

    output_lines = []
    try:
        for line in iter(process.stdout.readline, ""):
            output_lines.append(line)
            if log_file:
                with log_file.open("a", encoding="utf-8") as f:
                    f.write(line)
        return_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        raise CommandError(f"Command timed out: {' '.join(cmd)}") from exc

    output = "".join(output_lines)
    if return_code != 0:
        raise CommandError(f"Command failed ({return_code}): {' '.join(cmd)}\n{output}")

    return subprocess.CompletedProcess(args=cmd, returncode=return_code, stdout=output, stderr=None)


def run_cmd_wsl(
    cmd: Iterable[str],
    timeout: int = 600,
    log_file: Path | None = None,
) -> subprocess.CompletedProcess:
    if not wsl_available():
        raise CommandError(
            "WSL is not available. Install WSL + Ubuntu (or run scans from an Ubuntu environment) to perform real scans on Windows."
        )
    distro = pick_wsl_distro()
    # Use `wsl -e <cmd...>` to avoid shell quoting issues.
    wsl_cmd = ["wsl", "-d", distro, "-e", *list(cmd)]
    return run_cmd(wsl_cmd, timeout=timeout, log_file=log_file)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def get_cache_dir() -> Path:
    return Path(os.path.expanduser("~/.cache/secpatchlab"))
