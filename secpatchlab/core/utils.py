from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Iterable


class CommandError(RuntimeError):
    pass


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


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def get_cache_dir() -> Path:
    return Path(os.path.expanduser("~/.cache/secpatchlab"))
