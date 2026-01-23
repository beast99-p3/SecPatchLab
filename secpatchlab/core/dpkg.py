from __future__ import annotations

import subprocess
from typing import Dict

from secpatchlab.core.utils import CommandError, run_cmd


def list_installed_packages() -> Dict[str, str]:
    cmd = ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"]
    try:
        result = run_cmd(cmd, timeout=60)
    except FileNotFoundError as exc:
        raise CommandError("dpkg-query not available") from exc
    installed = {}
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        pkg, ver = line.split("\t", 1)
        installed[pkg.strip()] = ver.strip()
    return installed


def compare_versions(installed: str, op: str, fixed: str) -> bool:
    cmd = ["dpkg", "--compare-versions", installed, op, fixed]
    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError as exc:
        raise CommandError("dpkg not available") from exc
