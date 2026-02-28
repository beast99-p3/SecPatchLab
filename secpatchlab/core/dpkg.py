from __future__ import annotations

import subprocess
from typing import Dict

try:
    from debian.debian_support import Version as DebianVersion
    DEBIAN_VERSION_AVAILABLE = True
except ImportError:
    DEBIAN_VERSION_AVAILABLE = False
    DebianVersion = None

from secpatchlab.core.utils import CommandError, is_windows, run_cmd, run_cmd_wsl, wsl_available


def list_installed_packages() -> Dict[str, str]:
    cmd = ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"]
    try:
        result = run_cmd(cmd, timeout=60)
    except FileNotFoundError as exc:
        if is_windows() and wsl_available():
            result = run_cmd_wsl(cmd, timeout=60)
        else:
            raise CommandError("dpkg-query not available") from exc
    installed = {}
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        pkg, ver = line.split("\t", 1)
        installed[pkg.strip()] = ver.strip()
    return installed


def compare_versions(installed: str, op: str, fixed: str) -> bool:
    """Compare package versions using proper Debian version semantics.
    
    Supports epoch (1:), revisions (-0ubuntu2), backports, and security suffixes.
    Falls back to dpkg --compare-versions if debian.version is not available.
    """
    installed = (installed or "").strip() or "0"
    fixed = (fixed or "").strip() or "0"

    if DEBIAN_VERSION_AVAILABLE:
        try:
            # Use proper Debian version comparison
            installed_ver = DebianVersion(installed)
            fixed_ver = DebianVersion(fixed)
            
            if op == "lt":
                return installed_ver < fixed_ver
            elif op == "le":
                return installed_ver <= fixed_ver
            elif op == "eq":
                return installed_ver == fixed_ver
            elif op == "ge":
                return installed_ver >= fixed_ver
            elif op == "gt":
                return installed_ver > fixed_ver
            else:
                raise ValueError(f"Unsupported comparison operator: {op}")
                
        except Exception as exc:
            # If debian.version fails, fall back to dpkg
            pass
    
    # Fallback to dpkg --compare-versions
    return _dpkg_compare_versions(installed, op, fixed)


def _dpkg_compare_versions(installed: str, op: str, fixed: str) -> bool:
    """Fallback version comparison using dpkg --compare-versions."""
    cmd = ["dpkg", "--compare-versions", installed, op, fixed]
    try:
        if is_windows() and wsl_available():
            run_cmd_wsl(cmd, timeout=10)
        else:
            subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError as exc:
        if is_windows() and wsl_available():
            # run_cmd_wsl will raise a CommandError with details.
            run_cmd_wsl(cmd, timeout=10)
            return True
        raise CommandError("dpkg not available") from exc


def normalize_version(version_str: str) -> str:
    """Normalize a version string for consistent comparison.
    
    Handles common version string variations and edge cases.
    """
    if not version_str:
        return "0"
    
    # Handle debian.version normalization if available
    if DEBIAN_VERSION_AVAILABLE:
        try:
            return str(DebianVersion(version_str))
        except Exception:
            pass
    
    return version_str.strip()


def parse_version_components(version_str: str) -> dict:
    """Parse version string into components (epoch, upstream, revision).
    
    Returns dict with 'epoch', 'upstream', 'revision' keys.
    """
    if DEBIAN_VERSION_AVAILABLE:
        try:
            ver = DebianVersion(version_str)
            epoch = ver.epoch
            try:
                epoch = int(epoch)
            except Exception:
                pass
            return {
                "epoch": epoch,
                "upstream": ver.upstream_version,
                "revision": ver.debian_revision
            }
        except Exception:
            pass
    
    # Fallback manual parsing
    epoch = None
    revision = None
    upstream = version_str
    
    # Extract epoch (before first colon)
    if ":" in version_str:
        epoch_str, rest = version_str.split(":", 1)
        try:
            epoch = int(epoch_str)
            upstream = rest
        except ValueError:
            pass
    
    # Extract revision (after last dash)
    if "-" in upstream:
        parts = upstream.rsplit("-", 1)
        if len(parts) == 2:
            upstream, revision = parts
    
    return {
        "epoch": epoch,
        "upstream": upstream,
        "revision": revision
    }
