from __future__ import annotations

from pathlib import Path
from typing import List

from secpatchlab.core import dpkg
from secpatchlab.core import oval
from secpatchlab.core import storage
from secpatchlab.core.models import Finding, ScanResult
from secpatchlab.core.utils import CommandError

SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Unknown": 4,
}


def get_codename() -> str:
    """Read the Ubuntu codename from /etc/os-release."""
    path = Path("/etc/os-release")
    if not path.exists():
        raise CommandError("/etc/os-release not found")
    data = path.read_text(encoding="utf-8")
    for line in data.splitlines():
        if line.startswith("VERSION_CODENAME="):
            return line.split("=", 1)[1].strip().strip('"')
        if line.startswith("UBUNTU_CODENAME="):
            return line.split("=", 1)[1].strip().strip('"')
    raise CommandError("Ubuntu codename not found")


def perform_scan(top: int | None, refresh: bool = False):
    """Run a vulnerability scan and store results under runs/."""
    codename = get_codename()
    xml_path = oval.ensure_oval(codename, refresh=refresh)
    entries = oval.parse_oval(xml_path)
    installed = dpkg.list_installed_packages()

    findings: List[Finding] = []
    for entry in entries:
        if entry.package not in installed:
            continue
        installed_ver = installed[entry.package]
        if dpkg.compare_versions(installed_ver, "lt", entry.fixed_version):
            findings.append(
                Finding(
                    severity=entry.severity,
                    package=entry.package,
                    installed=installed_ver,
                    fixed=entry.fixed_version,
                    usn=entry.usn,
                    cves=entry.cves,
                    action="Upgrade package",
                )
            )

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.package))
    if top:
        findings = findings[:top]

    scan_id = storage.create_scan_id()
    result = ScanResult(
        scan_id=scan_id,
        codename=codename,
        total_packages=len(installed),
        findings=findings,
    )
    storage.store_scan(result)
    return scan_id, result


def print_table(result: ScanResult) -> None:
    """Pretty-print the scan results in a simple table."""
    headers = ["Severity", "Package", "Installed", "Fixed", "USN", "CVE", "Action"]
    rows = []
    for f in result.findings:
        rows.append([
            f.severity,
            f.package,
            f.installed,
            f.fixed,
            f.usn or "",
            ",".join(f.cves) if f.cves else "",
            f.action,
        ])

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    def fmt_row(values):
        return " | ".join(str(v).ljust(col_widths[i]) for i, v in enumerate(values))

    print(fmt_row(headers))
    print("-+-".join("-" * w for w in col_widths))
    for row in rows:
        print(fmt_row(row))
