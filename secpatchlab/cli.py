from __future__ import annotations

import json
from pathlib import Path
import typer
from typing import Optional
from datetime import datetime, timedelta, timezone

from secpatchlab.core import scan as scan_mod
from secpatchlab.core import validation as validation_mod
from secpatchlab.core import storage
from secpatchlab.reporting.sarif import export_sarif_report
from secpatchlab.reporting.sbom import export_sbom
from secpatchlab.core.models import ScanResult, Finding, ValidationSummary
from secpatchlab.core.utils import CommandError, ensure_dir, write_json, utc_now

app = typer.Typer(help="SecPatchLab CLI")


@app.command()
def scan(
    format: str = typer.Option("table", "--format", help="Output format: table, json, or sarif"),
    output: Optional[str] = typer.Option(None, "--output", help="Output file path (for json/sarif formats)"),
    top: Optional[int] = typer.Option(None, "--top", help="Show top N findings"),
    refresh: bool = typer.Option(False, "--refresh", help="Refresh OVAL cache"),
):
    """Run a security vulnerability scan."""
    try:
        scan_id, result = scan_mod.perform_scan(top=top, refresh=refresh)
    except CommandError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1)
    except Exception as exc:
        typer.echo(f"Scan failed: {exc}", err=True)
        raise typer.Exit(code=1)
    
    if format == "json":
        output_data = result.model_dump()
        if output:
            Path(output).write_text(json.dumps(output_data, indent=2))
            typer.echo(f"JSON report saved to: {output}")
        else:
            typer.echo(json.dumps(output_data, indent=2))
    elif format == "sarif":
        if not output:
            output = f"results-{scan_id}.sarif"
        
        output_path = Path(output)
        export_sarif_report(result, output_path)
        typer.echo(f"SARIF report saved to: {output_path}")
        typer.echo(f"Upload to GitHub with: gh api repos/:owner/:repo/code-scanning/sarifs -F sarif=@{output_path}")
    else:
        # Default table format
        scan_mod.print_table(result)
        typer.echo(f"\nScan saved: {scan_id}")
        if format not in ["table", "json", "sarif"]:
            typer.echo(f"Warning: Unknown format '{format}', using table format")


@app.command()
def validate(
    package: str = typer.Option(..., "--package", help="Package name"),
    patch: Optional[str] = typer.Option(None, "--patch", help="Patch file path"),
    release: Optional[str] = typer.Option(None, "--release", help="Ubuntu codename"),
    sbom: bool = typer.Option(False, "--sbom", help="Generate SBOM report"),
):
    """Run package validation in sandbox."""
    run_id = validation_mod.run_validation_sync(package, patch, release)
    typer.echo(f"Validation run complete: {run_id}")
    
    if sbom:
        # Generate SBOM
        run_dir = storage.get_validation_run_dir(run_id)
        if run_dir:
            sbom_path = run_dir / "sbom.json"
            artifacts_dir = run_dir / "artifacts"
            
            try:
                export_sbom(run_id, package, sbom_path, artifacts_dir)
                typer.echo(f"SBOM generated: {sbom_path}")
            except Exception as e:
                typer.echo(f"SBOM generation failed: {e}", err=True)
        else:
            typer.echo("Warning: Could not locate run directory for SBOM generation", err=True)


@app.command()
def demo(
    cve: str = typer.Option("CVE-2023-0464", "--cve", help="CVE identifier to demonstrate"),
    format: str = typer.Option("table", "--format", help="Output format: table, json, sarif"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", help="Output directory for reports"),
):
    """Run a complete CVE demonstration workflow."""
    typer.echo(f"🔍 SecPatchLab CVE Demonstration: {cve}")
    typer.echo("=" * 50)
    
    # CVE to package mapping (known examples) 
    cve_packages = {
        "CVE-2023-0464": "openssl",
        "CVE-2022-4203": "openssl", 
        "CVE-2021-3156": "sudo",
        "CVE-2023-22809": "sudo",
        "CVE-2022-2068": "openssl",
        "CVE-2022-4304": "openssl"
    }
    
    target_package = cve_packages.get(cve)
    if not target_package:
        # Try to extract package from CVE description or use default
        typer.echo(f"⚠️  Unknown CVE {cve}, using OpenSSL as demonstration package")
        target_package = "openssl"
    
    typer.echo(f"🎯 Target package: {target_package}")
    typer.echo()
    
    # Step 1: Run vulnerability scan
    typer.echo("📊 Step 1: Running vulnerability scan...")
    try:
        scan_id, scan_result = scan_mod.perform_scan(top=None, refresh=False)
        
        # Look for findings related to the CVE or package
        relevant_findings = []
        for finding in scan_result.findings:
            if (target_package == finding.package or 
                cve in finding.cves or 
                any(cve in c for c in finding.cves)):
                relevant_findings.append(finding)
        
        if relevant_findings:
            typer.echo(f"✅ Found {len(relevant_findings)} relevant findings!")
            target_finding = relevant_findings[0]
            typer.echo(f"   Package: {target_finding.package} {target_finding.installed}")
            typer.echo(f"   Vulnerability: {target_finding.severity}")
            if target_finding.cves:
                typer.echo(f"   CVEs: {', '.join(target_finding.cves)}")
            typer.echo(f"   Fixed in: {target_finding.fixed}")
        else:
            # Create a demonstration finding if none found
            typer.echo(f"⚠️  No active findings for {cve}, creating demonstration scenario")
            from secpatchlab.core.models import Finding
            target_finding = Finding(
                severity="High",
                package=target_package,
                installed="1.1.1f-1ubuntu2.16",
                fixed="1.1.1f-1ubuntu2.17",
                usn="USN-5844-1",
                cves=[cve],
                action="apt upgrade"
            )
        
    except Exception as e:
        typer.echo(f"❌ Scan failed: {e}")
        return
    
    typer.echo()
    
    # Step 2: Generate reports
    if output_dir:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        typer.echo("📋 Step 2: Generating reports...")
        
        # Generate SARIF report
        sarif_path = output_path / f"cve-{cve.lower()}-results.sarif"
        try:
            export_sarif_report(scan_result, sarif_path)
            typer.echo(f"   ✅ SARIF report: {sarif_path}")
        except Exception as e:
            typer.echo(f"   ❌ SARIF generation failed: {e}")
        
        # Generate JSON report
        json_path = output_path / f"cve-{cve.lower()}-results.json"
        try:
            json_path.write_text(json.dumps(scan_result.model_dump(), indent=2))
            typer.echo(f"   ✅ JSON report: {json_path}")
        except Exception as e:
            typer.echo(f"   ❌ JSON generation failed: {e}")
    
    typer.echo()
    
    # Step 3: Run validation
    typer.echo(f"🧪 Step 3: Running validation for {target_package}...")
    try:
        run_id = validation_mod.run_validation_sync(target_package, None, scan_result.codename)
        typer.echo(f"   ✅ Validation complete: {run_id}")
        
        # Generate SBOM if output directory specified
        if output_dir:
            run_dir = storage.get_validation_run_dir(run_id)
            if run_dir:
                sbom_path = Path(output_dir) / f"cve-{cve.lower()}-sbom.json"
                artifacts_dir = run_dir / "artifacts"
                try:
                    export_sbom(run_id, target_package, sbom_path, artifacts_dir)
                    typer.echo(f"   ✅ SBOM report: {sbom_path}")
                except Exception as e:
                    typer.echo(f"   ❌ SBOM generation failed: {e}")
        
    except Exception as e:
        typer.echo(f"   ❌ Validation failed: {e}")
    
    typer.echo()
    
    # Step 4: Summary and recommendations
    typer.echo("📋 Step 4: Summary and Recommendations")
    typer.echo(f"   CVE: {cve}")
    typer.echo(f"   Package: {target_package}")
    if 'target_finding' in locals():
        typer.echo(f"   Current Version: {target_finding.installed}")
        typer.echo(f"   Fixed Version: {target_finding.fixed}")
        typer.echo(f"   Severity: {target_finding.severity}")
        typer.echo(f"   Recommended Action: {target_finding.action}")
    
    if output_dir:
        typer.echo(f"   Reports saved to: {output_dir}")
        typer.echo(f"   Upload SARIF to GitHub: gh api repos/:owner/:repo/code-scanning/sarifs -F sarif=@{sarif_path}")
    
    typer.echo()
    typer.echo("🎉 CVE demonstration complete!")


@app.command()
def run(
    top: int = typer.Option(3, "--top", help="Top N packages to validate"),
):
    """Run end-to-end scan and validation workflow."""
    scan_id, result = scan_mod.perform_scan(top=top, refresh=False)
    typer.echo(f"Scan complete: {scan_id}")
    for finding in result.findings:
        typer.echo(f"Validating {finding.package}...")
        validation_mod.run_validation_sync(finding.package, None, result.codename)


@app.command("seed-demo")
def seed_demo(
    include_scan: bool = typer.Option(True, "--include-scan/--no-scan", help="Create a demo scan with findings"),
    include_runs: bool = typer.Option(True, "--include-runs/--no-runs", help="Create demo validation runs"),
):
    """Seed demo data under runs/ so the frontend can showcase success + failure.

    This is intentionally deterministic-ish and does NOT require Docker.
    """

    created = []

    now_utc = datetime.now(timezone.utc)

    if include_scan:
        scan_id = f"scan-demo-{now_utc.strftime('%Y%m%d-%H%M%S')}"
        result = ScanResult(
            scan_id=scan_id,
            codename="noble",
            total_packages=607,
            findings=[
                Finding(
                    severity="High",
                    package="openssl",
                    installed="1.1.1f-1ubuntu2.16",
                    fixed="1.1.1f-1ubuntu2.17",
                    usn="USN-5844-1",
                    cves=["CVE-2023-0464"],
                    action="Upgrade package",
                ),
                Finding(
                    severity="Medium",
                    package="sudo",
                    installed="1.9.9-1ubuntu2.3",
                    fixed="1.9.9-1ubuntu2.4",
                    usn="USN-5206-1",
                    cves=["CVE-2021-3156"],
                    action="Upgrade package",
                ),
            ],
        )
        storage.store_scan(result)
        created.append(scan_id)

    if include_runs:
        ensure_dir(storage.RUNS_DIR)

        # Successful run (simulated)
        run_id_ok = f"validate-demo-{now_utc.strftime('%Y%m%d-%H%M%S')}-ok"
        run_dir_ok = storage.RUNS_DIR / run_id_ok
        ensure_dir(run_dir_ok)
        started_ok = (now_utc - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
        finished_ok = utc_now()

        artifacts_dir_ok = run_dir_ok / "artifacts"
        ensure_dir(artifacts_dir_ok)
        (artifacts_dir_ok / "build-info.txt").write_text(
            "Demo artifact: build summary\nStatus: success\n",
            encoding="utf-8",
        )
        (artifacts_dir_ok / "sbom.json").write_text(
            json.dumps({"demo": True, "package": "openssl", "format": "sbom"}, indent=2),
            encoding="utf-8",
        )

        (run_dir_ok / "run.log").write_text(
            "[demo] docker build ...\n[demo] running package tests ...\n[demo] SUCCESS\n",
            encoding="utf-8",
        )

        summary_ok = ValidationSummary(
            run_id=run_id_ok,
            package="openssl",
            release="jammy",
            result="success",
            started_at=started_ok,
            finished_at=finished_ok,
            commands=[
                "docker build -t secpatchlab-demo ...",
                "docker run --rm secpatchlab-demo openssl",
            ],
            artifacts=["build-info.txt", "sbom.json"],
            log_path=str(run_dir_ok / "run.log"),
        )
        write_json(run_dir_ok / "summary.json", summary_ok.model_dump())
        write_json(
            run_dir_ok / "status.json",
            {
                "run_id": run_id_ok,
                "package": "openssl",
                "status": "success",
                "started_at": started_ok,
                "finished_at": finished_ok,
            },
        )
        created.append(run_id_ok)

        # Failed run (simulated)
        run_id_bad = f"validate-demo-{now_utc.strftime('%Y%m%d-%H%M%S')}-fail"
        run_dir_bad = storage.RUNS_DIR / run_id_bad
        ensure_dir(run_dir_bad)
        started_bad = (now_utc - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
        finished_bad = utc_now()
        (run_dir_bad / "run.log").write_text(
            "[demo] docker version\n[demo] ERROR: Docker not available\n",
            encoding="utf-8",
        )
        summary_bad = ValidationSummary(
            run_id=run_id_bad,
            package="openssl",
            release="jammy",
            result="failure",
            started_at=started_bad,
            finished_at=finished_bad,
            commands=["docker version"],
            artifacts=[],
            log_path=str(run_dir_bad / "run.log"),
            error="Docker not available",
        )
        write_json(run_dir_bad / "summary.json", summary_bad.model_dump())
        write_json(
            run_dir_bad / "status.json",
            {
                "run_id": run_id_bad,
                "package": "openssl",
                "status": "failure",
                "started_at": started_bad,
                "finished_at": finished_bad,
                "error": "Docker not available",
            },
        )
        created.append(run_id_bad)

    if created:
        typer.echo("Seeded demo data:")
        for item in created:
            typer.echo(f"- {item}")
    else:
        typer.echo("Nothing to seed (all demo outputs disabled).")


if __name__ == "__main__":
    app()
