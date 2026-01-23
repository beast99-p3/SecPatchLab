from __future__ import annotations

import json
import typer
from typing import Optional

from secpatchlab.core import scan as scan_mod
from secpatchlab.core import validation as validation_mod

app = typer.Typer(help="SecPatchLab CLI")


@app.command()
def scan(
    format: str = typer.Option("table", "--format", help="Output format: table or json"),
    top: Optional[int] = typer.Option(None, "--top", help="Show top N findings"),
    refresh: bool = typer.Option(False, "--refresh", help="Refresh OVAL cache"),
):
    scan_id, result = scan_mod.perform_scan(top=top, refresh=refresh)
    if format == "json":
        typer.echo(json.dumps(result.model_dump(), indent=2))
        return
    scan_mod.print_table(result)
    typer.echo(f"\nScan saved: {scan_id}")


@app.command()
def validate(
    package: str = typer.Option(..., "--package", help="Package name"),
    patch: Optional[str] = typer.Option(None, "--patch", help="Patch file path"),
    release: Optional[str] = typer.Option(None, "--release", help="Ubuntu codename"),
):
    run_id = validation_mod.run_validation_sync(package, patch, release)
    typer.echo(f"Validation run complete: {run_id}")


@app.command()
def run(
    top: int = typer.Option(3, "--top", help="Top N packages to validate"),
):
    scan_id, result = scan_mod.perform_scan(top=top, refresh=False)
    typer.echo(f"Scan complete: {scan_id}")
    for finding in result.findings:
        typer.echo(f"Validating {finding.package}...")
        validation_mod.run_validation_sync(finding.package, None, result.codename)


if __name__ == "__main__":
    app()
