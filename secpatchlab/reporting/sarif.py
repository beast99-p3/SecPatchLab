"""SARIF (Static Analysis Results Interchange Format) export functionality.

Converts SecPatchLab scan results into SARIF 2.1.0 format for integration
with GitHub Security tab and other security tooling.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from uuid import uuid4

from secpatchlab.core.models import Finding, ScanResult


# SARIF severity level mapping
SARIF_SEVERITY_MAP = {
    "Critical": "error",
    "High": "error", 
    "Medium": "warning",
    "Low": "note",
    "Unknown": "note"
}

# SARIF security severity mapping (for GitHub integration)
SECURITY_SEVERITY_MAP = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium", 
    "Low": "low",
    "Unknown": "low"
}


def _generate_rule_id(finding: Finding) -> str:
    """Generate a consistent rule ID for a finding."""
    # Use USN as primary identifier, fall back to package name
    if finding.usn:
        return f"USN-{finding.usn}"
    return f"VULN-{finding.package}"


def _create_sarif_rule(finding: Finding) -> Dict[str, Any]:
    """Create a SARIF rule definition for a finding."""
    rule_id = _generate_rule_id(finding)
    
    # Build help text with CVE information
    cve_text = ""
    if finding.cves:
        cve_list = ", ".join(finding.cves)
        cve_text = f" Associated CVEs: {cve_list}."
    
    help_text = (
        f"Package {finding.package} version {finding.installed} has known security "
        f"vulnerabilities. Update to version {finding.fixed} or later.{cve_text}"
    )
    
    rule = {
        "id": rule_id,
        "name": f"VulnerablePackage/{finding.package}",
        "shortDescription": {
            "text": f"Vulnerable package: {finding.package}"
        },
        "fullDescription": {
            "text": help_text
        },
        "help": {
            "text": help_text,
            "markdown": f"## Vulnerable Package: {finding.package}\n\n"
                       f"**Installed Version:** `{finding.installed}`\n\n"
                       f"**Fixed Version:** `{finding.fixed}`\n\n"
                       f"**Severity:** {finding.severity}\n\n"
                       + (f"**USN:** {finding.usn}\n\n" if finding.usn else "")
                       + (f"**CVEs:** {', '.join(finding.cves)}\n\n" if finding.cves else "")
                       + f"**Recommended Action:** {finding.action}\n\n"
                       + "Update this package to the fixed version to resolve the security vulnerability."
        },
        "defaultConfiguration": {
            "level": SARIF_SEVERITY_MAP.get(finding.severity, "warning")
        },
        "properties": {
            "security-severity": SECURITY_SEVERITY_MAP.get(finding.severity, "medium"),
            "precision": "high",
            "problem.severity": finding.severity.lower(),
            "tags": ["security", "vulnerability"]
        }
    }
    
    # Add CVE tags
    if finding.cves:
        rule["properties"]["tags"].extend([f"cve-{cve.lower()}" for cve in finding.cves])
    
    return rule


def _create_sarif_result(finding: Finding, rule_id: str) -> Dict[str, Any]:
    """Create a SARIF result for a finding."""
    # Generate a message with details
    cve_info = f" ({', '.join(finding.cves)})" if finding.cves else ""
    message = (
        f"Package {finding.package} {finding.installed} is vulnerable{cve_info}. "
        f"Update to {finding.fixed} or later."
    )
    
    result = {
        "ruleId": rule_id,
        "ruleIndex": 0,  # Will be updated when building the full report
        "level": SARIF_SEVERITY_MAP.get(finding.severity, "warning"),
        "message": {
            "text": message
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": "/var/lib/dpkg/status",
                        "description": {
                            "text": "System package database"
                        }
                    },
                    "region": {
                        "startLine": 1,
                        "startColumn": 1,
                        "endLine": 1,
                        "endColumn": 1
                    }
                },
                "logicalLocations": [
                    {
                        "name": finding.package,
                        "fullyQualifiedName": f"package:{finding.package}",
                        "kind": "package"
                    }
                ]
            }
        ],
        "properties": {
            "installed_version": finding.installed,
            "fixed_version": finding.fixed,
            "package_name": finding.package,
            "severity": finding.severity,
            "action": finding.action,
            "usn": finding.usn,
            "cves": finding.cves
        }
    }
    
    return result


def convert_to_sarif(scan_result: ScanResult, tool_version: str = "0.1.0") -> Dict[str, Any]:
    """Convert SecPatchLab scan results to SARIF 2.1.0 format."""
    
    # Create rules and results
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    rule_index_map: Dict[str, int] = {}
    
    for finding in scan_result.findings:
        rule_id = _generate_rule_id(finding)
        
        # Create rule if not already exists
        if rule_id not in rules:
            rules[rule_id] = _create_sarif_rule(finding)
            rule_index_map[rule_id] = len(rule_index_map)
        
        # Create result
        result = _create_sarif_result(finding, rule_id)
        result["ruleIndex"] = rule_index_map[rule_id]
        results.append(result)
    
    # Build SARIF document
    sarif_doc = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecPatchLab",
                        "version": tool_version,
                        "informationUri": "https://github.com/yourusername/secpatchlab",
                        "shortDescription": {
                            "text": "Ubuntu security monitoring and patch validation"
                        },
                        "fullDescription": {
                            "text": "SecPatchLab scans Ubuntu systems for security vulnerabilities by comparing installed packages against Canonical OVAL feeds."
                        },
                        "rules": list(rules.values())
                    }
                },
                "invocation": {
                    "executionSuccessful": True,
                    "startTimeUtc": datetime.utcnow().isoformat() + "Z",
                    "endTimeUtc": datetime.utcnow().isoformat() + "Z",
                    "machine": scan_result.codename,
                    "commandLine": f"secpatchlab scan --top {len(scan_result.findings)}",
                    "responseFiles": [
                        {
                            "uri": f"runs/{scan_result.scan_id}/scan.json",
                            "description": {
                                "text": "Original scan results"
                            }
                        }
                    ]
                },
                "artifacts": [
                    {
                        "location": {
                            "uri": "/var/lib/dpkg/status",
                            "description": {
                                "text": "System package database"
                            }
                        },
                        "mimeType": "text/plain",
                        "roles": ["analysisTarget"]
                    }
                ],
                "results": results,
                "properties": {
                    "scan_id": scan_result.scan_id,
                    "codename": scan_result.codename,
                    "total_packages": scan_result.total_packages,
                    "findings_count": len(scan_result.findings),
                    "secpatchlab_version": tool_version
                }
            }
        ]
    }
    
    return sarif_doc


def export_sarif_report(scan_result: ScanResult, output_path: Path, 
                        tool_version: str = "0.1.0", pretty: bool = True) -> None:
    """Export scan results as SARIF report to file."""
    sarif_data = convert_to_sarif(scan_result, tool_version)
    
    # Write to file
    with open(output_path, 'w', encoding='utf-8') as f:
        if pretty:
            json.dump(sarif_data, f, indent=2, ensure_ascii=False)
        else:
            json.dump(sarif_data, f, separators=(',', ':'), ensure_ascii=False)


def validate_sarif_schema(sarif_data: Dict[str, Any]) -> List[str]:
    """Basic validation of SARIF document structure.
    
    Returns list of validation errors, empty if valid.
    """
    errors = []
    
    # Check required top-level fields
    if "version" not in sarif_data:
        errors.append("Missing required field: version")
    elif sarif_data["version"] != "2.1.0":
        errors.append(f"Unsupported SARIF version: {sarif_data['version']}")
    
    if "$schema" not in sarif_data:
        errors.append("Missing recommended field: $schema")
    
    if "runs" not in sarif_data:
        errors.append("Missing required field: runs")
    elif not isinstance(sarif_data["runs"], list):
        errors.append("Field 'runs' must be an array")
    elif len(sarif_data["runs"]) == 0:
        errors.append("At least one run is required")
    
    # Check run structure
    for i, run in enumerate(sarif_data.get("runs", [])):
        if not isinstance(run, dict):
            errors.append(f"Run {i} must be an object")
            continue
            
        if "tool" not in run:
            errors.append(f"Run {i}: missing required field 'tool'")
        
        if "results" not in run:
            errors.append(f"Run {i}: missing required field 'results'")
    
    return errors


def create_github_sarif_upload_info(sarif_path: Path, scan_result: ScanResult) -> Dict[str, Any]:
    """Create metadata for GitHub SARIF upload."""
    return {
        "sarif_file": str(sarif_path),
        "commit_sha": "HEAD",  # Will need to be updated for actual Git integration
        "ref": "refs/heads/main",
        "tool_name": "SecPatchLab",
        "category": "security",
        "scan_id": scan_result.scan_id,
        "upload_command": f"gh api repos/:owner/:repo/code-scanning/sarifs -F sarif=@{sarif_path}"
    }