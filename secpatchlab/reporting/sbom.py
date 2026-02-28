"""Software Bill of Materials (SBOM) generation using CycloneDX format.

Generates SBOM documents for validation runs including package metadata,
dependencies, and artifact hashes.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Set

from secpatchlab.core.dpkg import list_installed_packages
from secpatchlab.core.utils import run_cmd, CommandError


def _calculate_file_hashes(file_path: Path) -> Dict[str, str]:
    """Calculate multiple hash algorithms for a file."""
    if not file_path.exists() or not file_path.is_file():
        return {}
    
    hashes = {}
    try:
        content = file_path.read_bytes()
        hashes["sha256"] = hashlib.sha256(content).hexdigest()
        hashes["sha1"] = hashlib.sha1(content).hexdigest()
        hashes["md5"] = hashlib.md5(content).hexdigest()
    except (OSError, MemoryError):
        pass  # File too large or inaccessible
    
    return hashes


def _get_package_dependencies(package: str) -> List[str]:
    """Get direct dependencies for a package."""
    try:
        result = run_cmd(["apt-cache", "depends", package], timeout=30)
        deps = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Depends:"):
                dep = line.split(":", 1)[1].strip()
                # Remove version constraints and alternatives
                dep = dep.split()[0].split("|")[0]
                if dep and not dep.startswith("<") and not dep.startswith("("):
                    deps.append(dep)
        return deps
    except (CommandError, Exception):
        return []


def _get_package_metadata(package: str, version: str) -> Dict[str, Any]:
    """Get additional metadata for a package."""
    metadata = {
        "name": package,
        "version": version,
        "type": "library",  # Default type
        "scope": "required",
        "purl": f"pkg:deb/ubuntu/{package}@{version}",
        "properties": []
    }
    
    try:
        # Get package description
        result = run_cmd(["apt-cache", "show", f"{package}={version}"], timeout=15)
        description = ""
        section = ""
        source_package = ""
        
        for line in result.stdout.splitlines():
            if line.startswith("Description:"):
                description = line.split(":", 1)[1].strip()
            elif line.startswith("Section:"):
                section = line.split(":", 1)[1].strip()
            elif line.startswith("Source:"):
                source_package = line.split(":", 1)[1].strip().split()[0]
        
        if description:
            metadata["description"] = description
        
        if section:
            metadata["properties"].append({
                "name": "apt:section", 
                "value": section
            })
        
        if source_package:
            metadata["properties"].append({
                "name": "apt:source_package",
                "value": source_package
            })
        
        # Classify package type based on section
        if section:
            if any(x in section for x in ["lib", "devel"]):
                metadata["type"] = "library"
            elif "doc" in section:
                metadata["type"] = "documentation" 
            elif any(x in section for x in ["admin", "utils", "net", "web"]):
                metadata["type"] = "application"
            else:
                metadata["type"] = "library"  # Default
                
    except CommandError:
        pass  # Continue with basic metadata
    
    return metadata


def generate_sbom(run_id: str, package: str, artifacts_dir: Path, 
                  include_system_packages: bool = False) -> Dict[str, Any]:
    """Generate CycloneDX SBOM for a validation run."""
    
    sbom_uuid = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    # Base SBOM structure
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{sbom_uuid}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "SecPatchLab",
                    "name": "SecPatchLab SBOM Generator", 
                    "version": "0.1.0"
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": f"secpatchlab-validation-{run_id}",
                "name": f"SecPatchLab Validation: {package}",
                "version": "1.0.0",
                "description": f"Validation run for package {package}"
            },
            "properties": [
                {
                    "name": "secpatchlab:run_id",
                    "value": run_id
                },
                {
                    "name": "secpatchlab:target_package", 
                    "value": package
                },
                {
                    "name": "secpatchlab:timestamp",
                    "value": timestamp
                }
            ]
        },
        "components": [],
        "dependencies": []
    }
    
    components_by_name: Dict[str, Dict[str, Any]] = {}
    
    # Add target package and its dependencies
    try:
        installed_packages = list_installed_packages()
        
        if package in installed_packages:
            # Add main package
            main_component = _get_package_metadata(package, installed_packages[package])
            main_component["bom-ref"] = f"pkg:{package}"
            components_by_name[package] = main_component
            
            # Get dependencies
            deps = _get_package_dependencies(package)
            dependency_refs = []
            
            for dep in deps:
                if dep in installed_packages:
                    dep_component = _get_package_metadata(dep, installed_packages[dep])
                    dep_component["bom-ref"] = f"pkg:{dep}"
                    components_by_name[dep] = dep_component
                    dependency_refs.append(f"pkg:{dep}")
            
            # Add dependency relationship
            if dependency_refs:
                sbom["dependencies"].append({
                    "ref": f"pkg:{package}",
                    "dependsOn": dependency_refs
                })
        
        # Optionally include all system packages
        if include_system_packages:
            for pkg_name, pkg_version in installed_packages.items():
                if pkg_name not in components_by_name:
                    comp = _get_package_metadata(pkg_name, pkg_version)
                    comp["bom-ref"] = f"pkg:{pkg_name}"
                    components_by_name[pkg_name] = comp
    
    except Exception as e:
        # Add error information if package enumeration fails
        sbom["metadata"]["properties"].append({
            "name": "secpatchlab:enumeration_error",
            "value": str(e)
        })
    
    # Add all components to SBOM
    sbom["components"] = list(components_by_name.values())
    
    # Process artifacts and add hashes
    if artifacts_dir and artifacts_dir.exists():
        artifacts = []
        
        for artifact_file in artifacts_dir.iterdir():
            if artifact_file.is_file():
                hashes = _calculate_file_hashes(artifact_file)
                
                artifact = {
                    "name": artifact_file.name,
                    "type": "file",
                    "bom-ref": f"artifact:{artifact_file.name}",
                    "properties": [
                        {
                            "name": "secpatchlab:file_path",
                            "value": str(artifact_file)
                        },
                        {
                            "name": "secpatchlab:file_size",
                            "value": str(artifact_file.stat().st_size)
                        }
                    ]
                }
                
                # Add hash information
                if hashes:
                    artifact["hashes"] = [
                        {"alg": alg.upper(), "content": hash_val}
                        for alg, hash_val in hashes.items()
                    ]
                
                artifacts.append(artifact)
        
        # Add artifacts as components
        sbom["components"].extend(artifacts)
        
        # Add artifact count to metadata
        sbom["metadata"]["properties"].append({
            "name": "secpatchlab:artifacts_count",
            "value": str(len(artifacts))
        })
    
    return sbom


def export_sbom(run_id: str, package: str, output_path: Path, 
                artifacts_dir: Optional[Path] = None,
                include_system_packages: bool = False,
                pretty: bool = True) -> None:
    """Export SBOM to file."""
    
    if artifacts_dir is None:
        # Default to run directory artifacts
        from secpatchlab.core import storage
        run_dir = storage.get_validation_run_dir(run_id)
        if run_dir:
            artifacts_dir = run_dir / "artifacts"
    
    sbom_data = generate_sbom(run_id, package, artifacts_dir or Path(),
                              include_system_packages)
    
    # Write to file
    with open(output_path, 'w', encoding='utf-8') as f:
        if pretty:
            json.dump(sbom_data, f, indent=2, ensure_ascii=False)
        else:
            json.dump(sbom_data, f, separators=(',', ':'), ensure_ascii=False)


def validate_sbom_schema(sbom_data: Dict[str, Any]) -> List[str]:
    """Basic validation of CycloneDX SBOM structure.
    
    Returns list of validation errors, empty if valid.
    """
    errors = []
    
    # Check required fields
    required_fields = ["bomFormat", "specVersion", "serialNumber", "version", "metadata"]
    for field in required_fields:
        if field not in sbom_data:
            errors.append(f"Missing required field: {field}")
    
    # Check bomFormat
    if sbom_data.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat must be 'CycloneDX'")
    
    # Check specVersion
    spec_version = sbom_data.get("specVersion")
    if spec_version not in ["1.4", "1.5"]:
        errors.append(f"Unsupported specVersion: {spec_version}")
    
    # Check serialNumber format (should be URN)
    serial_num = sbom_data.get("serialNumber", "")
    if not serial_num.startswith("urn:uuid:"):
        errors.append("serialNumber should be a URN with UUID")
    
    # Check metadata structure
    metadata = sbom_data.get("metadata", {})
    if not isinstance(metadata, dict):
        errors.append("metadata must be an object")
    elif "timestamp" not in metadata:
        errors.append("metadata.timestamp is required")
    
    # Check components if present
    components = sbom_data.get("components", [])
    if not isinstance(components, list):
        errors.append("components must be an array")
    
    return errors


def create_sbom_summary(sbom_data: Dict[str, Any]) -> Dict[str, Any]:
    """Create a summary of SBOM contents."""
    summary = {
        "total_components": len(sbom_data.get("components", [])),
        "component_types": {},
        "has_dependencies": bool(sbom_data.get("dependencies")),
        "dependency_count": len(sbom_data.get("dependencies", [])),
        "artifacts_with_hashes": 0,
        "timestamp": sbom_data.get("metadata", {}).get("timestamp"),
        "run_id": None
    }
    
    # Count component types
    for component in sbom_data.get("components", []):
        comp_type = component.get("type", "unknown")
        summary["component_types"][comp_type] = summary["component_types"].get(comp_type, 0) + 1
    
    # Count artifacts with hashes
    for component in sbom_data.get("components", []):
        if component.get("hashes"):
            summary["artifacts_with_hashes"] += 1
    
    # Extract run ID from metadata
    for prop in sbom_data.get("metadata", {}).get("properties", []):
        if prop.get("name") == "secpatchlab:run_id":
            summary["run_id"] = prop.get("value")
            break
    
    return summary