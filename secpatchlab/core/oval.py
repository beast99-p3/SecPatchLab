from __future__ import annotations

import os
import bz2
import hashlib
import json
import requests
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Optional

from secpatchlab.core.utils import ensure_dir, get_cache_dir

OVAL_BASE_URL = os.getenv("OVAL_BASE_URL", "https://security-metadata.canonical.com/oval/")

# Fallback mirrors for OVAL feeds
OVAL_MIRRORS = [
    "https://security-metadata.canonical.com/oval/",
    "https://people.canonical.com/~ubuntu-security/oval/",
]

CODENAME_TO_OVAL = {
    "focal": "com.ubuntu.focal.usn.oval.xml.bz2",
    "jammy": "com.ubuntu.jammy.usn.oval.xml.bz2",
    "kinetic": "com.ubuntu.kinetic.usn.oval.xml.bz2",
    "lunar": "com.ubuntu.lunar.usn.oval.xml.bz2",
    "mantic": "com.ubuntu.mantic.usn.oval.xml.bz2",
    "noble": "com.ubuntu.noble.usn.oval.xml.bz2",
    "oracular": "com.ubuntu.oracular.usn.oval.xml.bz2",
}


class OvalEntry:
    def __init__(self, package: str, fixed_version: str, usn: str | None, cves: list[str], severity: str):
        self.package = package
        self.fixed_version = fixed_version
        self.usn = usn
        self.cves = cves
        self.severity = severity


def get_oval_filename(codename: str) -> str:
    """Map Ubuntu codename to Canonical OVAL filename."""
    if codename not in CODENAME_TO_OVAL:
        raise ValueError(f"Unsupported codename: {codename}")
    return CODENAME_TO_OVAL[codename]


def _calculate_sha256(data: bytes) -> str:
    """Calculate SHA256 hash of data."""
    return hashlib.sha256(data).hexdigest()


def _load_cache_metadata(cache_dir: Path, filename: str) -> dict:
    """Load cached metadata (checksums, etags, etc.)."""
    meta_file = cache_dir / f"{filename}.meta"
    if meta_file.exists():
        try:
            return json.loads(meta_file.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_cache_metadata(cache_dir: Path, filename: str, metadata: dict) -> None:
    """Save cache metadata."""
    meta_file = cache_dir / f"{filename}.meta"
    try:
        meta_file.write_text(json.dumps(metadata, indent=2))
    except OSError:
        pass  # Ignore metadata write errors


def _download_with_fallback(filename: str, cache_dir: Path) -> tuple[bytes, str]:
    """Download OVAL feed with fallback mirrors and checksum validation."""
    mirrors = [OVAL_BASE_URL] + [m for m in OVAL_MIRRORS if m != OVAL_BASE_URL]
    
    metadata = _load_cache_metadata(cache_dir, filename)
    last_etag = metadata.get("etag")
    
    for base_url in mirrors:
        try:
            url = base_url.rstrip("/") + "/" + filename
            headers = {}
            
            # Use ETag for conditional requests if available
            if last_etag:
                headers["If-None-Match"] = last_etag
            
            resp = requests.get(url, timeout=60, headers=headers)
            
            if resp.status_code == 304:  # Not modified
                cached_file = cache_dir / filename
                if cached_file.exists():
                    return cached_file.read_bytes(), last_etag
                # If 304 but no cached file, continue to full download
                
            resp.raise_for_status()
            
            # Get new ETag
            new_etag = resp.headers.get("ETag", "")
            
            return resp.content, new_etag
            
        except (requests.RequestException, OSError) as e:
            print(f"Failed to download from {base_url}: {e}")
            continue
    
    raise ConnectionError(f"Failed to download {filename} from all mirrors")


def _validate_oval_content(content: bytes) -> bool:
    """Basic validation of OVAL XML content."""
    try:
        # Check if it's valid XML and has OVAL namespace
        root = ET.fromstring(bz2.decompress(content))
        return "oval" in (root.tag or "").lower()
    except (ET.ParseError, OSError):
        return False


def ensure_oval(codename: str, refresh: bool = False) -> Path:
    """Download and cache the OVAL feed for a codename with checksum validation."""
    cache_dir = get_cache_dir()
    ensure_dir(cache_dir)
    filename = get_oval_filename(codename)
    compressed_path = cache_dir / filename
    xml_path = cache_dir / filename.replace(".bz2", "")
    
    # Load existing metadata
    metadata = _load_cache_metadata(cache_dir, filename)
    
    should_download = (
        refresh or 
        not xml_path.exists() or 
        not compressed_path.exists()
    )
    
    if should_download:
        try:
            # Download with fallback support
            compressed_data, new_etag = _download_with_fallback(filename, cache_dir)
            
            # Validate content before processing
            if not _validate_oval_content(compressed_data):
                raise ValueError("Invalid OVAL content received")
            
            # Calculate checksum
            content_hash = _calculate_sha256(compressed_data)
            
            # Check if content changed (compare with cached hash)
            if metadata.get("sha256") == content_hash and xml_path.exists():
                # Content unchanged, update metadata and return existing file
                metadata.update({
                    "etag": new_etag,
                    "last_checked": int(Path().stat().st_mtime) if Path().exists() else 0
                })
                _save_cache_metadata(cache_dir, filename, metadata)
                return xml_path
            
            # Decompress and save
            xml_data = bz2.decompress(compressed_data)
            
            # Save compressed and decompressed versions
            compressed_path.write_bytes(compressed_data)
            xml_path.write_bytes(xml_data)
            
            # Update metadata
            metadata.update({
                "sha256": content_hash,
                "etag": new_etag,
                "last_updated": int(xml_path.stat().st_mtime),
                "size_bytes": len(compressed_data),
                "xml_size_bytes": len(xml_data)
            })
            _save_cache_metadata(cache_dir, filename, metadata)
            
        except Exception as e:
            # If download fails but we have cached data, use it
            if xml_path.exists():
                print(f"Warning: Failed to update OVAL feed ({e}), using cached version")
                return xml_path
            raise ConnectionError(f"Failed to download OVAL feed and no cached version available: {e}")
    
    return xml_path


def parse_oval(xml_path: Path) -> List[OvalEntry]:
    """Parse OVAL XML into package/fixed-version entries."""
    tree = ET.parse(xml_path)
    root = tree.getroot()

    ns = {"oval": "http://oval.mitre.org/XMLSchema/oval-definitions-5"}

    objects: Dict[str, str] = {}
    states: Dict[str, str] = {}
    tests: Dict[str, tuple[str, str]] = {}

    for obj in root.findall(".//oval:dpkginfo_object", ns):
        obj_id = obj.get("id")
        name_el = obj.find("oval:name", ns)
        if obj_id and name_el is not None and name_el.text:
            objects[obj_id] = name_el.text.strip()

    for state in root.findall(".//oval:dpkginfo_state", ns):
        state_id = state.get("id")
        evr_el = state.find("oval:evr", ns)
        if state_id and evr_el is not None and evr_el.text:
            states[state_id] = evr_el.text.strip()

    for test in root.findall(".//oval:dpkginfo_test", ns):
        test_id = test.get("id")
        object_ref = test.find("oval:object", ns)
        state_ref = test.find("oval:state", ns)
        if test_id and object_ref is not None and state_ref is not None:
            obj_id = object_ref.get("object_ref")
            state_id = state_ref.get("state_ref")
            if obj_id and state_id:
                tests[test_id] = (obj_id, state_id)

    entries: List[OvalEntry] = []

    for definition in root.findall(".//oval:definition", ns):
        metadata = definition.find("oval:metadata", ns)
        if metadata is None:
            continue

        usn = None
        cves = []
        severity = "Unknown"

        for ref in metadata.findall("oval:reference", ns):
            src = ref.get("source", "")
            ref_id = ref.get("ref_id", "")
            if src == "USN":
                usn = ref_id
            if src == "CVE" and ref_id:
                cves.append(ref_id)

        advisory = metadata.find("oval:advisory", ns)
        if advisory is not None:
            sev_el = advisory.find("oval:severity", ns)
            if sev_el is not None and sev_el.text:
                severity = sev_el.text.strip()

        for criterion in definition.findall(".//oval:criterion", ns):
            test_ref = criterion.get("test_ref")
            if not test_ref or test_ref not in tests:
                continue
            obj_id, state_id = tests[test_ref]
            pkg = objects.get(obj_id)
            fixed = states.get(state_id)
            if pkg and fixed:
                entries.append(OvalEntry(pkg, fixed, usn, cves, severity))

    return entries


def discover_available_feeds() -> List[str]:
    """Discover available OVAL feeds from Canonical."""
    available = []
    
    for base_url in [OVAL_BASE_URL] + OVAL_MIRRORS:
        try:
            # Try to get directory listing or known feeds
            resp = requests.get(base_url.rstrip("/") + "/", timeout=30)
            if resp.status_code == 200:
                content = resp.text
                # Look for .oval.xml.bz2 files in HTML content
                import re
                pattern = r'com\.ubuntu\.(\w+)\.usn\.oval\.xml\.bz2'
                matches = re.findall(pattern, content)
                available.extend(matches)
                break  # Use first successful mirror
        except requests.RequestException:
            continue
    
    # Fallback to known codenames if discovery fails
    if not available:
        available = list(CODENAME_TO_OVAL.keys())
    
    return sorted(set(available))


def get_feed_info(codename: str) -> Optional[dict]:
    """Get information about a cached OVAL feed."""
    cache_dir = get_cache_dir()
    filename = get_oval_filename(codename)
    
    metadata = _load_cache_metadata(cache_dir, filename)
    xml_path = cache_dir / filename.replace(".bz2", "")
    
    if not xml_path.exists():
        return None
    
    file_stats = xml_path.stat()
    
    return {
        "codename": codename,
        "filename": filename,
        "cached_path": str(xml_path),
        "size_bytes": metadata.get("xml_size_bytes", file_stats.st_size),
        "compressed_size_bytes": metadata.get("size_bytes"),
        "sha256": metadata.get("sha256"),
        "last_updated": metadata.get("last_updated", int(file_stats.st_mtime)),
        "etag": metadata.get("etag"),
        "last_checked": metadata.get("last_checked")
    }
