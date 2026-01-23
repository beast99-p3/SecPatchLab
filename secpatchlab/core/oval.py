from __future__ import annotations

import os
import bz2
import requests
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict

from secpatchlab.core.utils import ensure_dir, get_cache_dir

OVAL_BASE_URL = os.getenv("OVAL_BASE_URL", "https://security-metadata.canonical.com/oval/")

CODENAME_TO_OVAL = {
    "focal": "com.ubuntu.focal.usn.oval.xml.bz2",
    "jammy": "com.ubuntu.jammy.usn.oval.xml.bz2",
    "kinetic": "com.ubuntu.kinetic.usn.oval.xml.bz2",
    "lunar": "com.ubuntu.lunar.usn.oval.xml.bz2",
    "mantic": "com.ubuntu.mantic.usn.oval.xml.bz2",
    "noble": "com.ubuntu.noble.usn.oval.xml.bz2",
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


def ensure_oval(codename: str, refresh: bool = False) -> Path:
    """Download and cache the OVAL feed for a codename."""
    cache_dir = get_cache_dir()
    ensure_dir(cache_dir)
    filename = get_oval_filename(codename)
    compressed = cache_dir / filename
    xml_path = cache_dir / filename.replace(".bz2", "")

    if refresh or not xml_path.exists():
        url = OVAL_BASE_URL.rstrip("/") + "/" + filename
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        compressed.write_bytes(resp.content)
        xml_path.write_bytes(bz2.decompress(resp.content))

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
