from pathlib import Path

from secpatchlab.core.oval import parse_oval


def test_parse_oval_sample():
    xml_path = Path(__file__).parent / "fixtures" / "sample_oval.xml"
    entries = parse_oval(xml_path)
    assert len(entries) == 1
    e = entries[0]
    assert e.package == "openssl"
    assert e.fixed_version == "1.2.3-4"
    assert e.usn == "USN-0000-1"
    assert "CVE-2020-0001" in e.cves
    assert e.severity == "High"
