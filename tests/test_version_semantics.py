"""Tests for Debian version comparison functionality."""

import pytest
from secpatchlab.core.dpkg import compare_versions, parse_version_components, normalize_version


class TestVersionComparison:
    """Test cases for Debian package version comparison."""
    
    def test_basic_version_comparison(self):
        """Test basic version comparisons."""
        assert compare_versions("1.0", "lt", "2.0") == True
        assert compare_versions("2.0", "lt", "1.0") == False
        assert compare_versions("1.0", "eq", "1.0") == True
        assert compare_versions("1.0", "gt", "0.9") == True
    
    def test_ubuntu_security_versions(self):
        """Test Ubuntu security update version comparisons."""
        # Real-world Ubuntu security update example
        assert compare_versions("1.1.1f-1ubuntu2.17", "lt", "1.1.1f-1ubuntu2.19") == True
        assert compare_versions("1.1.1f-1ubuntu2.19", "lt", "1.1.1f-1ubuntu2.17") == False
        
        # Different Ubuntu revisions
        assert compare_versions("2.7.4-0ubuntu1.1", "lt", "2.7.4-0ubuntu1.2") == True
        assert compare_versions("2.7.4-0ubuntu1", "lt", "2.7.4-0ubuntu1.1") == True
    
    def test_epoch_handling(self):
        """Test epoch comparison."""
        assert compare_versions("1.0", "lt", "1:0.9") == True
        assert compare_versions("1:1.0", "gt", "2.0") == True
        assert compare_versions("2:1.0", "gt", "1:2.0") == True
    
    def test_backport_versions(self):
        """Test backport version handling."""
        # Backports typically have ~bpo suffix
        assert compare_versions("1.0", "gt", "1.0~bpo11+1") == True
        assert compare_versions("1.1~bpo11+1", "lt", "1.1") == True
    
    def test_security_pocket_suffixes(self):
        """Test security pocket version suffixes."""
        # Security updates often have specific patterns
        assert compare_versions("1.0-1", "lt", "1.0-1+deb11u1") == True
        assert compare_versions("1.0-1+deb11u1", "lt", "1.0-1+deb11u2") == True
    
    def test_complex_version_strings(self):
        """Test complex real-world version strings."""
        # OpenSSL versions from real Ubuntu systems
        versions = [
            ("1.1.1-1ubuntu2.1~18.04.20", "lt", "1.1.1-1ubuntu2.1~18.04.21"),
            ("3.0.2-0ubuntu1.8", "lt", "3.0.2-0ubuntu1.10"),
            ("1.1.1f-1ubuntu2", "lt", "1.1.1f-1ubuntu2.17"),
        ]
        
        for installed, op, fixed in versions:
            assert compare_versions(installed, op, fixed) == True
    
    def test_edge_cases(self):
        """Test edge cases and unusual version formats."""
        # Empty or minimal versions
        assert compare_versions("", "lt", "1.0") == True
        assert compare_versions("0", "lt", "0.1") == True
        
        # Version with letters
        assert compare_versions("1.0a", "lt", "1.0b") == True
        assert compare_versions("1.0", "lt", "1.0a") == True


class TestVersionParsing:
    """Test version string parsing functionality."""
    
    def test_parse_simple_version(self):
        """Test parsing simple version strings."""
        components = parse_version_components("1.2.3")
        assert components["upstream"] == "1.2.3"
        assert components["epoch"] is None
        assert components["revision"] is None
    
    def test_parse_version_with_revision(self):
        """Test parsing versions with Debian revision."""
        components = parse_version_components("1.2.3-4ubuntu1")
        assert components["upstream"] == "1.2.3"
        assert components["revision"] == "4ubuntu1"
        assert components["epoch"] is None
    
    def test_parse_version_with_epoch(self):
        """Test parsing versions with epoch."""
        components = parse_version_components("2:1.2.3-4")
        assert components["epoch"] == 2
        assert components["upstream"] == "1.2.3"
        assert components["revision"] == "4"
    
    def test_parse_complex_ubuntu_version(self):
        """Test parsing complex Ubuntu version strings."""
        components = parse_version_components("1:1.1.1f-1ubuntu2.19")
        assert components["epoch"] == 1
        assert components["upstream"] == "1.1.1f"
        assert components["revision"] == "1ubuntu2.19"


class TestVersionNormalization:
    """Test version string normalization."""
    
    def test_normalize_basic_versions(self):
        """Test basic version normalization."""
        assert normalize_version("1.0") == "1.0"
        assert normalize_version(" 1.0 ") == "1.0"
        assert normalize_version("") == "0"
    
    def test_normalize_complex_versions(self):
        """Test normalization of complex version strings."""
        # Should handle whitespace and edge cases
        normalized = normalize_version("  1:1.0-1ubuntu1  ")
        assert normalized.strip() == normalized
        assert "1:1.0-1ubuntu1" in normalized


# Integration tests that require the actual system
class TestIntegrationVersionComparison:
    """Integration tests for version comparison with real system."""
    
    def test_known_vulnerability_versions(self):
        """Test version comparisons for known vulnerabilities."""
        # Test cases based on real CVEs and USNs
        test_cases = [
            # OpenSSL CVE examples
            ("1.1.1f-1ubuntu2.16", "lt", "1.1.1f-1ubuntu2.17"),  # CVE-2022-4203
            ("3.0.2-0ubuntu1.8", "lt", "3.0.2-0ubuntu1.10"),      # CVE-2023-0464
            
            # Sudo examples  
            ("1.8.31-1ubuntu1.2", "lt", "1.8.31-1ubuntu1.5"),     # CVE-2021-3156
            ("1.9.5p2-3ubuntu1.4", "lt", "1.9.9-1ubuntu2.4"),     # CVE-2023-22809
        ]
        
        for installed, op, fixed in test_cases:
            result = compare_versions(installed, op, fixed)
            assert result == True, f"Expected {installed} {op} {fixed} to be True"


if __name__ == "__main__":
    # Run basic tests
    test_comparison = TestVersionComparison()
    test_comparison.test_basic_version_comparison()
    test_comparison.test_ubuntu_security_versions()
    
    print("Basic version comparison tests passed!")