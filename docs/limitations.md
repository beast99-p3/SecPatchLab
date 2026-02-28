# SecPatchLab Known Limitations

This document outlines the current limitations, constraints, and unsupported scenarios in SecPatchLab. Understanding these limitations is crucial for proper usage and setting appropriate expectations.

## Platform and Distribution Limitations

### Ubuntu-Only Support

**Current Scope**: Ubuntu Linux distributions only
- Designed specifically for Ubuntu OVAL feeds from Canonical
- Package management assumes `apt`/`dpkg` toolchain
- Version comparison logic tuned for Ubuntu/Debian versioning

**Unsupported Distributions**:
- Red Hat Enterprise Linux (RHEL) / CentOS / Fedora
- SUSE Linux Enterprise / openSUSE
- Arch Linux / Alpine Linux
- macOS / Windows (except via WSL2)

**Rationale**: OVAL feed formats, package managers, and security advisory structures differ significantly between distributions.

**Workaround**: Use WSL2 on Windows or Ubuntu containers/VMs on other platforms.

### Ubuntu Version Coverage

**Supported Releases**:
- Ubuntu 20.04 LTS (Focal Fossa)
- Ubuntu 22.04 LTS (Jammy Jellyfish) 
- Ubuntu 23.04 (Lunar Lobster)
- Ubuntu 23.10 (Mantic Minotaur)
- Ubuntu 24.04 LTS (Noble Numbat)

**Limitations**:
- Older releases may have incomplete OVAL coverage
- End-of-life releases not supported
- Development/daily builds not recommended

**Future Releases**: Require updating `CODENAME_TO_OVAL` mapping in `oval.py`

## Architecture Limitations

### CPU Architecture Support

**Primary Support**: x86_64 (amd64)
- OVAL feeds primarily focus on x86_64 packages
- Docker validation containers assume amd64 base images
- Testing primarily conducted on x86_64 systems

**Limited Support**: 
- ARM64 (aarch64): Basic functionality available but less tested
- ARM32: May work but not validated
- Other architectures (RISC-V, PowerPC, s390x): Unsupported

**Cross-Architecture Issues**:
- Architecture-specific vulnerabilities may be misrepresented
- Docker builds may fail on non-x86_64 hosts
- Package availability varies by architecture

## Security Detection Limitations

### Vulnerability Coverage

**Scope**: Package-level vulnerabilities only
- No application-layer vulnerability detection
- No custom code or configuration analysis
- No runtime exploit detection

**OVAL Feed Dependencies**:
- Relies entirely on Canonical's OVAL feed completeness
- May miss vulnerabilities not yet published in USN format
- Zero-day vulnerabilities not detectable until USN release

**Package Boundaries**:
- Only detects vulnerabilities in packaged software
- Snap, Flatpak, AppImage applications not covered
- Manually compiled software not analyzed
- Container images and their contents not scanned

### False Positive/Negative Scenarios

**Common False Positives**:
- Backported security fixes not reflected in version numbers
- Meta-packages flagged when underlying libraries are secure
- Architecture-specific CVEs reported on all architectures
- Custom kernel builds with security patches not recognized

**Common False Negatives**:
- Package name mismatches between OVAL and system
- Custom PPAs with different versioning schemes
- Security fixes applied via configuration rather than code changes
- Embedded library vulnerabilities in statically linked binaries

## Validation and Testing Limitations

### Docker Dependency

**Hard Requirement**: Docker must be available and functional
- No alternative container runtimes supported (Podman, etc.)
- Fails gracefully but validation becomes unavailable
- Requires Docker daemon running with appropriate permissions

**Docker-specific Issues**:
- Host kernel capabilities affect container security features
- Storage driver compatibility may cause build failures
- Network connectivity required for package downloads during builds
- Large disk space requirements for build artifacts

### Build Environment Constraints

**Build Tools Availability**:
- Depends on Ubuntu repositories having build dependencies
- Some packages require proprietary or restricted tools
- Network-dependent builds may fail in isolated containers
- Build-time test failures don't necessarily indicate patch problems

**Resource Limitations**:
- Default resource limits may be insufficient for large packages
- Memory-intensive builds can fail in constrained environments
- No parallel build optimization implemented
- Timeout values may need adjustment for slow systems

### Patch Application Limitations

**Patch Format Support**:
- Git patches generally work better than unified diffs
- Binary patches not supported
- Patches requiring interactive input will fail
- Context-sensitive patches may fail on different versions

**Patch Quality Dependencies**:
- Assumes well-formed, compatible patches
- No automatic patch adaptation or fuzzing
- Multi-file patches must apply cleanly in sequence
- Manual patch review recommended for critical updates

## Runtime and Operational Limitations

### Performance Characteristics

**Scan Performance**:
- Large systems (>10,000 packages) may have slow scan times
- OVAL feed parsing is CPU-intensive for large feeds
- Memory usage scales with number of installed packages
- Network bandwidth required for initial OVAL download

**Validation Performance**:
- Each package validation requires separate Docker build
- Sequential validation only (no parallel processing)
- Build artifacts consume significant disk space
- No incremental or cached validation results

### Concurrency and Scaling

**Single-User Design**:
- No multi-tenant support or user isolation
- File system permissions assume single administrative user
- No concurrent validation run protection
- Shared OVAL cache between all scans

**API Limitations**:
- FastAPI backend has no authentication or authorization
- No rate limiting on scan or validation endpoints
- Background task queue is in-memory only
- No persistent job scheduling or retry mechanisms

## Specific Package Type Limitations

### Kernel Packages

**Special Handling Required**:
- Kernel updates require reboot to become effective
- Multiple kernel versions may be installed simultaneously
- Running kernel version may differ from newest installed
- Kernel module compatibility not validated

**Not Detected**:
- Out-of-tree kernel modules
- Custom kernel patches or configurations
- Hardware-specific microcode updates
- Bootloader vulnerabilities

### System Package Edge Cases

**Essential Packages**:
- Core system packages (libc6, init, etc.) flagged but difficult to update
- Package removal may break system functionality
- Dependency resolution not performed before suggesting updates
- No rollback mechanism for failed updates

**Virtual and Meta Packages**:
- Virtual packages provide functionality but have no direct version
- Meta-packages may not reflect underlying library versions
- Transitional packages create confusing vulnerability reports
- Package name mapping inconsistencies with OVAL feeds

### Language-Specific Package Managers

**Not Covered**:
- Python pip packages
- Node.js npm packages  
- Ruby gems
- Golang modules
- Rust crates
- Java Maven/Gradle dependencies

**Rationale**: These ecosystems have separate vulnerability databases and versioning schemes incompatible with OVAL.

## Integration and Workflow Limitations

### CI/CD Integration

**Missing Features**:
- No native GitHub Actions integration
- No Jenkins plugin availability
- Exit codes not optimized for CI/CD pipelines
- No machine-readable confidence scoring

**SARIF Limitations**:
- No automatic GitHub Security tab upload
- Manual upload process required
- No integration with GitHub Advanced Security features
- Limited tool metadata in SARIF output

### Reporting and Output

**Format Constraints**:
- Fixed output formats (table, JSON, SARIF)
- No custom report templates
- Limited filtering and sorting options
- No trending or historical analysis

**Data Export**:
- No database backend for persistence
- Results stored as individual JSON files
- No bulk export or import capabilities
- Limited query and analysis functionality

## Network and Connectivity Requirements

### Internet Dependencies

**Required Connectivity**:
- Initial OVAL feed download requires internet access
- Package validation downloads build dependencies from repositories
- No offline mode for validation (scan can work with cached feeds)
- HTTPS connectivity required for secure feed downloads

**Proxy and Firewall Issues**:
- Docker build process may not respect system proxy settings
- Corporate firewalls may block required repository access
- No configuration for custom certificate authorities
- Limited support for air-gapped environments

### Network Security

**Unencrypted Components**:
- Internal API communication not encrypted by default
- Docker container networking uses default configurations
- No built-in VPN or tunnel support for remote access
- Log files may contain sensitive system information

## Data Privacy and Security Limitations

### Information Disclosure

**System Information Exposure**:
- Package lists reveal installed software and versions
- Validation logs may contain system paths and configurations
- Network requests expose system identity to repositories
- No data anonymization or redaction features

**Output Security**:
- Reports contain detailed system vulnerability information
- No encryption for stored scan results
- File permissions rely on host system configuration
- Temporary files may persist after failures

### Compliance and Auditing

**Missing Features**:
- No audit logging of user actions
- No compliance framework integration (SOC2, FedRAMP, etc.)
- No data retention policy enforcement
- Limited forensic analysis capabilities

## Future Limitation Roadmap

### Planned Improvements

**Short-term** (next release):
- Better error messages for unsupported scenarios
- Graceful degradation when optional dependencies missing
- Improved documentation of system requirements
- Basic proxy support for Docker builds

**Medium-term** (2-3 releases):
- Support for additional Ubuntu architectures (ARM64)
- Alternative container runtime support (Podman)
- Improved package name mapping and disambiguation
- Performance optimizations for large systems

**Long-term** (future major versions):
- Multi-distribution support framework
- Plugin architecture for custom vulnerability sources
- Database backend for persistence and analysis
- Enhanced CI/CD integration capabilities

### Non-Goals

**Explicitly Out of Scope**:
- Windows-native vulnerability scanning
- Application-layer security testing  
- Penetration testing or exploitation
- Compliance framework implementation
- Enterprise identity management integration
- Real-time system monitoring or alerting

## Mitigation Strategies

### Working Around Limitations

**For False Positives**:
- Cross-reference findings with official Ubuntu Security Notices
- Check package changelog for backported security fixes
- Use validation sandbox to verify actual vulnerability status
- Maintain allowlists for known false positives

**For Missing Coverage**:
- Supplement with other security tools for complete coverage
- Monitor upstream security mailing lists for early warnings
- Implement custom scripts for unsupported package managers
- Use container scanning tools for containerized applications

**For Performance Issues**:
- Run scans during maintenance windows
- Use `--top N` flag to limit initial analysis scope
- Cache OVAL feeds and refresh periodically rather than per-scan
- Consider distributed scanning for very large environments

### Best Practices

**Deployment Recommendations**:
- Deploy on dedicated security analysis systems
- Implement network segmentation for validation activities
- Regular backup of scan results and configuration
- Monitor disk space usage for validation artifacts

**Operational Procedures**:
- Establish baseline scans for comparison
- Review and triage findings before taking action
- Test updates in development environments first
- Maintain documentation of local customizations and exceptions