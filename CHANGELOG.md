# Changelog

All notable changes to PrivEsc-Enumerator will be documented in this file.

## [1.0.0] - 2025-12-27

### Added
- Initial release of PrivEsc-Enumerator framework
- Linux privilege escalation enumeration script (`linpeas_advanced.sh`)
- macOS privilege escalation enumeration script (`macpeas_advanced.sh`)
- Comprehensive README with full documentation
- Quick usage guide with exploitation examples
- Output file support with `-o` flag
- Color-coded risk indicators (CRITICAL, HIGH-RISK, POTENTIAL, INFO)
- 12+ enumeration categories per platform

### Linux Features
- System information (kernel, architecture, SELinux, AppArmor)
- User and privilege checks
- Sudo and authentication enumeration
- File permission analysis (SUID, SGID, capabilities)
- Process and service enumeration
- Cron and scheduled task checks
- Environment and PATH analysis
- Network configuration and services
- Docker and container detection
- Software and compiler enumeration
- Known kernel exploit detection (DirtyCow, Dirty Pipe, PwnKit)
- Sensitive file and credential discovery

### macOS Features
- System information (SIP, Gatekeeper, FileVault, Secure Boot)
- User and privilege checks
- Sudo and authentication enumeration
- File permission analysis
- Launch Services and persistence mechanisms
- Environment and PATH analysis
- Software and application enumeration
- Kernel extension analysis
- Scheduled task checks
- Security control verification (XProtect, TCC, firewall)
- Network configuration
- Exploit suggestions and resources

### Technical Details
- Zero dependencies (uses built-in tools only)
- Non-destructive, read-only operations
- Graceful error handling
- Timestamped output files
- Summary section with prioritized findings
- Total findings counter per risk level

---

## Future Improvements

### Planned Features
- [ ] Windows privilege escalation script
- [ ] JSON output format for automation
- [ ] Web-based report generation
- [ ] Integration with exploit frameworks
- [ ] Database of known exploits
- [ ] Automated exploitation suggestions
- [ ] Container-specific checks (Kubernetes, Podman)
- [ ] Cloud instance metadata enumeration (AWS, GCP, Azure)
- [ ] Active Directory enumeration for domain-joined systems
- [ ] Credential extraction modules
- [ ] Binary analysis for custom applications

### Known Limitations
- Some checks require elevated privileges for complete enumeration
- Performance may vary on systems with large filesystems
- Terminal color support required for best experience
- Some macOS checks require Full Disk Access permission

---

**Maintained by**: Security Research Team
**License**: MIT
