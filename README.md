# PrivEsc-Enumerator

> **Advanced Privilege Escalation Enumeration Framework for Linux & macOS**

A comprehensive, production-grade toolkit for identifying privilege escalation vectors on Linux and macOS systems. Designed by security professionals with over 20 years of combined experience in penetration testing and red teaming.

## 📋 Features

- **Dual OS Support**: Complete enumeration for both Linux and macOS
- **Comprehensive Checks**: 12+ major categories covering all known privilege escalation vectors
- **Smart Detection**: Automated identification of critical, high-risk, and potential vulnerabilities
- **Beautiful Output**: Color-coded terminal output with clear risk indicators
- **Export Capability**: Save all findings to timestamped output files
- **Zero Dependencies**: Uses only built-in system tools (bash, standard Unix utilities)
- **Non-Destructive**: Read-only operations with graceful error handling

## 🎯 What It Checks

### Linux (`linpeas_advanced.sh`)
1. **System Information** - OS details, kernel version, architecture, SELinux/AppArmor status
2. **User & Privileges** - Current user info, group memberships, shadow file access
3. **Sudo & Authentication** - Sudo version, privileges, NOPASSWD entries, polkit
4. **File Permissions** - SUID/SGID binaries, writable files, file capabilities
5. **Processes & Services** - Running processes, systemd services, writable binaries
6. **Cron & Scheduled Tasks** - System crontabs, writable cron scripts, systemd timers
7. **Environment & PATH** - PATH hijacking opportunities, dangerous environment variables
8. **Networking** - Open ports, listening services, firewall rules, active connections
9. **Docker & Containers** - Docker installation, socket permissions, container escape detection
10. **Installed Software** - Compilers, development tools, network tools
11. **Kernel Exploits** - DirtyCow, Dirty Pipe, PwnKit vulnerability checks
12. **Sensitive Files** - Password in configs, database credentials, bash history

### macOS (`macpeas_advanced.sh`)
1. **System Information** - macOS version, SIP status, Gatekeeper, FileVault
2. **User & Privileges** - User info, admin group members, login items
3. **Sudo & Authentication** - Sudo privileges, PAM configuration, password policies
4. **File Permissions** - World-writable files, SUID binaries, sensitive file access
5. **Launch Services** - LaunchDaemons/Agents, writable plists, persistence mechanisms
6. **Environment & PATH** - PATH hijacking, DYLD variables, shell configs
7. **Installed Software** - Applications, Homebrew packages, development tools
8. **Kernel Extensions** - Loaded kexts, third-party extensions, system extensions
9. **Scheduled Tasks** - Cron jobs, periodic scripts, at jobs
10. **Security Controls** - XProtect, MRT, TCC database, firewall status
11. **Networking** - Network interfaces, listening services, DNS configuration
12. **Additional Checks** - Sensitive data, credentials, exploit suggestions

## 🚀 Quick Start

```bash
# Clone or download the repository
cd PrivEsc-Enumerator/scripts

# For Linux
chmod +x linpeas_advanced.sh
./linpeas_advanced.sh

# For macOS
chmod +x macpeas_advanced.sh
./macpeas_advanced.sh
```

## 💾 Save Output to File

```bash
# Linux
./linpeas_advanced.sh -o /tmp/my_enum_results.txt

# macOS
./macpeas_advanced.sh -o /tmp/my_enum_results.txt
```

## 📊 Output Interpretation

The scripts use a color-coded risk classification system:

- 🔴 **[CRITICAL]** - Immediate privilege escalation possible (e.g., docker group, writable /etc/shadow)
- 🟠 **[HIGH-RISK]** - Strong privilege escalation vector (e.g., SUID vim, writable sudo files)
- 🟡 **[POTENTIAL]** - Configuration weakness worth investigating (e.g., user in admin group)
- 🔵 **[INFO]** - System information for context

## 🛡️ Use Cases

- **Penetration Testing**: Initial enumeration on compromised systems
- **CTF Competitions**: Quick identification of privilege escalation paths
- **Security Audits**: System hardening and configuration review
- **Red Team Operations**: Post-exploitation enumeration
- **Security Training**: Learning privilege escalation techniques

## ⚠️ Legal Disclaimer

These tools are for **authorized security testing and educational purposes only**. Only use on systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal.

## 📁 Project Structure

```
PrivEsc-Enumerator/
├── scripts/
│   ├── linpeas_advanced.sh      # Linux enumeration script
│   └── macpeas_advanced.sh      # macOS enumeration script
├── output/                       # Output files directory
├── docs/                         # Documentation
└── README.md                     # This file
```

## 🔧 Requirements

### Linux
- Bash 4.0+
- Standard Unix utilities (find, grep, awk, etc.)
- No root required (but more findings with elevated privileges)

### macOS
- macOS 10.14+ (Mojave or later)
- Bash or Zsh
- No root required (but some checks require elevated privileges)

## 🤝 Contributing

Contributions are welcome! If you discover new privilege escalation vectors or improvements, please submit a pull request.

## 📚 Resources

- [GTFOBins](https://gtfobins.github.io/) - Unix binaries for privilege escalation
- [HackTricks](https://book.hacktricks.xyz/) - Pentesting methodology
- [PEASS-ng](https://github.com/carlospolop/PEASS-ng) - Original linPEAS inspiration
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Privilege escalation techniques

## 📝 License

MIT License - Use at your own risk

---

**Created by Security Professionals | For Security Professionals**

*Happy Hunting! 🏴‍☠️*
