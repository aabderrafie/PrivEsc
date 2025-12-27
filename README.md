# PrivEsc - Privilege Escalation Enumeration Tool

**Advanced privilege escalation enumeration for Linux & macOS**

## Quick Start

```bash
# Linux
./scripts/linpeas.sh

# macOS  
./scripts/macpeas.sh

# Save to file
./scripts/linpeas.sh -o output.txt
./scripts/macpeas.sh -o output.txt
```

## What It Does

Checks for all common privilege escalation vectors:
- SUID/SGID binaries
- Sudo misconfigurations
- Writable files and directories
- Cron jobs and scheduled tasks
- Docker/container permissions
- Kernel vulnerabilities
- Credentials in files
- And much more...

## Output Colors

- 🔴 **CRITICAL** - Instant root/admin access
- 🟠 **HIGH-RISK** - Strong privilege escalation vector
- 🟡 **POTENTIAL** - Worth investigating
- 🔵 **INFO** - System information

## Requirements

- Bash 4.0+
- No root required (but more findings with sudo)
- Works on all Linux distros and macOS 10.14+

## Legal Notice

**For authorized testing only.** Only use on systems you own or have permission to test.

---

Created by security professionals | For security professionals
