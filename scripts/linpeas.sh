#!/bin/bash
################################################################################
# Linux Privilege Escalation Enumeration Script (Advanced)
# Author: Security Research Team
# Purpose: Comprehensive local enumeration for privilege escalation vectors
# Target: Linux (All distributions)
# Usage: ./linpeas_advanced.sh [-o output_file]
################################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Risk level indicators
INFO="${BLUE}[INFO]${NC}"
POTENTIAL="${YELLOW}[POTENTIAL]${NC}"
HIGH_RISK="${RED}[HIGH-RISK]${NC}"
CRITICAL="${RED}${BOLD}[CRITICAL]${NC}"

# Default output file
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="/tmp/linpeas_enum_${TIMESTAMP}.txt"
SAVE_TO_FILE=false

# Arrays to store findings
declare -a FINDINGS_INFO
declare -a FINDINGS_POTENTIAL
declare -a FINDINGS_HIGH_RISK
declare -a FINDINGS_CRITICAL

################################################################################
# Helper Functions
################################################################################

print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║            Linux Privilege Escalation Enumeration Script                 ║
║                        (Advanced Edition)                                 ║
║                                                                           ║
║      Comprehensive Local Security Assessment & Vector Discovery          ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

print_section() {
    local title="$1"
    echo -e "\n${BOLD}${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${MAGENTA}  $title${NC}"
    echo -e "${BOLD}${MAGENTA}═══════════════════════════════════════════════════════════════${NC}\n"
}

print_subsection() {
    local title="$1"
    echo -e "${CYAN}${BOLD}▶ $title${NC}"
}

log_finding() {
    local level="$1"
    local message="$2"
    
    case "$level" in
        "INFO")
            echo -e "${INFO} $message"
            FINDINGS_INFO+=("$message")
            ;;
        "POTENTIAL")
            echo -e "${POTENTIAL} $message"
            FINDINGS_POTENTIAL+=("$message")
            ;;
        "HIGH-RISK")
            echo -e "${HIGH_RISK} $message"
            FINDINGS_HIGH_RISK+=("$message")
            ;;
        "CRITICAL")
            echo -e "${CRITICAL} $message"
            FINDINGS_CRITICAL+=("$message")
            ;;
    esac
}

safe_exec() {
    local cmd="$1"
    local description="$2"
    
    if output=$(eval "$cmd" 2>/dev/null); then
        if [[ -n "$output" ]]; then
            echo -e "${GREEN}✓${NC} $description"
            echo "$output"
            return 0
        else
            echo -e "${YELLOW}⚠${NC} $description (no output)"
            return 1
        fi
    else
        echo -e "${RED}✗${NC} $description (permission denied or error)"
        return 1
    fi
}

check_writable() {
    local path="$1"
    [[ -w "$path" ]] && return 0 || return 1
}

check_readable() {
    local path="$1"
    [[ -r "$path" ]] && return 0 || return 1
}

################################################################################
# 1. SYSTEM INFORMATION
################################################################################

enum_system_info() {
    print_section "1. SYSTEM INFORMATION"
    
    print_subsection "Operating System Details"
    if [[ -f /etc/os-release ]]; then
        cat /etc/os-release
        log_finding "INFO" "OS: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
    elif [[ -f /etc/lsb-release ]]; then
        cat /etc/lsb-release
    fi
    
    echo ""
    print_subsection "Kernel Information"
    uname -a
    kernel_version=$(uname -r)
    log_finding "INFO" "Kernel: $kernel_version"
    
    # Check for known vulnerable kernels
    if [[ "$kernel_version" < "4.10" ]]; then
        log_finding "HIGH-RISK" "Old kernel version - likely vulnerable to multiple exploits"
    fi
    
    echo ""
    print_subsection "Architecture"
    arch=$(uname -m)
    echo "Architecture: $arch"
    log_finding "INFO" "Architecture: $arch"
    
    echo ""
    print_subsection "Hostname"
    hostname
    hostname -f 2>/dev/null
    
    echo ""
    print_subsection "Uptime"
    uptime
    
    echo ""
    print_subsection "Installed Packages Count"
    if command -v dpkg >/dev/null 2>&1; then
        dpkg_count=$(dpkg -l | grep ^ii | wc -l)
        echo "Debian packages: $dpkg_count"
    fi
    if command -v rpm >/dev/null 2>&1; then
        rpm_count=$(rpm -qa | wc -l)
        echo "RPM packages: $rpm_count"
    fi
    
    echo ""
    print_subsection "SELinux Status"
    if command -v getenforce >/dev/null 2>&1; then
        selinux_status=$(getenforce 2>/dev/null)
        echo "SELinux: $selinux_status"
        if [[ "$selinux_status" == "Disabled" ]]; then
            log_finding "POTENTIAL" "SELinux is disabled"
        fi
    else
        echo "SELinux: Not installed"
    fi
    
    echo ""
    print_subsection "AppArmor Status"
    if command -v aa-status >/dev/null 2>&1; then
        aa-status 2>/dev/null | head -20 || echo "Cannot read AppArmor status"
    else
        echo "AppArmor: Not installed"
    fi
}

################################################################################
# 2. USER & PRIVILEGES
################################################################################

enum_user_privileges() {
    print_section "2. USER & PRIVILEGES"
    
    print_subsection "Current User Information"
    echo "User: $(whoami)"
    echo "UID: $(id -u)"
    echo "GID: $(id -g)"
    echo "Groups: $(id -Gn)"
    log_finding "INFO" "Current user: $(whoami) (UID: $(id -u))"
    
    echo ""
    print_subsection "Privileged Groups"
    groups=$(id -Gn)
    for group in sudo wheel admin root docker lxd disk video plugdev shadow; do
        if echo "$groups" | grep -qw "$group"; then
            log_finding "CRITICAL" "User is member of privileged group: $group"
        fi
    done
    
    echo ""
    print_subsection "Users with UID 0"
    awk -F: '$3 == 0 {print $1}' /etc/passwd
    uid0_count=$(awk -F: '$3 == 0' /etc/passwd | wc -l)
    if [[ $uid0_count -gt 1 ]]; then
        log_finding "HIGH-RISK" "Multiple users with UID 0 detected!"
    fi
    
    echo ""
    print_subsection "Users with Login Shell"
    grep -v '/nologin\|/false' /etc/passwd | grep -v '^#'
    
    echo ""
    print_subsection "Sudo Group Members"
    getent group sudo 2>/dev/null || getent group wheel 2>/dev/null
    
    echo ""
    print_subsection "Recently Modified Users"
    find /home -maxdepth 1 -type d -mtime -30 2>/dev/null
    
    echo ""
    print_subsection "Shadow File Permissions"
    ls -la /etc/shadow 2>/dev/null
    if check_readable /etc/shadow; then
        log_finding "CRITICAL" "/etc/shadow is readable! Can extract password hashes!"
        echo "First 5 lines:"
        head -5 /etc/shadow 2>/dev/null
    fi
    
    echo ""
    print_subsection "Passwd File Check"
    if grep -v '^\*\|^!' /etc/shadow 2>/dev/null | grep ':$'; then
        log_finding "CRITICAL" "Users with empty passwords found in /etc/shadow!"
    fi
}

################################################################################
# 3. SUDO & AUTHENTICATION
################################################################################

enum_sudo() {
    print_section "3. SUDO & AUTHENTICATION"
    
    print_subsection "Sudo Version"
    sudo_version=$(sudo -V 2>/dev/null | head -1)
    echo "$sudo_version"
    log_finding "INFO" "Sudo version: $sudo_version"
    
    # Check for known vulnerable sudo versions
    if echo "$sudo_version" | grep -qE "1\.(8\.[0-9]|8\.1[0-9]|8\.2[0-7]|[0-7]\.)"; then
        log_finding "CRITICAL" "Vulnerable sudo version detected (CVE-2021-3156 - Baron Samedit)"
    fi
    
    echo ""
    print_subsection "Sudo Privileges (sudo -l)"
    if sudo -n -l 2>/dev/null; then
        log_finding "POTENTIAL" "Can run sudo -l without password!"
        
        # Check for dangerous NOPASSWD entries
        if sudo -n -l 2>/dev/null | grep -i "NOPASSWD"; then
            log_finding "CRITICAL" "NOPASSWD sudo rules found!"
        fi
        
        # Check for dangerous binaries
        dangerous_bins=(bash sh zsh vim vi nano less more awk perl python ruby lua gcc cc find nmap nc netcat socat ssh ftp)
        for bin in "${dangerous_bins[@]}"; do
            if sudo -n -l 2>/dev/null | grep -qw "$bin"; then
                log_finding "HIGH-RISK" "Dangerous sudo binary allowed: $bin"
            fi
        done
    else
        echo "Cannot run sudo -l without password"
    fi
    
    echo ""
    print_subsection "Sudoers File"
    ls -la /etc/sudoers 2>/dev/null
    if check_writable /etc/sudoers; then
        log_finding "CRITICAL" "/etc/sudoers is writable!"
    fi
    
    echo ""
    print_subsection "Sudoers.d Directory"
    ls -la /etc/sudoers.d/ 2>/dev/null
    find /etc/sudoers.d/ -type f -writable 2>/dev/null | while read -r file; do
        log_finding "CRITICAL" "Writable sudoers file: $file"
    done
    
    echo ""
    print_subsection "Cached Sudo Credentials"
    if sudo -n true 2>/dev/null; then
        log_finding "CRITICAL" "Sudo credentials cached - can run sudo without password!"
    fi
    
    echo ""
    print_subsection "Polkit (pkexec) Configuration"
    if command -v pkexec >/dev/null 2>&1; then
        pkexec --version
        log_finding "INFO" "Polkit is installed"
        
        # Check for CVE-2021-4034 (PwnKit)
        if [[ -f /usr/bin/pkexec ]]; then
            pkexec_ver=$(pkexec --version 2>&1 | head -1)
            log_finding "POTENTIAL" "pkexec found - check for CVE-2021-4034 (PwnKit)"
        fi
    fi
}

################################################################################
# 4. FILE PERMISSIONS & MISCONFIGURATIONS
################################################################################

enum_file_permissions() {
    print_section "4. FILE PERMISSIONS & MISCONFIGURATIONS"
    
    print_subsection "World-Writable Directories in /etc"
    find /etc -type d -perm -0002 2>/dev/null | head -20
    
    echo ""
    print_subsection "World-Writable Files in /etc"
    find /etc -type f -perm -0002 2>/dev/null | head -20
    world_writable=$(find /etc -type f -perm -0002 2>/dev/null | wc -l)
    if [[ $world_writable -gt 0 ]]; then
        log_finding "HIGH-RISK" "Found $world_writable world-writable files in /etc"
    fi
    
    echo ""
    print_subsection "SUID Binaries"
    echo "SUID binaries (potentially exploitable):"
    find / -type f -perm -4000 2>/dev/null | head -50
    
    # Check for unusual SUID binaries
    unusual_suid=(nmap vim nano less more cp mv find nc netcat python perl ruby lua bash sh)
    for bin in "${unusual_suid[@]}"; do
        if find / -type f -perm -4000 -name "*$bin*" 2>/dev/null | grep -q .; then
            log_finding "CRITICAL" "Unusual SUID binary found: $bin"
        fi
    done
    
    echo ""
    print_subsection "SGID Binaries"
    find / -type f -perm -2000 2>/dev/null | head -50
    
    echo ""
    print_subsection "Files with Capabilities"
    if command -v getcap >/dev/null 2>&1; then
        echo "Files with capabilities:"
        getcap -r / 2>/dev/null
        
        # Check for dangerous capabilities
        if getcap -r / 2>/dev/null | grep -E "cap_setuid|cap_setgid|cap_dac_override"; then
            log_finding "CRITICAL" "Dangerous file capabilities found!"
        fi
    fi
    
    echo ""
    print_subsection "Writable /etc/passwd or /etc/shadow"
    if check_writable /etc/passwd; then
        log_finding "CRITICAL" "/etc/passwd is writable - can add root user!"
    fi
    if check_writable /etc/shadow; then
        log_finding "CRITICAL" "/etc/shadow is writable!"
    fi
    
    echo ""
    print_subsection "SSH Keys"
    echo "Searching for SSH private keys..."
    find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null | head -20
    
     echo ""
    print_subsection "Writable SSH Configuration"
    if check_writable /root/.ssh/authorized_keys 2>/dev/null; then
        log_finding "CRITICAL" "Root's authorized_keys is writable!"
    fi
    
    echo ""
    print_subsection "NFS Exports"
    if [[ -f /etc/exports ]]; then
        cat /etc/exports
        if grep -q "no_root_squash" /etc/exports 2>/dev/null; then
            log_finding "CRITICAL" "NFS export with no_root_squash found!"
        fi
    fi
}

################################################################################
# 5. PROCESSES & SERVICES
################################################################################

enum_processes() {
    print_section "5. PROCESSES & SERVICES"
    
    print_subsection "Processes Running as Root"
    ps aux | grep "^root" | head -30
    
    echo ""
    print_subsection "Interesting Processes"
    ps aux | grep -iE "mysql|postgres|apache|nginx|redis|mongodb" | grep -v grep
    
    echo ""
    print_subsection "Process Binary Paths"
    echo "Checking for writable process binaries..."
    ps aux --no-headers 2>/dev/null | awk '{print $11}' | sort -u | while read -r proc; do
        if [[ -f "$proc" ]] && check_writable "$proc"; then
            log_finding "CRITICAL" "Process binary is writable: $proc"
        fi
    done
    
    echo ""
    print_subsection "Systemd Services"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-units --type=service --state=running | head -30
    fi
    
    echo ""
    print_subsection "Writable Service Files"
    find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -type f -writable 2>/dev/null | while read -r file; do
        log_finding "CRITICAL" "Writable systemd service: $file"
    done
}

################################################################################
# 6. CRON & SCHEDULED TASKS
################################################################################

enum_cron() {
    print_section "6. CRON & SCHEDULED TASKS"
    
    print_subsection "System Crontab"
    cat /etc/crontab 2>/dev/null
    
    echo ""
    print_subsection "User Crontabs"
    crontab -l 2>/dev/null || echo "No user crontab"
    
    echo ""
    print_subsection "Cron Directories"
    for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly; do
        if [[ -d "$dir" ]]; then
            echo "$dir:"
            ls -la "$dir" 2>/dev/null
            if check_writable "$dir"; then
                log_finding "CRITICAL" "Cron directory is writable: $dir"
            fi
        fi
    done
    
    echo ""
    print_subsection "Writable Cron Scripts"
    find /etc/cron* -type f -writable 2>/dev/null | while read -r file; do
        log_finding "CRITICAL" "Writable cron script: $file"
        echo "  $file"
    done
    
    echo ""
    print_subsection "Cron Scripts with Weak Permissions"
    find /etc/cron* -type f -perm -0002 2>/dev/null | while read -r file; do
        log_finding "HIGH-RISK" "World-writable cron script: $file"
    done
    
    echo ""
    print_subsection "Systemd Timers"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-timers --all 2>/dev/null | head -20
    fi
}

################################################################################
# 7. ENVIRONMENT & PATH
################################################################################

enum_environment() {
    print_section "7. ENVIRONMENT & PATH"
    
    print_subsection "Current PATH"
    echo "$PATH" | tr ':' '\n'
    
    echo ""
    print_subsection "Writable PATH Directories"
    IFS=':' read -ra PATH_DIRS <<< "$PATH"
    for dir in "${PATH_DIRS[@]}"; do
        if [[ -d "$dir" ]] && check_writable "$dir"; then
            log_finding "CRITICAL" "PATH directory is writable: $dir (PATH hijacking possible!)"
        fi
    done
    
    echo ""
    print_subsection "Relative Paths in PATH"
    if echo "$PATH" | grep -q "^\.:\."; then
        log_finding "HIGH-RISK" "Current directory (.) in PATH!"
    fi
    
    echo ""
    print_subsection "Environment Variables"
    env | sort
    
    echo ""
    print_subsection "Dangerous Environment Variables"
    if env | grep -qE "LD_PRELOAD|LD_LIBRARY_PATH"; then
        log_finding "HIGH-RISK" "LD_PRELOAD or LD_LIBRARY_PATH is set!"
        env | grep -E "LD_PRELOAD|LD_LIBRARY_PATH"
    fi
}

################################################################################
# 8. NETWORKING
################################################################################

enum_networking() {
    print_section "8. NETWORKING"
    
    print_subsection "Network Interfaces"
    if command -v ip >/dev/null 2>&1; then
        ip addr
    else
        ifconfig
    fi
    
    echo ""
    print_subsection "Routing Table"
    if command -v ip >/dev/null 2>&1; then
        ip route
    else
        route -n
    fi
    
    echo ""
    print_subsection "Listening Services"
    if command -v ss >/dev/null 2>&1; then
        ss -tulpn 2>/dev/null
    else
        netstat -tulpn 2>/dev/null
    fi
    
    echo ""
    print_subsection "Active Connections"
    if command -v ss >/dev/null 2>&1; then
        ss -tunp 2>/dev/null | head -30
    else
        netstat -tun 2>/dev/null | head -30
    fi
    
    echo ""
    print_subsection "Firewall Rules"
    if command -v iptables >/dev/null 2>&1; then
        iptables -L -n 2>/dev/null || echo "Cannot read iptables (need root)"
    fi
    
    echo ""
    print_subsection "DNS Configuration"
    cat /etc/resolv.conf 2>/dev/null
}

################################################################################
# 9. DOCKER & CONTAINERS
################################################################################

enum_containers() {
    print_section "9. DOCKER & CONTAINERS"
    
    print_subsection "Docker Installation"
    if command -v docker >/dev/null 2>&1; then
        docker --version
        log_finding "INFO" "Docker is installed"
        
        # Check if user can run docker commands
        if docker ps 2>/dev/null; then
            log_finding "CRITICAL" "User can run docker commands - instant root possible!"
        fi
        
        # Check docker socket permissions
        if [[ -S /var/run/docker.sock ]]; then
            ls -la /var/run/docker.sock
            if check_writable /var/run/docker.sock; then
                log_finding "CRITICAL" "Docker socket is writable - can escape to root!"
            fi
        fi
    fi
    
    echo ""
    print_subsection "LXC/LXD"
    if command -v lxc >/dev/null 2>&1; then
        lxc --version
        log_finding "INFO" "LXC is installed"
        
        if groups | grep -qw lxd; then
            log_finding "CRITICAL" "User is in lxd group - privilege escalation possible!"
        fi
    fi
    
    echo ""
    print_subsection "Container Escape Detection"
    if [[ -f /.dockerenv ]]; then
        log_finding "HIGH-RISK" "Running inside a Docker container!"
    fi
    
    if grep -qa docker /proc/1/cgroup 2>/dev/null; then
        log_finding "HIGH-RISK" "Running inside a container!"
    fi
}

################################################################################
# 10. INSTALLED SOFTWARE & EXPLOITS
################################################################################

enum_software() {
    print_section "10. INSTALLED SOFTWARE & EXPLOITS"
    
    print_subsection "Compiler Tools"
    for compiler in gcc cc g++ clang make; do
        if command -v "$compiler" >/dev/null 2>&1; then
            echo "$compiler: $($compiler --version 2>&1 | head -1)"
            log_finding "INFO" "Compiler available: $compiler"
        fi
    done
    
    echo ""
    print_subsection "Development Tools"
    for tool in python python3 perl ruby php node npm git; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "$tool: $(command -v $tool)"
        fi
    done
    
    echo ""
    print_subsection "Password Tools"
    for tool in john hashcat hydra; do
        if command -v "$tool" >/dev/null 2>&1; then
            log_finding "INFO" "Password cracking tool found: $tool"
        fi
    done
    
    echo ""
    print_subsection "Network Tools"
    for tool in nmap nc netcat socat tcpdump wireshark; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "$tool: $(command -v $tool)"
        fi
    done
}

################################################################################
# 11. KERNEL EXPLOITS
################################################################################

enum_kernel_exploits() {
    print_section "11. KERNEL EXPLOITS"
    
    kernel=$(uname -r)
    print_subsection "Kernel Version Check"
    echo "Kernel: $kernel"
    
    echo ""
    print_subsection "Known Vulnerable Kernels"
    
    # DirtyCow
    if [[ "$kernel" < "4.8.3" ]]; then
        log_finding "CRITICAL" "Kernel vulnerable to DirtyCow (CVE-2016-5195)"
    fi
    
    # Dirty Pipe
    if [[ "$kernel" > "5.8" ]] && [[ "$kernel" < "5.16.11" ]]; then
        log_finding "CRITICAL" "Kernel may be vulnerable to Dirty Pipe (CVE-2022-0847)"
    fi
    
    # PwnKit
    log_finding "POTENTIAL" "Check for CVE-2021-4034 (PwnKit) - affects most Linux systems"
    
    echo ""
    print_subsection "Loaded Kernel Modules"
    lsmod | head -30
}

################################################################################
# 12. SENSITIVE FILES
################################################################################

enum_sensitive_files() {
    print_section "12. SENSITIVE FILES & CREDENTIALS"
    
    print_subsection "Configuration Files with Passwords"
    echo "Searching for passwords in config files..."
    find /etc /home -type f \( -name "*.conf" -o -name "*.config" -o -name "*.cfg" \) -exec grep -l -i "password" {} \; 2>/dev/null | head -20
    
    echo ""
    print_subsection "Database Configuration Files"
    find / -type f \( -name "*.php" -o -name "*.inc" -o -name "config.py" \) 2>/dev/null | xargs grep -l -i "password\|mysql\|postgres" 2>/dev/null | head -20
    
    echo ""
    print_subsection "Bash History Files"
    find /home -name ".bash_history" -o -name ".zsh_history" 2>/dev/null | while read -r file; do
        if check_readable "$file"; then
            echo "Readable history: $file"
            grep -i "password\|passwd\|mysql\|ssh" "$file" 2>/dev/null | head -5
        fi
    done
    
    echo ""
    print_subsection "Backup Files"
    find / -name "*.bak" -o -name "*.backup" -o -name "*~" -o -name "*.old" 2>/dev/null | head -30
}

################################################################################
# SUMMARY
################################################################################

print_summary() {
    print_section "SUMMARY OF FINDINGS"
    
    echo -e "${RED}${BOLD}CRITICAL FINDINGS: ${#FINDINGS_CRITICAL[@]}${NC}"
    for finding in "${FINDINGS_CRITICAL[@]}"; do
        echo -e "  ${RED}●${NC} $finding"
    done
    
    echo ""
    echo -e "${RED}HIGH-RISK FINDINGS: ${#FINDINGS_HIGH_RISK[@]}${NC}"
    for finding in "${FINDINGS_HIGH_RISK[@]}"; do
        echo -e "  ${YELLOW}●${NC} $finding"
    done
    
    echo ""
    echo -e "${YELLOW}POTENTIAL FINDINGS: ${#FINDINGS_POTENTIAL[@]}${NC}"
    for finding in "${FINDINGS_POTENTIAL[@]}"; do
        echo -e "  ${YELLOW}●${NC} $finding"
    done
    
    echo ""
    echo -e "${BLUE}INFO: ${#FINDINGS_INFO[@]} informational findings${NC}"
}

################################################################################
# MAIN EXECUTION
################################################################################

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_FILE="$2"
            SAVE_TO_FILE=true
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [-o output_file]"
            echo "  -o, --output FILE    Save output to specified file"
            echo "  -h, --help          Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Main execution
main() {
    print_banner
    echo -e "${CYAN}Starting enumeration at: $(date)${NC}"
    echo -e "${CYAN}Running as: $(whoami) (UID: $(id -u))${NC}\n"
    
    if [[ "$SAVE_TO_FILE" == true ]]; then
        echo -e "${GREEN}Output will be saved to: $OUTPUT_FILE${NC}\n"
    fi
    
    enum_system_info
    enum_user_privileges
    enum_sudo
    enum_file_permissions
    enum_processes
    enum_cron
    enum_environment
    enum_networking
    enum_containers
    enum_software
    enum_kernel_exploits
    enum_sensitive_files
    print_summary
    
    echo ""
    echo -e "${CYAN}Enumeration completed at: $(date)${NC}"
    
    if [[ "$SAVE_TO_FILE" == true ]]; then
        echo -e "${GREEN}Results saved to: $OUTPUT_FILE${NC}"
    fi
}

# Run main and optionally save to file
if [[ "$SAVE_TO_FILE" == true ]]; then
    main 2>&1 | tee "$OUTPUT_FILE"
else
    main
fi
