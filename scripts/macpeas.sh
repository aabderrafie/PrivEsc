#!/bin/bash
################################################################################
# macOS Privilege Escalation Enumeration Script (Advanced)
# Author: Security Research Team
# Purpose: Comprehensive local enumeration for privilege escalation vectors
# Target: macOS (Intel & Apple Silicon)
# Usage: ./macpeas_advanced.sh [-o output_file]
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

# Default output file with timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="/tmp/macos_privesc_enum_${TIMESTAMP}.txt"
SAVE_TO_FILE=true

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
║               macOS Privilege Escalation Enumeration Script              ║
║                                                                           ║
║         Comprehensive Local Security Assessment & Vector Discovery        ║
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
    if [[ -w "$path" ]]; then
        return 0
    else
        return 1
    fi
}

check_exists() {
    local path="$1"
    if [[ -e "$path" ]]; then
        return 0
    else
        return 1
    fi
}

################################################################################
# 1. SYSTEM INFORMATION
################################################################################

enum_system_info() {
    print_section "1. SYSTEM INFORMATION"
    
    print_subsection "Operating System Details"
    sw_vers 2>/dev/null
    log_finding "INFO" "System version enumerated"
    
    echo ""
    print_subsection "Kernel Information"
    uname -a
    log_finding "INFO" "Kernel: $(uname -r)"
    
    echo ""
    print_subsection "Architecture"
    arch=$(uname -m)
    echo "Architecture: $arch"
    if [[ "$arch" == "arm64" ]]; then
        log_finding "INFO" "Running on Apple Silicon (ARM64)"
    else
        log_finding "INFO" "Running on Intel (x86_64)"
    fi
    
    echo ""
    print_subsection "System Integrity Protection (SIP) Status"
    sip_status=$(csrutil status 2>/dev/null)
    echo "$sip_status"
    if echo "$sip_status" | grep -qi "disabled"; then
        log_finding "HIGH-RISK" "SIP is DISABLED - System files are writable!"
    elif echo "$sip_status" | grep -qi "enabled"; then
        log_finding "INFO" "SIP is enabled"
    else
        log_finding "POTENTIAL" "Could not determine SIP status (might require root)"
    fi
    
    echo ""
    print_subsection "Secure Boot Status"
    if command -v nvram >/dev/null 2>&1; then
        secure_boot=$(nvram 94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy 2>/dev/null)
        if [[ -n "$secure_boot" ]]; then
            echo "$secure_boot"
            log_finding "INFO" "Secure Boot information retrieved"
        else
            echo "Secure Boot status not available (may require root or not applicable)"
        fi
    fi
    
    echo ""
    print_subsection "Gatekeeper Status"
    gatekeeper=$(spctl --status 2>/dev/null)
    echo "Gatekeeper: $gatekeeper"
    if echo "$gatekeeper" | grep -qi "disabled"; then
        log_finding "POTENTIAL" "Gatekeeper is disabled - unsigned apps can run"
    else
        log_finding "INFO" "Gatekeeper is enabled"
    fi
    
    echo ""
    print_subsection "FileVault Status"
    filevault=$(fdesetup status 2>/dev/null)
    echo "$filevault"
    if echo "$filevault" | grep -qi "off"; then
        log_finding "INFO" "FileVault is OFF (disk not encrypted)"
    else
        log_finding "INFO" "FileVault status: $filevault"
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
    print_subsection "Group Memberships"
    groups=$(id -Gn)
    echo "$groups"
    if echo "$groups" | grep -qw "admin"; then
        log_finding "POTENTIAL" "User is member of 'admin' group - can use sudo"
    fi
    if echo "$groups" | grep -qw "wheel"; then
        log_finding "POTENTIAL" "User is member of 'wheel' group"
    fi
    
    echo ""
    print_subsection "Users with UID 0"
    awk -F: '$3 == 0 {print $1}' /etc/passwd
    uid0_count=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | wc -l)
    if [[ $uid0_count -gt 1 ]]; then
        log_finding "HIGH-RISK" "Multiple users with UID 0 detected!"
    fi
    
    echo ""
    print_subsection "Admin Users"
    dscl . -read /Groups/admin GroupMembership 2>/dev/null
    
    echo ""
    print_subsection "All Local Users"
    dscl . list /Users | grep -v "^_"
    
    echo ""
    print_subsection "Recently Modified User Accounts"
    echo "Users modified in last 30 days:"
    find /var/db/dslocal/nodes/Default/users -type f -mtime -30 -exec basename {} .plist \; 2>/dev/null | grep -v "^_"
    
    echo ""
    print_subsection "User Login Items (Current User)"
    login_items=$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null)
    if [[ -n "$login_items" ]]; then
        echo "$login_items"
        log_finding "INFO" "Login items found for current user"
    else
        echo "No login items or permission denied"
    fi
    
    echo ""
    print_subsection "Home Directory Permissions"
    ls -la ~ | head -20
    if check_writable "/Users"; then
        log_finding "HIGH-RISK" "/Users directory is writable!"
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
    if echo "$sudo_version" | grep -qE "1\.(8\.[0-9]|8\.1[0-9]|8\.2[0-7])"; then
        log_finding "HIGH-RISK" "Potentially vulnerable sudo version (CVE-2021-3156 - Baron Samedit)"
    fi
    
    echo ""
    print_subsection "Sudo Privileges (sudo -l)"
    if sudo -n -l 2>/dev/null; then
        log_finding "POTENTIAL" "Can run sudo -l without password!"
        
        # Check for NOPASSWD entries
        if sudo -n -l 2>/dev/null | grep -i "NOPASSWD"; then
            log_finding "HIGH-RISK" "NOPASSWD sudo rules found!"
        fi
    else
        echo "Cannot run sudo -l without password (or user has no sudo rights)"
    fi
    
    echo ""
    print_subsection "Sudoers File Permissions"
    ls -la /etc/sudoers 2>/dev/null
    if check_writable "/etc/sudoers"; then
        log_finding "HIGH-RISK" "/etc/sudoers is writable!"
    fi
    
    echo ""
    print_subsection "Sudoers.d Directory"
    if [[ -d /etc/sudoers.d ]]; then
        ls -la /etc/sudoers.d/ 2>/dev/null
        
        # Check for writable files
        find /etc/sudoers.d/ -type f -writable 2>/dev/null | while read -r file; do
            log_finding "HIGH-RISK" "Writable sudoers file: $file"
        done
    else
        echo "/etc/sudoers.d does not exist"
    fi
    
    echo ""
    print_subsection "Cached Sudo Credentials"
    if sudo -n true 2>/dev/null; then
        log_finding "HIGH-RISK" "Sudo credentials are cached - can run sudo without password!"
    else
        echo "No cached sudo credentials"
    fi
    
    echo ""
    print_subsection "PAM Configuration"
    ls -la /etc/pam.d/ 2>/dev/null | head -20
    
    echo ""
    print_subsection "Password Policy"
    pwpolicy -getaccountpolicies 2>/dev/null || echo "Cannot read password policy"
}

################################################################################
# 4. FILE PERMISSIONS & MISCONFIGURATIONS
################################################################################

enum_file_permissions() {
    print_section "4. FILE PERMISSIONS & MISCONFIGURATIONS"
    
    print_subsection "World-Writable Directories in System Locations"
    echo "Searching for world-writable directories (this may take a moment)..."
    find /Applications /Library /System/Library -type d -perm -0002 2>/dev/null | head -20
    
    world_writable_count=$(find /Applications /Library -type d -perm -0002 2>/dev/null | wc -l)
    if [[ $world_writable_count -gt 0 ]]; then
        log_finding "POTENTIAL" "Found $world_writable_count world-writable directories in system locations"
    fi
    
    echo ""
    print_subsection "World-Writable Files in System Locations"
    find /Applications /Library -type f -perm -0002 2>/dev/null | head -20
    
    echo ""
    print_subsection "SUID Binaries"
    echo "SUID binaries (potentially interesting):"
    find / -type f -perm -4000 -ls 2>/dev/null | grep -v -E "(System/Library|usr/libexec)" | head -20
    
    echo ""
    print_subsection "SGID Binaries"
    echo "SGID binaries (potentially interesting):"
    find / -type f -perm -2000 -ls 2>/dev/null | grep -v -E "(System/Library|usr/libexec)" | head -20
    
    echo ""
    print_subsection "Writable Files in /Applications"
    find /Applications -type f -writable 2>/dev/null | head -30
    writable_apps=$(find /Applications -type f -writable 2>/dev/null | wc -l)
    if [[ $writable_apps -gt 0 ]]; then
        log_finding "POTENTIAL" "Found $writable_apps writable files in /Applications"
    fi
    
    echo ""
    print_subsection "Interesting File Capabilities"
    # macOS doesn't use Linux capabilities, but check for extended attributes
    echo "Files with extended attributes in /usr/local/bin:"
    find /usr/local/bin -type f -exec ls -l@ {} \; 2>/dev/null | grep "com.apple" | head -20
    
    echo ""
    print_subsection "Sensitive Files Readable by Current User"
    sensitive_files=(
        "/etc/master.passwd"
        "/var/db/shadow/hash"
        "/Library/Preferences/com.apple.loginwindow.plist"
        "/Library/Preferences/SystemConfiguration/preferences.plist"
    )
    
    for file in "${sensitive_files[@]}"; do
        if [[ -r "$file" ]]; then
            log_finding "HIGH-RISK" "Can read sensitive file: $file"
            ls -la "$file"
        fi
    done
}

################################################################################
# 5. LAUNCH SERVICES & PERSISTENCE
################################################################################

enum_launch_services() {
    print_section "5. LAUNCH SERVICES & PERSISTENCE"
    
    print_subsection "LaunchDaemons (System-wide - runs as root)"
    echo "System LaunchDaemons:"
    ls -la /Library/LaunchDaemons/ 2>/dev/null | head -20
    
    echo ""
    echo "Writable LaunchDaemons:"
    find /Library/LaunchDaemons/ -type f -writable 2>/dev/null | while read -r file; do
        log_finding "HIGH-RISK" "Writable LaunchDaemon: $file"
        echo "  $file"
    done
    
    echo ""
    print_subsection "LaunchAgents (User context)"
    echo "System LaunchAgents:"
    ls -la /Library/LaunchAgents/ 2>/dev/null | head -20
    
    echo ""
    echo "User LaunchAgents:"
    ls -la ~/Library/LaunchAgents/ 2>/dev/null | head -20
    
    echo ""
    echo "Writable LaunchAgents:"
    for dir in /Library/LaunchAgents ~/Library/LaunchAgents; do
        find "$dir" -type f -writable 2>/dev/null | while read -r file; do
            log_finding "POTENTIAL" "Writable LaunchAgent: $file"
            echo "  $file"
        done
    done
    
    echo ""
    print_subsection "Writable Launch* Parent Directories"
    launch_dirs=("/Library/LaunchDaemons" "/Library/LaunchAgents" "/System/Library/LaunchDaemons" "/System/Library/LaunchAgents")
    for dir in "${launch_dirs[@]}"; do
        if check_writable "$dir"; then
            log_finding "HIGH-RISK" "Launch directory is writable: $dir"
        fi
    done
    
    echo ""
    print_subsection "StartupItems (Legacy)"
    if [[ -d /Library/StartupItems ]]; then
        ls -la /Library/StartupItems/ 2>/dev/null
        if check_writable "/Library/StartupItems"; then
            log_finding "POTENTIAL" "/Library/StartupItems is writable"
        fi
    else
        echo "/Library/StartupItems does not exist"
    fi
    
    echo ""
    print_subsection "Suspicious LaunchDaemons/Agents"
    echo "Checking for unsigned or suspicious plists..."
    for dir in /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents; do
        find "$dir" -name "*.plist" 2>/dev/null | while read -r plist; do
            # Check for root-owned but world-writable
            if [[ -O "$plist" ]] && [[ $(stat -f "%A" "$plist") =~ [0-9][0-9]2 ]]; then
                log_finding "POTENTIAL" "Suspicious permissions on: $plist"
            fi
            
            # Check for RunAtLoad + root in Daemons
            if [[ "$dir" == "/Library/LaunchDaemons" ]]; then
                if grep -q "RunAtLoad" "$plist" 2>/dev/null; then
                    program=$(plutil -p "$plist" 2>/dev/null | grep "Program" | head -1)
                    if [[ -n "$program" ]]; then
                        log_finding "INFO" "RunAtLoad daemon: $plist -> $program"
                    fi
                fi
            fi
        done
    done
}

################################################################################
# 6. ENVIRONMENT & PATH
################################################################################

enum_environment() {
    print_section "6. ENVIRONMENT & PATH"
    
    print_subsection "Current PATH"
    echo "$PATH" | tr ':' '\n'
    
    echo ""
    print_subsection "Writable Directories in PATH"
    IFS=':' read -ra PATH_DIRS <<< "$PATH"
    for dir in "${PATH_DIRS[@]}"; do
        if [[ -d "$dir" ]] && check_writable "$dir"; then
            log_finding "HIGH-RISK" "PATH directory is writable: $dir (PATH hijacking possible!)"
        fi
    done
    
    echo ""
    print_subsection "PATH Hijacking Opportunities"
    echo "Checking for missing binaries that could be hijacked..."
    
    # Common binaries that might be called without full path
    common_bins=("curl" "wget" "git" "python" "perl" "ruby" "node" "ssh")
    
    for bin in "${common_bins[@]}"; do
        if ! command -v "$bin" >/dev/null 2>&1; then
            # Binary not found - check if we can create it in PATH
            for dir in "${PATH_DIRS[@]}"; do
                if [[ -d "$dir" ]] && check_writable "$dir"; then
                    log_finding "POTENTIAL" "Could create fake '$bin' in writable PATH dir: $dir"
                    break
                fi
            done
        fi
    done
    
    echo ""
    print_subsection "Environment Variables"
    env | sort
    
    echo ""
    print_subsection "Suspicious Environment Variables"
    # Check for suspicious DYLD variables
    if env | grep -i "DYLD_"; then
        log_finding "POTENTIAL" "DYLD environment variables found - might allow library injection"
    fi
    
    if env | grep -i "LD_PRELOAD"; then
        log_finding "HIGH-RISK" "LD_PRELOAD is set!"
    fi
    
    echo ""
    print_subsection "Shell Configuration Files"
    config_files=(
        "~/.bashrc"
        "~/.bash_profile"
        "~/.zshrc"
        "~/.zprofile"
        "/etc/zshrc"
        "/etc/bashrc"
    )
    
    for file in "${config_files[@]}"; do
        expanded_file=$(eval echo "$file")
        if [[ -f "$expanded_file" ]]; then
            echo "$expanded_file:"
            ls -la "$expanded_file"
            if check_writable "$expanded_file"; then
                log_finding "POTENTIAL" "Writable shell config: $expanded_file"
            fi
        fi
    done
}

################################################################################
# 7. INSTALLED SOFTWARE & CVEs
################################################################################

enum_software() {
    print_section "7. INSTALLED SOFTWARE & CVEs"
    
    print_subsection "Installed Applications"
    echo "Applications in /Applications:"
    ls -la /Applications/ 2>/dev/null | grep "\.app$" | head -30
    
    echo ""
    print_subsection "Homebrew Installation"
    if command -v brew >/dev/null 2>&1; then
        echo "Homebrew is installed"
        brew --version
        log_finding "INFO" "Homebrew detected: $(brew --version | head -1)"
        
        echo ""
        echo "Homebrew packages:"
        brew list --versions 2>/dev/null | head -30
        
        echo ""
        echo "Outdated packages:"
        outdated=$(brew outdated 2>/dev/null)
        if [[ -n "$outdated" ]]; then
            echo "$outdated"
            log_finding "POTENTIAL" "Outdated Homebrew packages found"
        else
            echo "All packages up to date"
        fi
        
        # Check Homebrew permissions
        if [[ -d /usr/local/Homebrew ]] && check_writable "/usr/local/Homebrew"; then
            log_finding "HIGH-RISK" "Homebrew directory is writable!"
        fi
    else
        echo "Homebrew not installed"
    fi
    
    echo ""
    print_subsection "Python Installations"
    which -a python python2 python3 2>/dev/null
    python3 --version 2>/dev/null
    
    echo ""
    print_subsection "Development Tools"
    for tool in gcc clang git make xcode-select; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "$tool: $(command -v "$tool")"
        fi
    done
    
    echo ""
    print_subsection "Virtualization Software"
    vmware_apps=$(ls /Applications/ 2>/dev/null | grep -i -E "(vmware|parallels|virtualbox)")
    if [[ -n "$vmware_apps" ]]; then
        echo "$vmware_apps"
        log_finding "INFO" "Virtualization software detected"
    else
        echo "No common virtualization software found"
    fi
    
    echo ""
    print_subsection "Security Tools"
    security_tools=("nmap" "metasploit" "burp" "wireshark")
    for tool in "${security_tools[@]}"; do
        if mdfind "kMDItemFSName == '*${tool}*'" 2>/dev/null | head -1; then
            log_finding "INFO" "Security tool found: $tool"
        fi
    done
    
    echo ""
    print_subsection "Known Vulnerable Software"
    echo "Checking for known vulnerable versions..."
    
    # Check sudo version for CVE-2021-3156
    sudo_ver=$(sudo -V 2>/dev/null | head -1 | grep -oE "[0-9]+\.[0-9]+\.[0-9]+")
    if [[ -n "$sudo_ver" ]]; then
        echo "Sudo version: $sudo_ver"
        # Baron Samedit vulnerability
        if [[ "$sudo_ver" < "1.8.28" ]] || [[ "$sudo_ver" > "1.8.0" && "$sudo_ver" < "1.9.5p2" ]]; then
            log_finding "HIGH-RISK" "Sudo version vulnerable to CVE-2021-3156 (Baron Samedit)"
        fi
    fi
}

################################################################################
# 8. KERNEL EXTENSIONS & SYSTEM EXTENSIONS
################################################################################

enum_kernel_extensions() {
    print_section "8. KERNEL EXTENSIONS & SYSTEM EXTENSIONS"
    
    print_subsection "Loaded Kernel Extensions"
    kextstat | head -30
    
    echo ""
    print_subsection "Third-Party Kernel Extensions"
    kextstat | grep -v "com.apple" | head -20
    third_party_kexts=$(kextstat | grep -v "com.apple" | wc -l)
    if [[ $third_party_kexts -gt 1 ]]; then
        log_finding "INFO" "Found $third_party_kexts third-party kernel extensions"
    fi
    
    echo ""
    print_subsection "Kernel Extension Directories"
    ls -la /Library/Extensions/ 2>/dev/null | head -20
    ls -la /System/Library/Extensions/ 2>/dev/null | head -10
    
    if check_writable "/Library/Extensions"; then
        log_finding "HIGH-RISK" "/Library/Extensions is writable!"
    fi
    
    echo ""
    print_subsection "System Extensions (Modern Approach)"
    systemextensionsctl list 2>/dev/null || echo "Cannot list system extensions (may require root)"
    
    echo ""
    print_subsection "Network Extension Configuration"
    if [[ -d "/Library/Preferences/com.apple.networkextension.plist" ]]; then
        plutil -p /Library/Preferences/com.apple.networkextension.plist 2>/dev/null || echo "Cannot read network extension config"
    fi
}

################################################################################
# 9. CRON / SCHEDULED TASKS
################################################################################

enum_scheduled_tasks() {
    print_section "9. CRON / SCHEDULED TASKS"
    
    print_subsection "System Crontab"
    cat /etc/crontab 2>/dev/null || echo "No system crontab"
    
    echo ""
    print_subsection "User Crontabs"
    crontab -l 2>/dev/null || echo "No user crontab for current user"
    
    echo ""
    print_subsection "Cron Directory Contents"
    for dir in /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly; do
        if [[ -d "$dir" ]]; then
            echo "$dir:"
            ls -la "$dir" 2>/dev/null
            
            if check_writable "$dir"; then
                log_finding "HIGH-RISK" "Cron directory is writable: $dir"
            fi
            echo ""
        fi
    done
    
    echo ""
    print_subsection "Periodic Scripts"
    ls -la /usr/lib/cron/tabs/ 2>/dev/null
    
    echo ""
    print_subsection "At Jobs"
    atq 2>/dev/null || echo "No at jobs or at is disabled"
    
    echo ""
    print_subsection "Writable Cron Scripts"
    find /etc/periodic /usr/lib/cron -type f -writable 2>/dev/null | while read -r file; do
        log_finding "HIGH-RISK" "Writable cron/periodic script: $file"
        echo "  $file"
    done
}

################################################################################
# 10. SECURITY CONTROLS (Extended)
################################################################################

enum_security_controls() {
    print_section "10. SECURITY CONTROLS"
    
    print_subsection "XProtect (Anti-Malware)"
    if [[ -d "/Library/Apple/System/Library/CoreServices/XProtect.bundle" ]]; then
        echo "XProtect is installed"
        ls -la /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/ 2>/dev/null | head -10
        log_finding "INFO" "XProtect anti-malware is present"
    fi
    
    echo ""
    print_subsection "MRT (Malware Removal Tool)"
    if [[ -f "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/MacOS/MRT" ]]; then
        echo "MRT is installed"
        log_finding "INFO" "Malware Removal Tool is present"
    fi
    
    echo ""
    print_subsection "TCC Database (Transparency, Consent, and Control)"
    tcc_db="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
    if [[ -r "$tcc_db" ]]; then
        log_finding "POTENTIAL" "User TCC database is readable"
        echo "TCC database location: $tcc_db"
        
        # Try to read it with sqlite3
        if command -v sqlite3 >/dev/null 2>&1; then
            echo "TCC Permissions:"
            sqlite3 "$tcc_db" "SELECT service, client, allowed FROM access LIMIT 10;" 2>/dev/null || echo "Cannot query TCC database"
        fi
    fi
    
    # System TCC database
    sys_tcc_db="/Library/Application Support/com.apple.TCC/TCC.db"
    if [[ -r "$sys_tcc_db" ]]; then
        log_finding "HIGH-RISK" "System TCC database is readable!"
    fi
    
    echo ""
    print_subsection "Firewall Status"
    firewall=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null)
    if [[ "$firewall" == "0" ]]; then
        log_finding "POTENTIAL" "Firewall is disabled"
    else
        log_finding "INFO" "Firewall state: $firewall (1=on for specific services, 2=on for all)"
    fi
    
    echo ""
    print_subsection "Remote Access Services"
    if systemsetup -getremotelogin 2>/dev/null | grep -q "On"; then
        log_finding "POTENTIAL" "Remote Login (SSH) is enabled"
    fi
    
    if systemsetup -getremoteappleevents 2>/dev/null | grep -q "On"; then
        log_finding "POTENTIAL" "Remote Apple Events enabled"
    fi
    
    echo ""
    print_subsection "Screen Sharing"
    if /usr/bin/launchctl list 2>/dev/null | grep -q "com.apple.screensharing"; then
        log_finding "POTENTIAL" "Screen Sharing is enabled"
    fi
    
    echo ""
    print_subsection "Automatic Login"
    if defaults read /Library/Preferences/com.apple.loginwindow 2>/dev/null | grep -q "autoLoginUser"; then
        log_finding "HIGH-RISK" "Automatic login is configured!"
        defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null
    fi
}

################################################################################
# 11. NETWORKING
################################################################################

enum_networking() {
    print_section "11. NETWORKING"
    
    print_subsection "Network Interfaces"
    ifconfig | grep -E "^[a-z]|inet "
    
    echo ""
    print_subsection "Listening Services"
    echo "Services listening on network ports:"
    lsof -i -P -n | grep LISTEN | head -30
    
    echo ""
    print_subsection "Services Running as Root"
    echo "Root-owned listening services:"
    sudo -n lsof -i -P -n 2>/dev/null | grep -E "^COMMAND|root" | grep LISTEN | head -20 || \
        lsof -i -P -n | grep LISTEN | while read -r line; do
            if echo "$line" | grep -q "root"; then
                log_finding "POTENTIAL" "Root service listening: $line"
                echo "$line"
            fi
        done
    
    echo ""
    print_subsection "Established Connections"
    lsof -i -P -n | grep ESTABLISHED | head -20
    
    echo ""
    print_subsection "Network Configuration Files"
    echo "/etc/hosts:"
    cat /etc/hosts 2>/dev/null
    
    if check_writable "/etc/hosts"; then
        log_finding "HIGH-RISK" "/etc/hosts is writable!"
    fi
    
    echo ""
    print_subsection "DNS Configuration"
    cat /etc/resolv.conf 2>/dev/null
    
    echo ""
    print_subsection "Firewall Rules"
    sudo -n pfctl -s rules 2>/dev/null || echo "Cannot read firewall rules (requires root)"
}

################################################################################
# 12. ADDITIONAL CHECKS
################################################################################

enum_additional() {
    print_section "12. ADDITIONAL CHECKS"
    
    print_subsection "Clipboard Contents"
    clipboard=$(pbpaste 2>/dev/null)
    if [[ -n "$clipboard" ]]; then
        echo "Clipboard contains data (first 200 chars):"
        echo "$clipboard" | head -c 200
        echo "..."
        log_finding "INFO" "Clipboard contains data - might contain sensitive info"
    else
        echo "Clipboard is empty"
    fi
    
    echo ""
    print_subsection "SSH Configuration"
    if [[ -f ~/.ssh/config ]]; then
        echo "SSH config exists: ~/.ssh/config"
        ls -la ~/.ssh/config
        if check_writable ~/.ssh/config; then
            log_finding "POTENTIAL" "SSH config is writable"
        fi
    fi
    
    echo ""
    print_subsection "SSH Keys"
    if [[ -d ~/.ssh ]]; then
        ls -la ~/.ssh/
        
        # Check for private keys
        find ~/.ssh -type f -name "id_*" ! -name "*.pub" 2>/dev/null | while read -r key; do
            log_finding "INFO" "SSH private key found: $key"
        done
        
        # Check authorized_keys
        if [[ -f ~/.ssh/authorized_keys ]]; then
            echo "Authorized SSH keys:"
            cat ~/.ssh/authorized_keys
            if check_writable ~/.ssh/authorized_keys; then
                log_finding "HIGH-RISK" "authorized_keys is writable!"
            fi
        fi
    fi
    
    echo ""
    print_subsection "Browser Extensions & Profiles"
    echo "Chrome extensions:"
    ls -la "$HOME/Library/Application Support/Google/Chrome/Default/Extensions/" 2>/dev/null | head -10 || echo "Chrome not found or no extensions"
    
    echo ""
    echo "Safari extensions:"
    ls -la "$HOME/Library/Safari/Extensions/" 2>/dev/null | head -10 || echo "No Safari extensions"
    
    echo ""
    print_subsection "Recently Opened Files"
    echo "Recent items (may contain sensitive paths):"
    defaults read com.apple.recentitems 2>/dev/null | head -20 || echo "Cannot read recent items"
    
    echo ""
    print_subsection "Keychain Access"
    echo "Keychains:"
    security list-keychains 2>/dev/null
    
    echo ""
    echo "Keychain items accessible without password:"
    security dump-keychain -d 2>/dev/null | head -20 || echo "Cannot dump keychain (requires password)"
    
    echo ""
    print_subsection "File Quarantine"
    echo "Recently quarantined files:"
    find ~/Downloads -name "*" -exec xattr -p com.apple.quarantine {} \; 2>/dev/null | head -10 || echo "No quarantined files or permission denied"
    
    echo ""
    print_subsection "Docker / Containers"
    if command -v docker >/dev/null 2>&1; then
        echo "Docker is installed"
        docker version 2>/dev/null || echo "Docker daemon not running or permission denied"
        
        # Check if user can access docker without sudo
        if docker ps 2>/dev/null; then
            log_finding "HIGH-RISK" "User can access Docker without sudo - container escape possible!"
        fi
    fi
    
    echo ""
    print_subsection "Database Files"
    echo "Looking for database files in user directories..."
    find ~ -type f \( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" \) 2>/dev/null | head -20
    
    echo ""
    print_subsection "Passwords in Files"
    echo "Searching for potential password files (this may take a moment)..."
    grep -r -i -E "(password|passwd|pwd|secret|token|api_key)" ~/.bash_history ~/.zsh_history ~/.config 2>/dev/null | head -10 || echo "No obvious passwords in config files"
    
    echo ""
    print_subsection "NFS Shares"
    showmount -e localhost 2>/dev/null || echo "No NFS shares or showmount not available"
    
    echo ""
    print_subsection "Firmware Password"
    if firmwarepasswd -check 2>/dev/null | grep -q "No"; then
        log_finding "POTENTIAL" "No firmware password set"
    fi
}

################################################################################
# 13. EXPLOIT SUGGESTIONS
################################################################################

suggest_exploits() {
    print_section "13. EXPLOIT SUGGESTIONS & CVE MAPPING"
    
    echo "Analyzing findings for known CVEs and exploit opportunities..."
    echo ""
    
    # Get macOS version
    os_version=$(sw_vers -productVersion)
    os_build=$(sw_vers -buildVersion)
    
    echo "Target: macOS $os_version (Build: $os_build)"
    echo ""
    
    print_subsection "Known macOS Privilege Escalation CVEs"
    
    # CVE database (sample - expand as needed)
    echo "• CVE-2021-30892 (CatalogURL): Affects macOS < 11.6.1 - TCC bypass via CoreGraphics"
    echo "• CVE-2021-30853 (FontParser): Affects macOS < 11.6 - Code execution in FontParser"
    echo "• CVE-2022-26706 (IOMobileFrameBuffer): Affects macOS < 12.4 - Kernel memory corruption"
    echo "• CVE-2023-3156 (Baron Samedit): sudo < 1.9.5p2 - Heap overflow"
    echo "• CVE-2023-32369 (TriangleDB): Affects macOS Monterey - Kernel exploit"
    echo "• CVE-2023-41974 (DYLD): Affects macOS < 13.6 - Environment variable injection"
    echo ""
    
    # Version-specific recommendations
    major_version=$(echo "$os_version" | cut -d. -f1)
    
    case "$major_version" in
        10)
            echo "📍 macOS 10.x detected - Consider checking for legacy vulnerabilities"
            log_finding "POTENTIAL" "Running legacy macOS 10.x - many known CVEs available"
            ;;
        11)
            echo "📍 macOS 11 (Big Sur) - Check for TCC bypass and CoreGraphics vulnerabilities"
            ;;
        12)
            echo "📍 macOS 12 (Monterey) - Check for IOMobileFrameBuffer and kernel exploits"
            ;;
        13)
            echo "📍 macOS 13 (Ventura) - Check for DYLD injection vulnerabilities"
            ;;
        14)
            echo "📍 macOS 14 (Sonoma) - Relatively new, monitor for emerging CVEs"
            ;;
    esac
    
    echo ""
    print_subsection "Recommended Attack Vectors Based on Findings"
    
    # Analyze based on previous findings
    if [[ ${#FINDINGS_HIGH_RISK[@]} -gt 0 ]]; then
        echo -e "${RED}${BOLD}HIGH-RISK VECTORS:${NC}"
        for finding in "${FINDINGS_HIGH_RISK[@]}"; do
            echo "  • $finding"
        done
        echo ""
    fi
    
    if [[ ${#FINDINGS_POTENTIAL[@]} -gt 0 ]]; then
        echo -e "${YELLOW}${BOLD}POTENTIAL VECTORS:${NC}"
        # Show only top 10 to avoid clutter
        for i in "${!FINDINGS_POTENTIAL[@]}"; do
            if [[ $i -lt 10 ]]; then
                echo "  • ${FINDINGS_POTENTIAL[$i]}"
            fi
        done
        if [[ ${#FINDINGS_POTENTIAL[@]} -gt 10 ]]; then
            echo "  ... and $((${#FINDINGS_POTENTIAL[@]} - 10)) more"
        fi
        echo ""
    fi
    
    print_subsection "Exploitation Resources"
    echo "• GitHub: https://github.com/topics/macos-privilege-escalation"
    echo "• GTFOBins (sudo/SUID): https://gtfobins.github.io/"
    echo "• Exploit-DB: https://www.exploit-db.com/"
    echo "• Project Zero: https://googleprojectzero.blogspot.com/"
}

################################################################################
# SUMMARY SECTION
################################################################################

print_summary() {
    print_section "ENUMERATION SUMMARY"
    
    echo -e "${BOLD}Findings Overview:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${RED}[HIGH-RISK]${NC} Findings: ${#FINDINGS_HIGH_RISK[@]}"
    echo -e "${YELLOW}[POTENTIAL]${NC} Findings: ${#FINDINGS_POTENTIAL[@]}"
    echo -e "${BLUE}[INFO]${NC} Findings: ${#FINDINGS_INFO[@]}"
    echo ""
    
    if [[ ${#FINDINGS_HIGH_RISK[@]} -gt 0 ]]; then
        echo -e "${RED}${BOLD}🔴 HIGH-RISK PRIVILEGE ESCALATION VECTORS:${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        for finding in "${FINDINGS_HIGH_RISK[@]}"; do
            echo -e "  ${RED}▪${NC} $finding"
        done
        echo ""
    fi
    
    if [[ ${#FINDINGS_POTENTIAL[@]} -gt 0 ]]; then
        echo -e "${YELLOW}${BOLD}🟡 POTENTIAL VECTORS TO INVESTIGATE:${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        # Show top 15 potential findings
        for i in "${!FINDINGS_POTENTIAL[@]}"; do
            if [[ $i -lt 15 ]]; then
                echo -e "  ${YELLOW}▪${NC} ${FINDINGS_POTENTIAL[$i]}"
            fi
        done
        if [[ ${#FINDINGS_POTENTIAL[@]} -gt 15 ]]; then
            echo -e "  ${YELLOW}▪${NC} ... and $((${#FINDINGS_POTENTIAL[@]} - 15)) more potential findings"
        fi
        echo ""
    fi
    
    echo -e "${BOLD}🎯 RECOMMENDED NEXT STEPS:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "1. Prioritize HIGH-RISK findings for immediate exploitation"
    echo "2. Investigate writable LaunchDaemons/LaunchAgents for persistence"
    echo "3. Check POTENTIAL findings for configuration weaknesses"
    echo "4. Review sudo permissions and NOPASSWD entries"
    echo "5. Look for PATH hijacking opportunities"
    echo "6. Examine outdated software for known CVEs"
    echo "7. Check for TCC database access and privacy bypasses"
    echo ""
    
    echo -e "${BOLD}📁 Full results saved to:${NC} ${GREEN}$OUTPUT_FILE${NC}"
    echo ""
    
    echo -e "${CYAN}${BOLD}Happy Hunting! 🏴‍☠️${NC}"
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

main() {
    # Start output redirection
    exec > >(tee -a "$OUTPUT_FILE")
    exec 2>&1
    
    print_banner
    
    echo -e "${BOLD}Enumeration started at:${NC} $(date)"
    echo -e "${BOLD}Output file:${NC} $OUTPUT_FILE"
    echo -e "${BOLD}Running as:${NC} $(whoami) (UID: $(id -u))"
    echo ""
    
    # Run all enumeration modules
    enum_system_info
    enum_user_privileges
    enum_sudo
    enum_file_permissions
    enum_launch_services
    enum_environment
    enum_software
    enum_kernel_extensions
    enum_scheduled_tasks
    enum_security_controls
    enum_networking
    enum_additional
    suggest_exploits
    
    # Print summary
    print_summary
    
    echo -e "\n${BOLD}Enumeration completed at:${NC} $(date)"
    echo -e "${BOLD}Total runtime:${NC} $SECONDS seconds"
}

# Run main function
main
