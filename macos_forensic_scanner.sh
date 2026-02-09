#!/bin/bash
#=============================================================================
# macOS Forensic Threat Hunter
# Scans for: Nova RAT, defense evasion, persistence, credential access,
#            PowerShell abuse, suspicious processes, network IOCs
# 
# Run as ROOT for full visibility: sudo ./macos_forensic_scanner.sh
#=============================================================================

set -uo pipefail

# Colors
RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
NC='\033[0m'

OUTDIR="./macos_forensic_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

LOGFILE="$OUTDIR/00_scan_log.txt"
FINDINGS=0
CRITICAL=0

# ============================================================
# Helpers
# ============================================================
log()  { echo -e "$1" | tee -a "$LOGFILE"; }
hdr()  { log "\n${BLD}${CYN}$1${NC}"; }
warn() { log "  ${YEL}[!] $1${NC}"; FINDINGS=$((FINDINGS+1)); }
crit() { log "  ${RED}[!!!] $1${NC}"; FINDINGS=$((FINDINGS+1)); CRITICAL=$((CRITICAL+1)); }
ok()   { log "  ${GRN}[✓] $1${NC}"; }
info() { log "  $1"; }

banner() {
    log "${BLD}${CYN}======================================================${NC}"
    log "${BLD}${CYN}  macOS FORENSIC THREAT HUNTER                        ${NC}"
    log "${BLD}${CYN}======================================================${NC}"
    log "  Date:     $(date)"
    log "  Hostname: $(hostname)"
    log "  User:     $(whoami)"
    log "  macOS:    $(sw_vers -productVersion 2>/dev/null || echo 'unknown')"
    log "  Output:   ${OUTDIR}"

    if [ "$(id -u)" -ne 0 ]; then
        log "\n  ${YEL}WARNING: Not running as root. Some checks will be limited.${NC}"
        log "  ${YEL}Run with: sudo $0${NC}"
    fi
    log ""
}

# ============================================================
# 1. UNIFIED LOG — Security & PowerShell events
# ============================================================
check_unified_logs() {
    hdr "[1/15] Unified Log Analysis (macOS primary log system)"

    local report="$OUTDIR/01_unified_log_analysis.txt"
    echo "UNIFIED LOG ANALYSIS" > "$report"
    echo "========================================" >> "$report"

    # --- 1a. Security / authorization events (last 7 days) ---
    info "Scanning authorization/security events (last 7d)..."
    log_show --predicate 'subsystem == "com.apple.Authorization" OR subsystem == "com.apple.securityd" OR subsystem == "com.apple.authd"' \
        --last 7d --style compact 2>/dev/null > "$OUTDIR/_auth_logs.txt" || true

    local auth_count=$(wc -l < "$OUTDIR/_auth_logs.txt" 2>/dev/null || echo 0)
    info "  Authorization log entries: $auth_count"

    # --- 1b. PowerShell events ---
    info "Scanning for PowerShell activity..."
    log_show --predicate 'process == "pwsh" OR process == "powershell" OR eventMessage CONTAINS "powershell"' \
        --last 30d --style compact 2>/dev/null > "$OUTDIR/_powershell_logs.txt" || true

    local ps_count=$(wc -l < "$OUTDIR/_powershell_logs.txt" 2>/dev/null || echo 0)
    if [ "$ps_count" -gt 5 ]; then
        warn "PowerShell activity detected: $ps_count entries → _powershell_logs.txt"
    else
        ok "Minimal PowerShell activity ($ps_count entries)"
    fi

    # --- 1c. Suspicious process execution ---
    info "Scanning for suspicious process execution..."
    log_show --predicate 'process == "curl" OR process == "wget" OR process == "nc" OR process == "ncat" OR process == "python" OR process == "python3" OR process == "ruby" OR process == "perl" OR process == "osascript" OR process == "bash" OR process == "sh" OR process == "zsh"' \
        --last 7d --style compact 2>/dev/null | head -5000 > "$OUTDIR/_suspicious_process_logs.txt" || true

    # --- 1d. XProtect / Gatekeeper events ---
    info "Scanning XProtect/Gatekeeper events..."
    log_show --predicate 'subsystem == "com.apple.xprotect" OR subsystem == "com.apple.gatekeeper" OR subsystem == "com.apple.MRT"' \
        --last 30d --style compact 2>/dev/null > "$OUTDIR/_xprotect_logs.txt" || true

    local xp_count=$(wc -l < "$OUTDIR/_xprotect_logs.txt" 2>/dev/null || echo 0)
    info "  XProtect/Gatekeeper entries: $xp_count"

    # --- 1e. TCC (Transparency, Consent, Control) events ---
    info "Scanning TCC access events..."
    log_show --predicate 'subsystem == "com.apple.TCC"' \
        --last 7d --style compact 2>/dev/null > "$OUTDIR/_tcc_logs.txt" || true

    # --- 1f. SSH/remote access ---
    info "Scanning SSH/remote access..."
    log_show --predicate 'process == "sshd" OR process == "ssh" OR subsystem == "com.apple.remotemanagement"' \
        --last 7d --style compact 2>/dev/null > "$OUTDIR/_ssh_logs.txt" || true

    # Combine key findings
    {
        echo "=== PowerShell Activity ==="
        head -100 "$OUTDIR/_powershell_logs.txt" 2>/dev/null
        echo ""
        echo "=== XProtect/Gatekeeper ==="
        head -100 "$OUTDIR/_xprotect_logs.txt" 2>/dev/null
        echo ""
        echo "=== SSH/Remote Access ==="
        head -100 "$OUTDIR/_ssh_logs.txt" 2>/dev/null
    } >> "$report"
}

# ============================================================
# 2. ASL / System Logs (legacy + current)
# ============================================================
check_system_logs() {
    hdr "[2/15] System Log Files"

    local report="$OUTDIR/02_system_logs.txt"
    echo "SYSTEM LOG FILE ANALYSIS" > "$report"

    # Key log locations
    local log_dirs=(
        "/var/log"
        "/var/log/asl"
        "/Library/Logs"
        "$HOME/Library/Logs"
        "/var/log/DiagnosticMessages"
    )

    for dir in "${log_dirs[@]}"; do
        if [ -d "$dir" ]; then
            echo "" >> "$report"
            echo "=== $dir ===" >> "$report"
            find "$dir" -maxdepth 2 -type f -name "*.log" -o -name "*.asl" 2>/dev/null | head -50 >> "$report"
        fi
    done

    # Check install.log for suspicious installs
    if [ -f /var/log/install.log ]; then
        info "Checking install.log for suspicious entries..."
        grep -iE "nova|beacon|payload|trojan|malware|hack|exploit|reverse|shell|rat" /var/log/install.log >> "$report" 2>/dev/null || true
    fi

    # Check system.log
    if [ -f /var/log/system.log ]; then
        info "Checking system.log..."
        grep -iE "nova|unauthorized|denied|malware|suspicious" /var/log/system.log >> "$report" 2>/dev/null || true
    fi

    ok "System logs collected → 02_system_logs.txt"
}

# ============================================================
# 3. PERSISTENCE MECHANISMS
# ============================================================
check_persistence() {
    hdr "[3/15] Persistence Mechanisms"

    local report="$OUTDIR/03_persistence.txt"
    echo "PERSISTENCE MECHANISM SCAN" > "$report"
    echo "========================================" >> "$report"

    # --- LaunchAgents (user) ---
    echo -e "\n=== USER LaunchAgents ===" >> "$report"
    for dir in "$HOME/Library/LaunchAgents" /Library/LaunchAgents /System/Library/LaunchAgents; do
        if [ -d "$dir" ]; then
            echo "--- $dir ---" >> "$report"
            ls -la "$dir"/ 2>/dev/null >> "$report"
            # Check each plist for suspicious programs
            for plist in "$dir"/*.plist 2>/dev/null; do
                [ -f "$plist" ] || continue
                prog=$(defaults read "$plist" ProgramArguments 2>/dev/null || plutil -p "$plist" 2>/dev/null | grep -i program)
                if echo "$prog" | grep -qiE "curl|wget|python|bash|sh|nc|ncat|reverse|beacon|nova|payload|tmp|hidden|cache.*bin"; then
                    crit "SUSPICIOUS LaunchAgent: $plist"
                    echo "*** SUSPICIOUS: $plist ***" >> "$report"
                    plutil -p "$plist" >> "$report" 2>/dev/null
                fi
            done
        fi
    done

    # --- LaunchDaemons ---
    echo -e "\n=== LaunchDaemons ===" >> "$report"
    for dir in /Library/LaunchDaemons /System/Library/LaunchDaemons; do
        if [ -d "$dir" ]; then
            echo "--- $dir ---" >> "$report"
            ls -la "$dir"/ 2>/dev/null >> "$report"
            for plist in "$dir"/*.plist 2>/dev/null; do
                [ -f "$plist" ] || continue
                if ! echo "$plist" | grep -qE "^/System/Library|com\.apple\.|com\.microsoft\.|com\.google\."; then
                    warn "Non-Apple LaunchDaemon: $plist"
                    echo "*** NON-APPLE: $plist ***" >> "$report"
                    plutil -p "$plist" >> "$report" 2>/dev/null
                fi
            done
        fi
    done

    # --- Login Items ---
    echo -e "\n=== Login Items ===" >> "$report"
    osascript -e 'tell application "System Events" to get the name of every login item' >> "$report" 2>/dev/null || true

    # --- Cron Jobs ---
    echo -e "\n=== Cron Jobs ===" >> "$report"
    crontab -l >> "$report" 2>/dev/null || echo "No crontab" >> "$report"
    for user_cron in /usr/lib/cron/tabs/*; do
        [ -f "$user_cron" ] && cat "$user_cron" >> "$report" 2>/dev/null
    done
    ls -la /etc/crontab /etc/periodic/*/* 2>/dev/null >> "$report"

    # --- Periodic scripts ---
    echo -e "\n=== Periodic Scripts ===" >> "$report"
    for period in daily weekly monthly; do
        if [ -d "/etc/periodic/$period" ]; then
            echo "--- /etc/periodic/$period ---" >> "$report"
            ls -la "/etc/periodic/$period/" >> "$report" 2>/dev/null
        fi
    done

    # --- Authorization plugins ---
    echo -e "\n=== Authorization Plugins ===" >> "$report"
    ls -la /Library/Security/SecurityAgentPlugins/ >> "$report" 2>/dev/null || echo "None" >> "$report"

    # --- Kernel extensions ---
    echo -e "\n=== Kernel Extensions (kexts) ===" >> "$report"
    kextstat 2>/dev/null | grep -v com.apple >> "$report" || true
    ls -la /Library/Extensions/ >> "$report" 2>/dev/null

    # --- System Extensions ---
    echo -e "\n=== System Extensions ===" >> "$report"
    systemextensionsctl list 2>/dev/null >> "$report" || true

    # --- Profiles ---
    echo -e "\n=== Configuration Profiles ===" >> "$report"
    profiles list 2>/dev/null >> "$report" || true

    # --- emond ---
    echo -e "\n=== emond rules ===" >> "$report"
    ls -la /etc/emond.d/rules/ 2>/dev/null >> "$report" || echo "None" >> "$report"

    # --- at jobs ---
    echo -e "\n=== at jobs ===" >> "$report"
    atq 2>/dev/null >> "$report" || echo "None" >> "$report"

    info "Persistence scan complete → 03_persistence.txt"
}

# ============================================================
# 4. RUNNING PROCESSES
# ============================================================
check_processes() {
    hdr "[4/15] Running Processes Analysis"

    local report="$OUTDIR/04_processes.txt"
    echo "RUNNING PROCESSES" > "$report"
    echo "========================================" >> "$report"

    # Full process list
    ps aux >> "$report" 2>/dev/null

    echo -e "\n=== SUSPICIOUS PROCESS PATTERNS ===" >> "$report"

    local suspicious_procs=(
        "nc -l"
        "ncat"
        "socat"
        "reverse"
        "beacon"
        "nova"
        "payload"
        "meterpreter"
        "empire"
        "cobaltstrike"
        "sliver"
        "pwsh"
        "powershell"
        "python.*http"
        "python.*socket"
        "ruby.*socket"
        "perl.*socket"
        "bash.*-i.*dev/tcp"
        "curl.*\|.*sh"
        "wget.*\|.*sh"
        "osascript.*-e"
        "screencapture"
        "tcpdump"
        "tshark"
        "cryptominer"
        "xmrig"
    )

    for pattern in "${suspicious_procs[@]}"; do
        matches=$(ps aux 2>/dev/null | grep -iE "$pattern" | grep -v grep || true)
        if [ -n "$matches" ]; then
            crit "Suspicious process running: $pattern"
            echo "$matches" >> "$report"
        fi
    done

    # Check for processes running from /tmp, /var/tmp, hidden dirs
    echo -e "\n=== Processes from suspicious locations ===" >> "$report"
    ps aux 2>/dev/null | grep -E '/tmp/|/var/tmp/|\./\.|/Users/.*/\.' | grep -v grep >> "$report" || true

    local tmp_procs=$(ps aux 2>/dev/null | grep -E '/tmp/|/var/tmp/' | grep -v grep | wc -l)
    if [ "$tmp_procs" -gt 0 ]; then
        warn "Processes running from /tmp or /var/tmp: $tmp_procs"
    fi

    # Process tree
    echo -e "\n=== Process Tree ===" >> "$report"
    pstree 2>/dev/null >> "$report" || ps -axo pid,ppid,user,comm >> "$report" 2>/dev/null

    ok "Process analysis → 04_processes.txt"
}

# ============================================================
# 5. NETWORK CONNECTIONS
# ============================================================
check_network() {
    hdr "[5/15] Network Connections"

    local report="$OUTDIR/05_network.txt"
    echo "NETWORK CONNECTION ANALYSIS" > "$report"
    echo "========================================" >> "$report"

    # Active connections
    echo "=== Active Connections (netstat) ===" >> "$report"
    netstat -an 2>/dev/null >> "$report" || true

    echo -e "\n=== Listening Ports ===" >> "$report"
    netstat -an 2>/dev/null | grep -i listen >> "$report" || true

    echo -e "\n=== lsof network connections ===" >> "$report"
    lsof -i -n -P 2>/dev/null >> "$report" || true

    # Check for suspicious outbound connections
    echo -e "\n=== SUSPICIOUS CONNECTIONS ===" >> "$report"

    # Common C2 ports
    local c2_ports="4444|5555|8443|8080|9090|1337|31337|6666|6667|4443|2222|3333|7777|9999"
    local suspicious_net=$(lsof -i -n -P 2>/dev/null | grep -E "ESTABLISHED|SYN_SENT" | grep -vE "localhost|127\.0\.0\.1" || true)

    if [ -n "$suspicious_net" ]; then
        echo "$suspicious_net" >> "$report"

        # Check for C2 ports
        c2_hits=$(echo "$suspicious_net" | grep -E ":($c2_ports)" || true)
        if [ -n "$c2_hits" ]; then
            crit "Connections on known C2 ports detected!"
            echo "$c2_hits" >> "$report"
        fi
    fi

    # DNS cache
    echo -e "\n=== DNS Cache (partial) ===" >> "$report"
    dscacheutil -cachedump -entries Host 2>/dev/null >> "$report" || true

    # Firewall status
    echo -e "\n=== Firewall Status ===" >> "$report"
    /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate >> "$report" 2>/dev/null || true
    /usr/libexec/ApplicationFirewall/socketfilterfw --liststealthmode >> "$report" 2>/dev/null || true

    info "Network analysis → 05_network.txt"
}

# ============================================================
# 6. USER ACCOUNTS & SUDO
# ============================================================
check_users() {
    hdr "[6/15] User Accounts & Privileges"

    local report="$OUTDIR/06_users.txt"
    echo "USER ACCOUNT ANALYSIS" > "$report"
    echo "========================================" >> "$report"

    # List all users
    echo "=== All Users ===" >> "$report"
    dscl . list /Users 2>/dev/null >> "$report" || true

    # Admin users
    echo -e "\n=== Admin Group Members ===" >> "$report"
    dscl . -read /Groups/admin GroupMembership 2>/dev/null >> "$report" || true

    # Recently created users
    echo -e "\n=== User creation dates ===" >> "$report"
    for user in $(dscl . list /Users 2>/dev/null | grep -v "^_"); do
        created=$(dscl . -read /Users/"$user" DateCreated 2>/dev/null | tail -1 || echo "unknown")
        echo "  $user: $created" >> "$report"
    done

    # Sudo log
    echo -e "\n=== Recent sudo usage ===" >> "$report"
    log_show --predicate 'process == "sudo"' --last 7d --style compact 2>/dev/null | tail -100 >> "$report" || true

    # SSH authorized keys
    echo -e "\n=== SSH Authorized Keys ===" >> "$report"
    for home in /Users/*; do
        if [ -f "$home/.ssh/authorized_keys" ]; then
            warn "SSH authorized_keys found: $home/.ssh/authorized_keys"
            echo "--- $home/.ssh/authorized_keys ---" >> "$report"
            cat "$home/.ssh/authorized_keys" >> "$report" 2>/dev/null
        fi
    done

    ok "User analysis → 06_users.txt"
}

# ============================================================
# 7. FILE SYSTEM — Suspicious files
# ============================================================
check_filesystem() {
    hdr "[7/15] Suspicious File Scan"

    local report="$OUTDIR/07_suspicious_files.txt"
    echo "SUSPICIOUS FILE SCAN" > "$report"
    echo "========================================" >> "$report"

    # Recently modified executables in /tmp
    echo "=== Executables in /tmp & /var/tmp (last 30d) ===" >> "$report"
    find /tmp /var/tmp -type f \( -perm +111 -o -name "*.sh" -o -name "*.py" -o -name "*.rb" -o -name "*.pl" \) -mtime -30 2>/dev/null >> "$report" || true

    # Hidden files in user home
    echo -e "\n=== Hidden executables in home dirs ===" >> "$report"
    find /Users -maxdepth 3 -name ".*" -type f -perm +111 2>/dev/null | grep -v ".DS_Store" >> "$report" || true

    # Recently modified files in suspicious locations
    echo -e "\n=== Recently modified files in /Library (last 7d) ===" >> "$report"
    find /Library -type f -mtime -7 -not -path "*/Caches/*" -not -path "*/Updates/*" 2>/dev/null | head -100 >> "$report" || true

    # Unsigned or ad-hoc signed binaries in Applications
    echo -e "\n=== Application code signing check ===" >> "$report"
    for app in /Applications/*.app; do
        [ -d "$app" ] || continue
        sig=$(codesign -dv "$app" 2>&1 || true)
        if echo "$sig" | grep -q "code object is not signed\|invalid signature\|adhoc"; then
            warn "Unsigned/adhoc app: $app"
            echo "*** $app ***" >> "$report"
            echo "$sig" >> "$report"
        fi
    done

    # Files with quarantine flag removed (bypass Gatekeeper)
    echo -e "\n=== Recently downloaded files (quarantine) ===" >> "$report"
    sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 \
        "SELECT datetime(LSQuarantineTimeStamp + 978307200, 'unixepoch') as date, LSQuarantineAgentName, LSQuarantineDataURLString, LSQuarantineOriginURLString FROM LSQuarantineEvent ORDER BY date DESC LIMIT 50;" \
        2>/dev/null >> "$report" || true

    # Look for Nova-specific artifacts
    echo -e "\n=== Nova IOC file scan ===" >> "$report"
    find / -maxdepth 5 -iname "*nova*" -not -path "*/Library/Caches/*" -not -path "*/.Trash/*" 2>/dev/null >> "$report" || true

    info "File scan → 07_suspicious_files.txt"
}

# ============================================================
# 8. BROWSER EXTENSIONS
# ============================================================
check_browser_extensions() {
    hdr "[8/15] Browser Extensions"

    local report="$OUTDIR/08_browser_extensions.txt"
    echo "BROWSER EXTENSION SCAN" > "$report"

    # Chrome extensions
    echo "=== Chrome Extensions ===" >> "$report"
    for profile in "$HOME/Library/Application Support/Google/Chrome"/{Default,Profile*}; do
        [ -d "$profile/Extensions" ] || continue
        echo "--- $profile ---" >> "$report"
        find "$profile/Extensions" -name "manifest.json" -exec sh -c '
            echo "Extension: $(dirname "{}")"
            grep -o "\"name\": *\"[^\"]*\"" "{}" 2>/dev/null | head -1
            echo ""
        ' \; >> "$report" 2>/dev/null
    done

    # Safari extensions
    echo -e "\n=== Safari Extensions ===" >> "$report"
    find "$HOME/Library/Safari/Extensions" -name "*.safariextz" 2>/dev/null >> "$report" || echo "None" >> "$report"
    pluginkit -mA 2>/dev/null | grep -i safari >> "$report" || true

    # Firefox
    echo -e "\n=== Firefox Extensions ===" >> "$report"
    find "$HOME/Library/Application Support/Firefox/Profiles" -name "extensions.json" -exec cat {} \; 2>/dev/null | \
        python3 -c "import sys,json; [print(e.get('defaultLocale',{}).get('name','?'),e.get('sourceURI','')) for e in json.loads(sys.stdin.read()).get('addons',[])]" >> "$report" 2>/dev/null || true

    ok "Browser extensions → 08_browser_extensions.txt"
}

# ============================================================
# 9. KEYCHAIN & CREDENTIALS
# ============================================================
check_credentials() {
    hdr "[9/15] Credential Stores"

    local report="$OUTDIR/09_credentials.txt"
    echo "CREDENTIAL STORE ANALYSIS" > "$report"
    echo "(Not dumping actual credentials, only metadata)" >> "$report"

    # Keychain list
    echo -e "\n=== Keychains ===" >> "$report"
    security list-keychains 2>/dev/null >> "$report" || true

    # Recently added keychain items (by modification date)
    echo -e "\n=== Recently modified keychain files ===" >> "$report"
    find "$HOME/Library/Keychains" -type f -mtime -30 2>/dev/null >> "$report" || true

    # SSH keys
    echo -e "\n=== SSH Keys ===" >> "$report"
    ls -la "$HOME/.ssh/" 2>/dev/null >> "$report" || true

    # AWS / Cloud credentials
    echo -e "\n=== Cloud credential files ===" >> "$report"
    for cred in "$HOME/.aws/credentials" "$HOME/.azure/accessTokens.json" "$HOME/.config/gcloud/credentials.db" "$HOME/.kube/config"; do
        if [ -f "$cred" ]; then
            warn "Cloud credential file found: $cred (check for unauthorized access)"
            echo "  EXISTS: $cred ($(stat -f '%Sm' "$cred" 2>/dev/null || stat -c '%y' "$cred" 2>/dev/null))" >> "$report"
        fi
    done

    ok "Credential analysis → 09_credentials.txt"
}

# ============================================================
# 10. TCC DATABASE (Privacy permissions)
# ============================================================
check_tcc() {
    hdr "[10/15] TCC Privacy Permissions"

    local report="$OUTDIR/10_tcc_permissions.txt"
    echo "TCC (Transparency, Consent, Control) DATABASE" > "$report"

    local tcc_dbs=(
        "$HOME/Library/Application Support/com.apple.TCC/TCC.db"
        "/Library/Application Support/com.apple.TCC/TCC.db"
    )

    for db in "${tcc_dbs[@]}"; do
        if [ -f "$db" ]; then
            echo -e "\n=== $db ===" >> "$report"
            sqlite3 "$db" "SELECT service, client, auth_value, last_modified FROM access ORDER BY last_modified DESC LIMIT 100;" 2>/dev/null >> "$report" || \
                warn "Cannot read TCC.db (need Full Disk Access or root)"

            # Check for suspicious FDA/accessibility grants
            local suspicious_tcc
            suspicious_tcc=$(sqlite3 "$db" "SELECT client FROM access WHERE service IN ('kTCCServiceAccessibility','kTCCServiceScreenCapture','kTCCServiceSystemPolicyAllFiles') AND auth_value=2;" 2>/dev/null || true)
            if [ -n "$suspicious_tcc" ]; then
                echo -e "\n*** Apps with sensitive permissions ***" >> "$report"
                echo "$suspicious_tcc" >> "$report"
            fi
        fi
    done

    info "TCC analysis → 10_tcc_permissions.txt"
}

# ============================================================
# 11. SHELL HISTORY
# ============================================================
check_shell_history() {
    hdr "[11/15] Shell History Analysis"

    local report="$OUTDIR/11_shell_history.txt"
    echo "SHELL HISTORY ANALYSIS" > "$report"

    local history_files=(
        "$HOME/.bash_history"
        "$HOME/.zsh_history"
        "$HOME/.sh_history"
        "$HOME/.fish_history"
        "$HOME/.python_history"
    )

    for hf in "${history_files[@]}"; do
        if [ -f "$hf" ]; then
            echo -e "\n=== $hf ===" >> "$report"
            echo "  Size: $(ls -lh "$hf" | awk '{print $5}')" >> "$report"
            echo "  Last modified: $(stat -f '%Sm' "$hf" 2>/dev/null || stat -c '%y' "$hf" 2>/dev/null)" >> "$report"

            # Search for suspicious commands
            echo "  --- Suspicious entries ---" >> "$report"
            grep -inE "curl.*\|.*sh|wget.*\|.*sh|nc -|ncat|socat|reverse|python.*http\.server|python.*socket|base64|openssl.*enc|chmod.*777|scp |rsync.*-e|ssh.*-R|ssh.*-D|nova|beacon|payload|/dev/tcp|mkfifo|mknod|credential|password|token|secret|api.key" \
                "$hf" >> "$report" 2>/dev/null || true
        fi
    done

    # Check if history was recently cleared
    for hf in "${history_files[@]}"; do
        if [ -f "$hf" ]; then
            lines=$(wc -l < "$hf" 2>/dev/null || echo 0)
            if [ "$lines" -lt 5 ]; then
                crit "Shell history suspiciously small ($lines lines): $hf — may have been wiped!"
            fi
        fi
    done

    # .zshrc / .bashrc / .bash_profile for injected commands
    echo -e "\n=== RC file analysis ===" >> "$report"
    for rc in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zprofile"; do
        if [ -f "$rc" ]; then
            echo "--- $rc ---" >> "$report"
            grep -nE "curl|wget|python|nc |eval|base64|exec|hidden|nova|beacon" "$rc" >> "$report" 2>/dev/null || echo "  Clean" >> "$report"
        fi
    done

    info "Shell history → 11_shell_history.txt"
}

# ============================================================
# 12. MDMCLIENT / PROFILES
# ============================================================
check_mdm() {
    hdr "[12/15] MDM & Configuration Profiles"

    local report="$OUTDIR/12_mdm_profiles.txt"
    echo "MDM & CONFIGURATION PROFILES" > "$report"

    profiles list -verbose 2>/dev/null >> "$report" || echo "Cannot list profiles" >> "$report"

    # Check for suspicious profiles
    if profiles list 2>/dev/null | grep -qiE "nova|hacker|test|unknown|suspicious"; then
        crit "Suspicious configuration profile detected!"
    fi

    ok "MDM analysis → 12_mdm_profiles.txt"
}

# ============================================================
# 13. APPLICATION QUARANTINE & GATEKEEPER
# ============================================================
check_gatekeeper() {
    hdr "[13/15] Gatekeeper & SIP Status"

    local report="$OUTDIR/13_gatekeeper_sip.txt"
    echo "GATEKEEPER & SIP STATUS" > "$report"

    echo "=== Gatekeeper ===" >> "$report"
    spctl --status 2>/dev/null >> "$report" || true

    echo -e "\n=== SIP (System Integrity Protection) ===" >> "$report"
    csrutil status 2>/dev/null >> "$report" || true

    if csrutil status 2>/dev/null | grep -q "disabled"; then
        crit "SIP is DISABLED — system integrity compromised!"
    else
        ok "SIP is enabled"
    fi

    echo -e "\n=== AMFI (Apple Mobile File Integrity) ===" >> "$report"
    nvram -p 2>/dev/null | grep -i amfi >> "$report" || echo "  Default (enabled)" >> "$report"

    ok "Security status → 13_gatekeeper_sip.txt"
}

# ============================================================
# 14. MICROSOFT DEFENDER FOR ENDPOINT (if installed)
# ============================================================
check_mde() {
    hdr "[14/15] Microsoft Defender for Endpoint (macOS)"

    local report="$OUTDIR/14_microsoft_defender.txt"
    echo "MICROSOFT DEFENDER FOR ENDPOINT (macOS)" > "$report"

    if command -v mdatp &>/dev/null; then
        ok "MDE (mdatp) is installed"

        echo "=== Health Status ===" >> "$report"
        mdatp health 2>/dev/null >> "$report" || true

        echo -e "\n=== Threat History ===" >> "$report"
        mdatp threat list 2>/dev/null >> "$report" || true

        echo -e "\n=== Exclusions ===" >> "$report"
        mdatp exclusion list 2>/dev/null >> "$report" || true

        echo -e "\n=== Real-time Protection ===" >> "$report"
        local rtp=$(mdatp health --field real_time_protection_enabled 2>/dev/null || echo "unknown")
        echo "  real_time_protection: $rtp" >> "$report"
        if [ "$rtp" = "false" ]; then
            crit "MDE Real-time Protection is DISABLED!"
        fi

        # Check for tampered exclusions
        local excl_count=$(mdatp exclusion list 2>/dev/null | wc -l)
        if [ "$excl_count" -gt 10 ]; then
            warn "MDE has $excl_count exclusions — check for attacker-added entries"
        fi

    elif [ -d "/Applications/Microsoft Defender.app" ]; then
        warn "Microsoft Defender app exists but mdatp CLI not in PATH"
    else
        info "Microsoft Defender for Endpoint not installed"
    fi

    # Check Defender logs
    local mde_log_dir="/Library/Logs/Microsoft/mdatp"
    if [ -d "$mde_log_dir" ]; then
        echo -e "\n=== MDE Logs ===" >> "$report"
        ls -lt "$mde_log_dir"/ 2>/dev/null | head -20 >> "$report"

        # Search for MpPreference equivalent tampering in logs
        grep -riE "exclusion|disabled|tamper|bypass|policy.*change" "$mde_log_dir"/*.log 2>/dev/null | tail -50 >> "$report" || true
    fi

    info "MDE analysis → 14_microsoft_defender.txt"
}

# ============================================================
# 15. SUMMARY & IOC EXTRACTION
# ============================================================
generate_summary() {
    hdr "[15/15] Generating Summary"

    local report="$OUTDIR/15_SUMMARY.txt"

    cat > "$report" << EOF
======================================================
  macOS FORENSIC SCAN SUMMARY
======================================================
Date:     $(date)
Hostname: $(hostname)
macOS:    $(sw_vers -productVersion 2>/dev/null || echo 'unknown')
User:     $(whoami)
Output:   ${OUTDIR}

FINDINGS:  ${FINDINGS}
CRITICAL:  ${CRITICAL}
======================================================

REPORTS GENERATED:
  01_unified_log_analysis.txt     - Unified log (PowerShell, auth, XProtect)
  02_system_logs.txt              - System/ASL log analysis
  03_persistence.txt              - LaunchAgents, LaunchDaemons, cron, etc.
  04_processes.txt                - Running process analysis
  05_network.txt                  - Network connections & listening ports
  06_users.txt                    - User accounts & privileges
  07_suspicious_files.txt         - Suspicious files on disk
  08_browser_extensions.txt       - Browser extension inventory
  09_credentials.txt              - Credential store metadata
  10_tcc_permissions.txt          - TCC privacy permissions
  11_shell_history.txt            - Shell history & RC files
  12_mdm_profiles.txt             - MDM & configuration profiles
  13_gatekeeper_sip.txt           - Gatekeeper, SIP, AMFI status
  14_microsoft_defender.txt       - MDE status, threats, exclusions
  15_SUMMARY.txt                  - This file

RAW LOG EXPORTS:
  _powershell_logs.txt            - PowerShell unified log entries
  _auth_logs.txt                  - Authorization events
  _xprotect_logs.txt              - XProtect/Gatekeeper events
  _tcc_logs.txt                   - TCC events
  _ssh_logs.txt                   - SSH/remote access events
  _suspicious_process_logs.txt    - Suspicious process execution logs
EOF

    echo "" >> "$report"
    echo "CRITICAL FINDINGS:" >> "$report"
    echo "==================" >> "$report"
    grep -h "\[!!!\]" "$LOGFILE" >> "$report" 2>/dev/null || echo "  None" >> "$report"

    echo "" >> "$report"
    echo "WARNINGS:" >> "$report"
    echo "=========" >> "$report"
    grep -h "\[!\]" "$LOGFILE" >> "$report" 2>/dev/null || echo "  None" >> "$report"

    log ""
    log "${BLD}${CYN}======================================================${NC}"
    log "${BLD}${CYN}  SCAN COMPLETE${NC}"
    log "${BLD}${CYN}======================================================${NC}"
    log ""
    log "  ${BLD}Findings: ${FINDINGS}${NC}"

    if [ "$CRITICAL" -gt 0 ]; then
        log "  ${RED}CRITICAL: ${CRITICAL}${NC}"
    fi

    log ""
    log "  ${BLD}Reports in: ${OUTDIR}${NC}"
    log ""
    log "  ${YEL}Priority reading:${NC}"
    log "    1. ${RED}15_SUMMARY.txt${NC}               — Start here"
    log "    2. ${RED}03_persistence.txt${NC}            — Backdoors & implants"
    log "    3. ${RED}14_microsoft_defender.txt${NC}     — Defender tampering (MpPreference equivalent)"
    log "    4. ${RED}05_network.txt${NC}               — C2 connections"
    log "    5. ${YEL}04_processes.txt${NC}             — Malicious processes"
    log "    6. ${YEL}11_shell_history.txt${NC}         — Attacker commands"
    log "    7. ${YEL}01_unified_log_analysis.txt${NC}  — PowerShell & system events"
    log ""
}

# ============================================================
# MAIN
# ============================================================
banner
check_unified_logs
check_system_logs
check_persistence
check_processes
check_network
check_users
check_filesystem
check_browser_extensions
check_credentials
check_tcc
check_shell_history
check_mdm
check_gatekeeper
check_mde
generate_summary
