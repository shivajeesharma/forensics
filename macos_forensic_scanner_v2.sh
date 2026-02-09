#!/bin/bash
#=============================================================================
# macOS Forensic Threat Hunter v2 — ATTACK TIMELINE EDITION
# 
# Reconstructs the attack kill chain chronologically using MITRE ATT&CK:
#   1. Initial Access → 2. Execution → 3. Persistence → 4. Privilege Escalation
#   5. Defense Evasion → 6. Credential Access → 7. Discovery → 8. Lateral Movement
#   9. Collection → 10. Exfiltration → 11. C2 → 12. Impact
#
# All events are normalized to a single unified timeline with timestamps,
# MITRE tactic tags, severity, and source attribution.
#
# Run as ROOT: sudo ./macos_forensic_scanner.sh [optional: days_back, default 30]
#=============================================================================

set -uo pipefail

# Colors
RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
MAG='\033[0;35m'
BLD='\033[1m'
NC='\033[0m'

DAYS_BACK="${1:-30}"
OUTDIR="./macos_attack_timeline_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR/raw" "$OUTDIR/phases"

LOGFILE="$OUTDIR/00_scan_log.txt"
TIMELINE_RAW="$OUTDIR/raw/_timeline_unsorted.tsv"
TIMELINE_FINAL="$OUTDIR/ATTACK_TIMELINE.txt"
TIMELINE_CSV="$OUTDIR/ATTACK_TIMELINE.csv"
FINDINGS=0
CRITICAL=0

# Timeline entry format: TIMESTAMP\tSEVERITY\tMITRE_TACTIC\tMITRE_TECHNIQUE\tSOURCE\tDETAILS
> "$TIMELINE_RAW"

# ============================================================
# Helpers
# ============================================================
log()  { echo -e "$1" | tee -a "$LOGFILE"; }
hdr()  { log "\n${BLD}${CYN}$1${NC}"; }
warn() { log "  ${YEL}[!] $1${NC}"; FINDINGS=$((FINDINGS+1)); }
crit() { log "  ${RED}[!!!] $1${NC}"; FINDINGS=$((FINDINGS+1)); CRITICAL=$((CRITICAL+1)); }
ok()   { log "  ${GRN}[✓] $1${NC}"; }
info() { log "  $1"; }

# Add event to unified timeline
# Usage: tl "2025-02-01 10:30:00" "CRITICAL" "Defense Evasion" "T1562.001" "unified_log" "Defender RTP disabled"
tl() {
    local ts="${1:-UNKNOWN}"
    local sev="${2:-INFO}"
    local tactic="${3:-Unknown}"
    local technique="${4:-}"
    local source="${5:-}"
    local detail="${6:-}"
    printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$ts" "$sev" "$tactic" "$technique" "$source" "$detail" >> "$TIMELINE_RAW"
}

banner() {
    log "${BLD}${CYN}============================================================${NC}"
    log "${BLD}${CYN}  macOS FORENSIC THREAT HUNTER v2 — ATTACK TIMELINE        ${NC}"
    log "${BLD}${CYN}============================================================${NC}"
    log "  Date:       $(date)"
    log "  Hostname:   $(hostname)"
    log "  User:       $(whoami)"
    log "  macOS:      $(sw_vers -productVersion 2>/dev/null || echo 'unknown')"
    log "  Scan scope: Last ${DAYS_BACK} days"
    log "  Output:     ${OUTDIR}"
    if [ "$(id -u)" -ne 0 ]; then
        log "\n  ${YEL}WARNING: Not running as root. Some checks limited.${NC}"
        log "  ${YEL}Run: sudo $0 $DAYS_BACK${NC}"
    fi
    log ""
}

# ============================================================
# PHASE 1: INITIAL ACCESS (TA0001)
# How did the attacker get in?
# ============================================================
phase_initial_access() {
    hdr "[PHASE 1/12] INITIAL ACCESS (TA0001)"
    local report="$OUTDIR/phases/01_initial_access.txt"
    echo "PHASE 1: INITIAL ACCESS" > "$report"

    # --- 1a. Quarantine events (downloaded files / phishing payloads) ---
    info "Checking quarantine database (download history)..."
    if [ -f "$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2" ]; then
        sqlite3 "$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2" \
            "SELECT datetime(LSQuarantineTimeStamp + 978307200, 'unixepoch') as ts,
                    LSQuarantineAgentName as agent,
                    LSQuarantineDataURLString as data_url,
                    LSQuarantineOriginURLString as origin_url,
                    LSQuarantineSenderName as sender
             FROM LSQuarantineEvent
             ORDER BY ts DESC LIMIT 200;" 2>/dev/null | while IFS='|' read -r ts agent data_url origin_url sender; do
            echo "[$ts] Agent=$agent URL=$data_url Origin=$origin_url Sender=$sender" >> "$report"

            # Flag suspicious downloads
            if echo "$data_url $origin_url" | grep -qiE "\.exe|\.scr|\.bat|\.ps1|\.vbs|\.js[^o]|\.hta|\.msi|\.dmg|\.pkg|\.app\.zip|nova|payload|beacon|trojan|hack|exploit"; then
                tl "$ts" "HIGH" "Initial Access" "T1566.001 Phishing Attachment" "quarantine_db" "Suspicious download: agent=$agent url=$data_url origin=$origin_url"
                crit "Suspicious download: $data_url via $agent"
            else
                tl "$ts" "INFO" "Initial Access" "T1566.002 Phishing Link" "quarantine_db" "Download: agent=$agent url=$data_url"
            fi
        done
    fi

    # --- 1b. Mail attachments (if Mail.app used) ---
    info "Checking Mail.app downloads..."
    find "$HOME/Library/Mail Downloads" "$HOME/Library/Containers/com.apple.mail/Data/Library/Mail Downloads" \
        -type f -mtime -"$DAYS_BACK" 2>/dev/null | while read -r f; do
        ts=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$f" 2>/dev/null || echo "UNKNOWN")
        tl "$ts" "MEDIUM" "Initial Access" "T1566.001 Phishing Attachment" "mail_downloads" "Mail attachment: $f"
        echo "[$ts] $f" >> "$report"
    done

    # --- 1c. AirDrop received files ---
    info "Checking AirDrop received files..."
    find "$HOME/Downloads" "$HOME/Desktop" -type f -mtime -"$DAYS_BACK" 2>/dev/null | while read -r f; do
        if xattr -l "$f" 2>/dev/null | grep -q "com.apple.metadata:kMDItemWhereFroms"; then
            ts=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$f" 2>/dev/null || echo "UNKNOWN")
            echo "[$ts] Downloaded file: $f" >> "$report"
        fi
    done

    # --- 1d. SSH brute force / unauthorized access ---
    info "Checking SSH login attempts..."
    log_show --predicate 'process == "sshd" AND (eventMessage CONTAINS "Failed" OR eventMessage CONTAINS "Accepted" OR eventMessage CONTAINS "Invalid")' \
        --last "${DAYS_BACK}d" --style compact 2>/dev/null | while read -r line; do
        ts=$(echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
        [ -z "$ts" ] && continue
        if echo "$line" | grep -qi "Failed\|Invalid"; then
            tl "$ts" "MEDIUM" "Initial Access" "T1110 Brute Force" "sshd_log" "SSH failed: $line"
        elif echo "$line" | grep -qi "Accepted"; then
            tl "$ts" "HIGH" "Initial Access" "T1078 Valid Accounts" "sshd_log" "SSH accepted: $line"
        fi
        echo "$line" >> "$report"
    done

    # --- 1e. Remote Apple Events / Screen Sharing ---
    info "Checking remote access services..."
    log_show --predicate 'subsystem == "com.apple.remotemanagement" OR process == "screensharingd" OR process == "ARDAgent"' \
        --last "${DAYS_BACK}d" --style compact 2>/dev/null | head -500 > "$OUTDIR/raw/_remote_access.txt" || true

    local remote_count=$(wc -l < "$OUTDIR/raw/_remote_access.txt" 2>/dev/null || echo 0)
    if [ "$remote_count" -gt 10 ]; then
        warn "Remote access activity: $remote_count entries"
    fi

    info "Initial access analysis → phases/01_initial_access.txt"
}

# ============================================================
# PHASE 2: EXECUTION (TA0002)
# What did the attacker run?
# ============================================================
phase_execution() {
    hdr "[PHASE 2/12] EXECUTION (TA0002)"
    local report="$OUTDIR/phases/02_execution.txt"
    echo "PHASE 2: EXECUTION" > "$report"

    # --- 2a. PowerShell execution ---
    info "Scanning PowerShell execution..."
    log_show --predicate 'process == "pwsh" OR process == "powershell"' \
        --last "${DAYS_BACK}d" --style compact 2>/dev/null | while read -r line; do
        ts=$(echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
        [ -z "$ts" ] && continue
        tl "$ts" "HIGH" "Execution" "T1059.001 PowerShell" "unified_log" "PowerShell: $(echo "$line" | cut -c1-300)"
        echo "$line" >> "$report"
    done

    # --- 2b. osascript (AppleScript) execution ---
    info "Scanning AppleScript execution..."
    log_show --predicate 'process == "osascript"' \
        --last "${DAYS_BACK}d" --style compact 2>/dev/null | while read -r line; do
        ts=$(echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
        [ -z "$ts" ] && continue
        tl "$ts" "MEDIUM" "Execution" "T1059.002 AppleScript" "unified_log" "osascript: $(echo "$line" | cut -c1-300)"
        echo "$line" >> "$report"
    done

    # --- 2c. Shell commands via unified log ---
    info "Scanning suspicious shell execution..."
    log_show --predicate '(process == "bash" OR process == "zsh" OR process == "sh") AND (eventMessage CONTAINS "curl" OR eventMessage CONTAINS "wget" OR eventMessage CONTAINS "python" OR eventMessage CONTAINS "base64" OR eventMessage CONTAINS "eval" OR eventMessage CONTAINS "nc " OR eventMessage CONTAINS "ncat")' \
        --last "${DAYS_BACK}d" --style compact 2>/dev/null | head -2000 | while read -r line; do
        ts=$(echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
        [ -z "$ts" ] && continue
        tl "$ts" "HIGH" "Execution" "T1059.004 Unix Shell" "unified_log" "Shell cmd: $(echo "$line" | cut -c1-300)"
        echo "$line" >> "$report"
    done

    # --- 2d. Shell history (timestamped entries) ---
    info "Extracting shell history with timestamps..."
    for hf in "$HOME/.zsh_history" "$HOME/.bash_history"; do
        [ -f "$hf" ] || continue
        echo "=== $hf ===" >> "$report"

        # zsh_history has format: : timestamp:0;command
        if [ "$(basename "$hf")" = ".zsh_history" ]; then
            grep -E "^: [0-9]+:" "$hf" 2>/dev/null | while IFS= read -r entry; do
                epoch=$(echo "$entry" | sed -E 's/^: ([0-9]+):.*/\1/')
                cmd=$(echo "$entry" | sed -E 's/^: [0-9]+:[0-9]+;//')
                ts=$(date -r "$epoch" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "UNKNOWN")

                echo "[$ts] $cmd" >> "$report"

                # Classify commands
                if echo "$cmd" | grep -qiE "curl.*\|.*sh|wget.*\|.*sh|python.*-c.*import|base64.*-d|openssl.*enc"; then
                    tl "$ts" "CRITICAL" "Execution" "T1059.004 Unix Shell" "zsh_history" "Suspicious cmd: $cmd"
                elif echo "$cmd" | grep -qiE "curl|wget|python.*http|nc -|ncat|socat|reverse|nova|beacon|payload"; then
                    tl "$ts" "HIGH" "Execution" "T1059.004 Unix Shell" "zsh_history" "Interesting cmd: $cmd"
                elif echo "$cmd" | grep -qiE "chmod|chown|sudo|su -|dscl|security|defaults write|launchctl|networksetup|spctl|csrutil|mdatp|pfctl"; then
                    tl "$ts" "MEDIUM" "Execution" "T1059.004 Unix Shell" "zsh_history" "Admin cmd: $cmd"
                fi
            done
        else
            # bash_history has no timestamps, use file mtime as approximate
            file_ts=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$hf" 2>/dev/null || echo "UNKNOWN")
            grep -inE "curl|wget|python|base64|eval|nc |ncat|socat|reverse|nova|beacon|chmod|sudo|launchctl|defaults|security|mdatp|osascript|ssh|scp" "$hf" 2>/dev/null | while IFS=: read -r linenum cmd; do
                tl "$file_ts" "MEDIUM" "Execution" "T1059.004 Unix Shell" "bash_history:L$linenum" "Cmd: $cmd"
                echo "[~$file_ts L:$linenum] $cmd" >> "$report"
            done
        fi
    done

    # --- 2e. Detect wiped history (anti-forensics) ---
    for hf in "$HOME/.zsh_history" "$HOME/.bash_history"; do
        if [ -f "$hf" ]; then
            lines=$(wc -l < "$hf")
            if [ "$lines" -lt 5 ]; then
                ts=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$hf" 2>/dev/null || echo "UNKNOWN")
                tl "$ts" "CRITICAL" "Defense Evasion" "T1070.003 Clear Command History" "filesystem" "History file nearly empty ($lines lines): $hf"
                crit "Shell history wiped: $hf ($lines lines)"
            fi
        fi
    done

    info "Execution analysis → phases/02_execution.txt"
}

# ============================================================
# PHASE 3: PERSISTENCE (TA0003)
# ============================================================
phase_persistence() {
    hdr "[PHASE 3/12] PERSISTENCE (TA0003)"
    local report="$OUTDIR/phases/03_persistence.txt"
    echo "PHASE 3: PERSISTENCE" > "$report"

    # --- 3a. LaunchAgents & LaunchDaemons ---
    info "Scanning LaunchAgents/Daemons..."
    for dir in "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
        [ -d "$dir" ] || continue
        for plist in "$dir"/*.plist 2>/dev/null; do
            [ -f "$plist" ] || continue
            ts=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$plist" 2>/dev/null || echo "UNKNOWN")
            label=$(defaults read "$plist" Label 2>/dev/null || basename "$plist")
            prog=$(defaults read "$plist" ProgramArguments 2>/dev/null || plutil -p "$plist" 2>/dev/null | grep -A5 ProgramArguments)

            echo "[$ts] $plist" >> "$report"
            echo "  Label: $label" >> "$report"
            echo "  Program: $prog" >> "$report"
            plutil -p "$plist" >> "$report" 2>/dev/null
            echo "---" >> "$report"

            # Flag non-Apple entries
            if ! echo "$plist" | grep -qE "com\.apple\." ; then
                severity="MEDIUM"
                technique="T1543.004 Launch Agent/Daemon"

                # Escalate if suspicious binary paths
                if echo "$prog" | grep -qiE "/tmp|/var/tmp|curl|wget|python|bash|sh|nc|hidden|cache.*bin|nova|beacon|payload|reverse|\.app/.*MacOS"; then
                    severity="CRITICAL"
                    crit "SUSPICIOUS persistence: $plist → $prog"
                else
                    warn "Non-Apple persistence: $plist"
                fi

                tl "$ts" "$severity" "Persistence" "$technique" "launch_plist" "$label → $prog ($plist)"
            fi
        done
    done

    # --- 3b. Cron jobs ---
    info "Checking cron jobs..."
    local cron_out=$(crontab -l 2>/dev/null || true)
    if [ -n "$cron_out" ]; then
        echo "=== Current user crontab ===" >> "$report"
        echo "$cron_out" >> "$report"
        ts=$(date '+%Y-%m-%d %H:%M:%S')
        tl "$ts" "MEDIUM" "Persistence" "T1053.003 Cron" "crontab" "Active cron entries found"
    fi

    for user_cron in /usr/lib/cron/tabs/* /var/at/tabs/*; do
        [ -f "$user_cron" ] || continue
        ts=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$user_cron" 2>/dev/null || echo "UNKNOWN")
        echo "=== $user_cron ===" >> "$report"
        cat "$user_cron" >> "$report" 2>/dev/null
        tl "$ts" "MEDIUM" "Persistence" "T1053.003 Cron" "cron_tabs" "Cron file: $user_cron"
    done

    # --- 3c. Login items ---
    info "Checking login items..."
    echo "=== Login Items ===" >> "$report"
    osascript -e 'tell application "System Events" to get the name of every login item' >> "$report" 2>/dev/null || true

    # --- 3d. RC file backdoors ---
    info "Checking RC files for injection..."
    for rc in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zprofile" "$HOME/.zshenv" "$HOME/.zlogin"; do
        [ -f "$rc" ] || continue
        ts=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$rc" 2>/dev/null || echo "UNKNOWN")

        suspicious=$(grep -nE "curl|wget|python.*http|eval.*\(|base64|nc |ncat|reverse|hidden|nova|beacon|/dev/tcp|exec [0-9]" "$rc" 2>/dev/null || true)
        if [ -n "$suspicious" ]; then
            crit "RC file backdoor in $rc"
            echo "*** SUSPICIOUS in $rc ***" >> "$report"
            echo "$suspicious" >> "$report"
            tl "$ts" "CRITICAL" "Persistence" "T1546.004 Unix Shell Config" "rc_files" "Backdoor in $rc: $suspicious"
        fi
    done

    # --- 3e. Kernel extensions ---
    info "Checking kernel extensions..."
    echo "=== Non-Apple Kexts ===" >> "$report"
    kextstat 2>/dev/null | grep -v "com.apple" | while read -r line; do
        tl "UNKNOWN" "MEDIUM" "Persistence" "T1547.006 Kernel Modules" "kextstat" "Non-Apple kext: $line"
        echo "$line" >> "$report"
    done

    # --- 3f. Authorization plugins ---
    info "Checking auth plugins..."
    for plugin in /Library/Security/SecurityAgentPlugins/*; do
        [ -e "$plugin" ] || continue
        ts=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$plugin" 2>/dev/null || echo "UNKNOWN")
        tl "$ts" "HIGH" "Persistence" "T1547.002 Auth Plugins" "filesystem" "Auth plugin: $plugin"
        warn "Authorization plugin: $plugin"
        echo "[$ts] $plugin" >> "$report"
    done

    # --- 3g. Configuration profiles ---
    info "Checking MDM/config profiles..."
    echo "=== Configuration Profiles ===" >> "$report"
    profiles list 2>/dev/null >> "$report" || true

    # --- 3h. emond rules ---
    for rule in /etc/emond.d/rules/*; do
        [ -f "$rule" ] || continue
        ts=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$rule" 2>/dev/null || echo "UNKNOWN")
        tl "$ts" "HIGH" "Persistence" "T1546 Event Triggered" "emond" "emond rule: $rule"
        crit "emond persistence rule: $rule"
    done

    info "Persistence analysis → phases/03_persistence.txt"
}

# ============================================================
# PHASE 4: PRIVILEGE ESCALATION (TA0004)
# ============================================================
phase_privesc() {
    hdr "[PHASE 4/12] PRIVILEGE ESCALATION (TA0004)"
    local report="$OUTDIR/phases/04_privilege_escalation.txt"
    echo "PHASE 4: PRIVILEGE ESCALATION" > "$report"

    # --- 4a. sudo usage ---
    info "Scanning sudo usage..."
    log_show --predicate 'process == "sudo"' \
        --last "${DAYS_BACK}d" --style compact 2>/dev/null | while read -r line; do
        ts=$(echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
        [ -z "$ts" ] && continue
        if echo "$line" | grep -qi "COMMAND\|executed"; then
            tl "$ts" "MEDIUM" "Privilege Escalation" "T1548.003 Sudo" "sudo_log" "$(echo "$line" | cut -c1-300)"
        fi
        echo "$line" >> "$report"
    done

    # --- 4b. TCC/FDA grants (privacy escalation) ---
    info "Scanning TCC permission grants..."
    for tcc_db in "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "/Library/Application Support/com.apple.TCC/TCC.db"; do
        [ -f "$tcc_db" ] || continue
        sqlite3 "$tcc_db" \
            "SELECT datetime(last_modified,'unixepoch') as ts, service, client, auth_value
             FROM access WHERE auth_value = 2
             ORDER BY last_modified DESC;" 2>/dev/null | while IFS='|' read -r ts service client auth; do
            echo "[$ts] GRANTED: $service → $client" >> "$report"

            case "$service" in
                kTCCServiceSystemPolicyAllFiles)
                    tl "$ts" "HIGH" "Privilege Escalation" "T1548 Abuse Elevation" "tcc_db" "Full Disk Access granted to: $client"
                    warn "FDA granted: $client" ;;
                kTCCServiceAccessibility)
                    tl "$ts" "HIGH" "Privilege Escalation" "T1548 Abuse Elevation" "tcc_db" "Accessibility granted to: $client"
                    warn "Accessibility granted: $client" ;;
                kTCCServiceScreenCapture)
                    tl "$ts" "MEDIUM" "Collection" "T1113 Screen Capture" "tcc_db" "Screen capture granted to: $client" ;;
                kTCCServiceMicrophone|kTCCServiceCamera)
                    tl "$ts" "MEDIUM" "Collection" "T1123 Audio/Video Capture" "tcc_db" "$service granted to: $client" ;;
            esac
        done
    done

    # --- 4c. SIP status ---
    info "Checking SIP status..."
    local sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    echo "SIP: $sip_status" >> "$report"
    if echo "$sip_status" | grep -qi "disabled"; then
        tl "UNKNOWN" "CRITICAL" "Privilege Escalation" "T1548 Abuse Elevation" "csrutil" "SIP is DISABLED"
        crit "SIP is DISABLED — full system compromise possible"
    fi

    # --- 4d. User added to admin group ---
    info "Checking admin group changes..."
    log_show --predicate 'subsystem == "com.apple.opendirectoryd" AND eventMessage CONTAINS "admin"' \
        --last "${DAYS_BACK}d" --style compact 2>/dev/null | while read -r line; do
        ts=$(echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
        [ -z "$ts" ] && continue
        tl "$ts" "HIGH" "Privilege Escalation" "T1078 Valid Accounts" "opendirectoryd" "Admin group change: $(echo "$line" | cut -c1-200)"
        echo "$line" >> "$report"
    done

    # --- 4e. SUID/SGID binaries in unusual locations ---
    info "Scanning for suspicious SUID binaries..."
    find /tmp /var/tmp /Users -perm -4000 -type f 2>/dev/null | while read -r f; do
        ts=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$f" 2>/dev/null || echo "UNKNOWN")
        tl "$ts" "CRITICAL" "Privilege Escalation" "T1548.001 SUID/SGID" "filesystem" "SUID binary: $f"
        crit "SUID binary in unusual location: $f"
        echo "[$ts] $f" >> "$report"
    done

    info "Privilege escalation → phases/04_privilege_escalation.txt"
}

# ============================================================
# PHASE 5: DEFENSE EVASION (TA0005)
# ============================================================
phase_defense_evasion() {
    hdr "[PHASE 5/12] DEFENSE EVASION (TA0005)"
    local report="$OUTDIR/phases/05_defense_evasion.txt"
    echo "PHASE 5: DEFENSE EVASION" > "$report"

    # --- 5a. Microsoft Defender tampering (MpPreference equivalent on macOS) ---
    info "Checking Microsoft Defender for Endpoint..."
    if command -v mdatp &>/dev/null; then
        # RTP status
        local rtp=$(mdatp health --field real_time_protection_enabled 2>/dev/null || echo "unknown")
        local tamper=$(mdatp health --field tamper_protection 2>/dev/null || echo "unknown")
        local cloud=$(mdatp health --field cloud_enabled 2>/dev/null || echo "unknown")
        local definitions=$(mdatp health --field definitions_updated 2>/dev/null || echo "unknown")

        echo "=== MDE Health ===" >> "$report"
        mdatp health 2>/dev/null >> "$report"

        if [ "$rtp" = "false" ]; then
            tl "$(date '+%Y-%m-%d %H:%M:%S')" "CRITICAL" "Defense Evasion" "T1562.001 Disable Security Tools" "mdatp" "Real-time Protection DISABLED"
            crit "MDE Real-time Protection is DISABLED!"
        fi

        if [ "$tamper" = "false" ] || [ "$tamper" = "disabled" ]; then
            tl "$(date '+%Y-%m-%d %H:%M:%S')" "CRITICAL" "Defense Evasion" "T1562.001 Disable Security Tools" "mdatp" "Tamper Protection DISABLED"
            crit "MDE Tamper Protection is DISABLED!"
        fi

        # Exclusions (macOS equivalent of MpPreference ExclusionPath)
        echo -e "\n=== MDE Exclusions ===" >> "$report"
        local exclusions=$(mdatp exclusion list 2>/dev/null)
        echo "$exclusions" >> "$report"
        local excl_count=$(echo "$exclusions" | grep -c "." 2>/dev/null || echo 0)
        if [ "$excl_count" -gt 5 ]; then
            tl "$(date '+%Y-%m-%d %H:%M:%S')" "HIGH" "Defense Evasion" "T1562.001 Disable Security Tools" "mdatp" "Suspicious: $excl_count exclusions configured"
            warn "MDE has $excl_count exclusions — check for attacker additions"
        fi

        # Threat history (shows what Defender caught)
        echo -e "\n=== MDE Threat History ===" >> "$report"
        mdatp threat list 2>/dev/null | while read -r line; do
            echo "$line" >> "$report"
            if [ -n "$line" ]; then
                tl "$(date '+%Y-%m-%d %H:%M:%S')" "HIGH" "Defense Evasion" "T1562 Impair Defenses" "mdatp_threats" "Threat: $line"
            fi
        done

        # MDE logs for tampering
        local mde_log_dir="/Library/Logs/Microsoft/mdatp"
        if [ -d "$mde_log_dir" ]; then
            echo -e "\n=== MDE Log Tampering Evidence ===" >> "$report"
            grep -riE "exclusion|disabled|tamper|bypass|policy.*change|realtime.*off|Set-MpPreference|MpPreference" "$mde_log_dir"/*.log 2>/dev/null | tail -100 | while read -r line; do
                tl "UNKNOWN" "HIGH" "Defense Evasion" "T1562.001 Disable Security Tools" "mde_logs" "MDE log: $(echo "$line" | cut -c1-300)"
                echo "$line" >> "$report"
            done
        fi
    else
        info "mdatp not installed — skipping MDE checks"
    fi

    # --- 5b. XProtect / Gatekeeper bypass ---
    info "Checking XProtect/Gatekeeper events..."
    log_show --predicate 'subsystem == "com.apple.xprotect" OR subsystem == "com.apple.gatekeeper" OR subsystem == "com.apple.MRT"' \
        --last "${DAYS_BACK}d" --style compact 2>/dev/null | while read -r line; do
        ts=$(echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
        [ -z "$ts" ] && continue
        if echo "$line" | grep -qiE "blocked\|denied\|quarantine\|malware\|threat"; then
            tl "$ts" "HIGH" "Defense Evasion" "T1553 Subvert Trust" "xprotect" "$(echo "$line" | cut -c1-300)"
        fi
        echo "$line" >> "$report"
    done

    # Gatekeeper override
    local gk_status=$(spctl --status 2>/dev/null || echo "unknown")
    echo "Gatekeeper: $gk_status" >> "$report"
    if echo "$gk_status" | grep -qi "disabled"; then
        tl "UNKNOWN" "CRITICAL" "Defense Evasion" "T1553.001 Gatekeeper Bypass" "spctl" "Gatekeeper is DISABLED"
        crit "Gatekeeper is DISABLED!"
    fi

    # --- 5c. Quarantine flag removal (xattr -d) ---
    info "Checking for quarantine flag removal in logs..."
    log_show --predicate 'eventMessage CONTAINS "xattr" AND eventMessage CONTAINS "quarantine"' \
        --last "${DAYS_BACK}d" --style compact 2>/dev/null | while read -r line; do
        ts=$(echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
        [ -z "$ts" ] && continue
        tl "$ts" "HIGH" "Defense Evasion" "T1553.001 Gatekeeper Bypass" "unified_log" "Quarantine removed: $(echo "$line" | cut -c1-200)"
        echo "$line" >> "$report"
    done

    # In shell history
    for hf in "$HOME/.zsh_history" "$HOME/.bash_history"; do
        [ -f "$hf" ] || continue
        grep -n "xattr.*-d.*quarantine\|xattr.*-cr\|spctl.*--master-disable\|csrutil.*disable" "$hf" 2>/dev/null | while IFS=: read -r linenum cmd; do
            tl "UNKNOWN" "CRITICAL" "Defense Evasion" "T1553.001 Gatekeeper Bypass" "shell_history" "History: $cmd"
            crit "Defense evasion in history: $cmd"
            echo "[history L:$linenum] $cmd" >> "$report"
        done
    done

    # --- 5d. Log clearing / timestomping ---
    info "Checking for log clearing..."
    for hf in "$HOME/.zsh_history" "$HOME/.bash_history"; do
        [ -f "$hf" ] || continue
        grep -n "log.*erase\|log.*delete\|rm.*\.log\|rm.*\.asl\|rm.*history\|history.*-c\|unset.*HISTFILE\|HISTSIZE=0" "$hf" 2>/dev/null | while IFS=: read -r linenum cmd; do
            tl "UNKNOWN" "CRITICAL" "Defense Evasion" "T1070 Indicator Removal" "shell_history" "Log clearing: $cmd"
            crit "Log clearing in history: $cmd"
            echo "[history L:$linenum] $cmd" >> "$report"
        done
    done

    # --- 5e. Unsigned/adhoc code ---
    info "Checking for unsigned applications..."
    for app in /Applications/*.app; do
        [ -d "$app" ] || continue
        sig=$(codesign -dv "$app" 2>&1 || true)
        if echo "$sig" | grep -q "code object is not signed\|invalid signature\|adhoc"; then
            ts=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$app" 2>/dev/null || echo "UNKNOWN")
            tl "$ts" "HIGH" "Defense Evasion" "T1553.002 Code Signing" "codesign" "Unsigned/adhoc app: $app"
            warn "Unsigned app: $app"
            echo "[$ts] $app: $sig" >> "$report"
        fi
    done

    info "Defense evasion → phases/05_defense_evasion.txt"
}

# ============================================================
# PHASE 6: CREDENTIAL ACCESS (TA0006)
# ============================================================
phase_credential_access() {
    hdr "[PHASE 6/12] CREDENTIAL ACCESS (TA0006)"
    local report="$OUTDIR/phases/06_credential_access.txt"
    echo "PHASE 6: CREDENTIAL ACCESS" > "$report"

    # --- 6a. Keychain access ---
    info "Scanning keychain access events..."
    log_show --predicate 'subsystem == "com.apple.securityd" AND (eventMessage CONTAINS "unlock" OR eventMessage CONTAINS "authorizationdb" OR eventMessage CONTAINS "SecItem")' \
        --last "${DAYS_BACK}d" --style compact 2>/dev/null | head -1000 | while read -r line; do
        ts=$(echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
        [ -z "$ts" ] && continue
        tl "$ts" "MEDIUM" "Credential Access" "T1555.001 Keychain" "securityd" "$(echo "$line" | cut -c1-200)"
        echo "$line" >> "$report"
    done

    # --- 6b. Security command usage (export, dump, find) ---
    info "Checking for 'security' command abuse..."
    for hf in "$HOME/.zsh_history" "$HOME/.bash_history"; do
        [ -f "$hf" ] || continue
        grep -nE "security find-.*password|security dump-keychain|security export|security unlock-keychain" "$hf" 2>/dev/null | while IFS=: read -r linenum cmd; do
            tl "UNKNOWN" "CRITICAL" "Credential Access" "T1555.001 Keychain" "shell_history" "Keychain dump: $cmd"
            crit "Keychain access in history: $cmd"
            echo "[history L:$linenum] $cmd" >> "$report"
        done
    done

    # --- 6c. SSH key theft ---
    info "Checking SSH key access..."
    for ssh_dir in /Users/*/.ssh; do
        [ -d "$ssh_dir" ] || continue
        for key in "$ssh_dir"/id_*; do
            [ -f "$key" ] || continue
            ts=$(stat -f '%Sa' -t '%Y-%m-%d %H:%M:%S' "$key" 2>/dev/null || echo "UNKNOWN")
            echo "[$ts] Last accessed: $key" >> "$report"
        done
        # Check for unauthorized authorized_keys
        if [ -f "$ssh_dir/authorized_keys" ]; then
            ts=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$ssh_dir/authorized_keys" 2>/dev/null || echo "UNKNOWN")
            tl "$ts" "HIGH" "Credential Access" "T1552.004 SSH Keys" "filesystem" "authorized_keys modified: $ssh_dir/authorized_keys"
            warn "authorized_keys found: $ssh_dir/authorized_keys"
            cat "$ssh_dir/authorized_keys" >> "$report" 2>/dev/null
        fi
    done

    # --- 6d. Cloud credential files ---
    for cred in "$HOME/.aws/credentials" "$HOME/.azure/accessTokens.json" "$HOME/.config/gcloud/credentials.db" "$HOME/.kube/config" "$HOME/.netrc"; do
        if [ -f "$cred" ]; then
            ts=$(stat -f '%Sa' -t '%Y-%m-%d %H:%M:%S' "$cred" 2>/dev/null || echo "UNKNOWN")
            tl "$ts" "HIGH" "Credential Access" "T1552.001 Credentials in Files" "filesystem" "Cloud cred file accessed: $cred"
            warn "Cloud credential: $cred (last accessed $ts)"
            echo "[$ts] $cred" >> "$report"
        fi
    done

    # --- 6e. Browser credential stores ---
    for store in \
        "$HOME/Library/Application Support/Google/Chrome/Default/Login Data" \
        "$HOME/Library/Application Support/Firefox/Profiles/*/logins.json" \
        "$HOME/Library/Cookies/Cookies.binarycookies"; do
        for f in $store; do
            [ -f "$f" ] || continue
            ts=$(stat -f '%Sa' -t '%Y-%m-%d %H:%M:%S' "$f" 2>/dev/null || echo "UNKNOWN")
            tl "$ts" "MEDIUM" "Credential Access" "T1555.003 Browser Credentials" "filesystem" "Browser cred store accessed: $f"
            echo "[$ts] $f" >> "$report"
        done
    done

    info "Credential access → phases/06_credential_access.txt"
}

# ============================================================
# PHASE 7: DISCOVERY (TA0007)
# ============================================================
phase_discovery() {
    hdr "[PHASE 7/12] DISCOVERY (TA0007)"
    local report="$OUTDIR/phases/07_discovery.txt"
    echo "PHASE 7: DISCOVERY" > "$report"

    # Check shell history for recon commands
    for hf in "$HOME/.zsh_history" "$HOME/.bash_history"; do
        [ -f "$hf" ] || continue

        # System info
        grep -nE "^(: [0-9]+:[0-9]+;)?(sw_vers|system_profiler|uname|hostname|id|whoami|groups|dscl.*list.*Users|dscl.*read.*admin|dscacheutil|scutil|networksetup|ifconfig|arp|netstat|lsof -i|nmap|ping|traceroute|dig|nslookup|mount|diskutil|df |du |ls -la /|find / |ps aux|top|launchctl list)" "$hf" 2>/dev/null | while IFS= read -r entry; do
            # Extract timestamp if zsh format
            if echo "$entry" | grep -qE "^: [0-9]+:"; then
                epoch=$(echo "$entry" | sed -E 's/^: ([0-9]+):.*/\1/')
                cmd=$(echo "$entry" | sed -E 's/^: [0-9]+:[0-9]+;//')
                ts=$(date -r "$epoch" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "UNKNOWN")
            else
                linenum=$(echo "$entry" | cut -d: -f1)
                cmd=$(echo "$entry" | cut -d: -f2-)
                ts="UNKNOWN"
            fi
            tl "$ts" "LOW" "Discovery" "T1082 System Info" "shell_history" "Recon: $cmd"
            echo "[$ts] $cmd" >> "$report"
        done

        # Network recon
        grep -nE "^(: [0-9]+:[0-9]+;)?(nmap|masscan|arp -a|netstat -rn|route|dns-sd)" "$hf" 2>/dev/null | while IFS= read -r entry; do
            tl "UNKNOWN" "HIGH" "Discovery" "T1046 Network Scanning" "shell_history" "Network scan: $entry"
            echo "$entry" >> "$report"
        done
    done

    info "Discovery → phases/07_discovery.txt"
}

# ============================================================
# PHASE 8: LATERAL MOVEMENT (TA0008)
# ============================================================
phase_lateral_movement() {
    hdr "[PHASE 8/12] LATERAL MOVEMENT (TA0008)"
    local report="$OUTDIR/phases/08_lateral_movement.txt"
    echo "PHASE 8: LATERAL MOVEMENT" > "$report"

    # SSH outbound
    info "Scanning outbound SSH..."
    log_show --predicate 'process == "ssh" AND eventMessage CONTAINS "Connection to"' \
        --last "${DAYS_BACK}d" --style compact 2>/dev/null | while read -r line; do
        ts=$(echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
        [ -z "$ts" ] && continue
        tl "$ts" "MEDIUM" "Lateral Movement" "T1021.004 SSH" "unified_log" "SSH: $(echo "$line" | cut -c1-200)"
        echo "$line" >> "$report"
    done

    # SCP / rsync
    for hf in "$HOME/.zsh_history" "$HOME/.bash_history"; do
        [ -f "$hf" ] || continue
        grep -nE "scp |rsync |ssh .*@|sftp " "$hf" 2>/dev/null | while IFS=: read -r linenum cmd; do
            tl "UNKNOWN" "MEDIUM" "Lateral Movement" "T1021.004 SSH" "shell_history" "File transfer: $cmd"
            echo "[L:$linenum] $cmd" >> "$report"
        done
    done

    # SMB / network shares
    info "Checking mounted network shares..."
    mount 2>/dev/null | grep -iE "smbfs|nfs|afpfs|cifs" | while read -r line; do
        tl "$(date '+%Y-%m-%d %H:%M:%S')" "MEDIUM" "Lateral Movement" "T1021.002 SMB" "mount" "Network share: $line"
        echo "$line" >> "$report"
    done

    info "Lateral movement → phases/08_lateral_movement.txt"
}

# ============================================================
# PHASE 9: COLLECTION (TA0009)
# ============================================================
phase_collection() {
    hdr "[PHASE 9/12] COLLECTION (TA0009)"
    local report="$OUTDIR/phases/09_collection.txt"
    echo "PHASE 9: COLLECTION" > "$report"

    # Screen capture
    info "Checking screen capture activity..."
    log_show --predicate 'process == "screencapture" OR (subsystem == "com.apple.TCC" AND eventMessage CONTAINS "ScreenCapture")' \
        --last "${DAYS_BACK}d" --style compact 2>/dev/null | while read -r line; do
        ts=$(echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
        [ -z "$ts" ] && continue
        tl "$ts" "MEDIUM" "Collection" "T1113 Screen Capture" "unified_log" "$(echo "$line" | cut -c1-200)"
        echo "$line" >> "$report"
    done

    # Clipboard
    for hf in "$HOME/.zsh_history" "$HOME/.bash_history"; do
        [ -f "$hf" ] || continue
        grep -nE "pbpaste|pbcopy|osascript.*clipboard" "$hf" 2>/dev/null | while IFS=: read -r linenum cmd; do
            tl "UNKNOWN" "MEDIUM" "Collection" "T1115 Clipboard Data" "shell_history" "Clipboard: $cmd"
            echo "[L:$linenum] $cmd" >> "$report"
        done
    done

    # Archive creation (staging for exfil)
    for hf in "$HOME/.zsh_history" "$HOME/.bash_history"; do
        [ -f "$hf" ] || continue
        grep -nE "tar.*czf|zip -r|ditto.*--keepParent|hdiutil create|Compress-Archive" "$hf" 2>/dev/null | while IFS=: read -r linenum cmd; do
            tl "UNKNOWN" "MEDIUM" "Collection" "T1560.001 Archive Data" "shell_history" "Archiving: $cmd"
            echo "[L:$linenum] $cmd" >> "$report"
        done
    done

    info "Collection → phases/09_collection.txt"
}

# ============================================================
# PHASE 10: EXFILTRATION (TA0010)
# ============================================================
phase_exfiltration() {
    hdr "[PHASE 10/12] EXFILTRATION (TA0010)"
    local report="$OUTDIR/phases/10_exfiltration.txt"
    echo "PHASE 10: EXFILTRATION" > "$report"

    # Large outbound transfers
    info "Checking for data exfiltration patterns..."
    for hf in "$HOME/.zsh_history" "$HOME/.bash_history"; do
        [ -f "$hf" ] || continue
        grep -nE "curl.*-X POST|curl.*--upload|curl.*-F.*file|wget.*--post|scp.*@.*:|rsync.*@.*:|aws s3 cp|gsutil cp|azcopy|rclone|mega-put|dropbox_uploader" "$hf" 2>/dev/null | while IFS=: read -r linenum cmd; do
            tl "UNKNOWN" "HIGH" "Exfiltration" "T1041 C2 Channel Exfil" "shell_history" "Upload cmd: $cmd"
            crit "Potential exfiltration: $cmd"
            echo "[L:$linenum] $cmd" >> "$report"
        done
    done

    # DNS exfil patterns
    for hf in "$HOME/.zsh_history" "$HOME/.bash_history"; do
        [ -f "$hf" ] || continue
        grep -nE "dig.*TXT|nslookup.*-type=TXT|base64.*\|.*dig|base64.*\|.*nslookup" "$hf" 2>/dev/null | while IFS=: read -r linenum cmd; do
            tl "UNKNOWN" "CRITICAL" "Exfiltration" "T1048.003 DNS Exfil" "shell_history" "DNS exfil: $cmd"
            crit "Possible DNS exfiltration: $cmd"
            echo "[L:$linenum] $cmd" >> "$report"
        done
    done

    info "Exfiltration → phases/10_exfiltration.txt"
}

# ============================================================
# PHASE 11: COMMAND & CONTROL (TA0011)
# ============================================================
phase_c2() {
    hdr "[PHASE 11/12] COMMAND & CONTROL (TA0011)"
    local report="$OUTDIR/phases/11_c2.txt"
    echo "PHASE 11: COMMAND & CONTROL" > "$report"

    # --- Current active connections ---
    info "Analyzing active network connections..."
    echo "=== Active ESTABLISHED connections ===" >> "$report"

    local c2_ports="4444|5555|8443|8080|9090|1337|31337|6666|6667|4443|2222|3333|7777|9999|1234|4321|5678|13337"

    lsof -i -n -P 2>/dev/null | grep -E "ESTABLISHED|SYN_SENT" | while read -r line; do
        echo "$line" >> "$report"
        proc=$(echo "$line" | awk '{print $1}')
        port=$(echo "$line" | grep -oE ':[0-9]+$' | tr -d ':')

        # Check C2 ports
        if echo "$port" | grep -qE "^($c2_ports)$"; then
            tl "$(date '+%Y-%m-%d %H:%M:%S')" "CRITICAL" "Command and Control" "T1571 Non-Standard Port" "lsof" "C2 port connection: $line"
            crit "Connection on C2 port $port: $line"
        fi

        # Check suspicious processes with outbound connections
        if echo "$proc" | grep -qiE "python|ruby|perl|nc|ncat|socat|curl|wget|bash|sh|zsh|pwsh|powershell|osascript"; then
            tl "$(date '+%Y-%m-%d %H:%M:%S')" "HIGH" "Command and Control" "T1059 Scripting" "lsof" "Scripting engine with network: $line"
        fi
    done

    # --- Listening ports (reverse shell listeners) ---
    echo -e "\n=== Listening Ports ===" >> "$report"
    lsof -i -n -P 2>/dev/null | grep LISTEN | while read -r line; do
        proc=$(echo "$line" | awk '{print $1}')
        port=$(echo "$line" | grep -oE ':\*:[0-9]+' | tr -d ':*')
        [ -z "$port" ] && port=$(echo "$line" | grep -oE ':[0-9]+ \(LISTEN\)' | grep -oE '[0-9]+')

        echo "$line" >> "$report"
        if echo "$port" | grep -qE "^($c2_ports)$"; then
            tl "$(date '+%Y-%m-%d %H:%M:%S')" "CRITICAL" "Command and Control" "T1571 Non-Standard Port" "lsof" "Listening on C2 port: $line"
            crit "Listening on suspicious port $port: $proc"
        fi
    done

    # --- Suspicious DNS queries (if mDNSResponder logs available) ---
    info "Checking DNS query logs..."
    log_show --predicate 'process == "mDNSResponder" AND (eventMessage CONTAINS "query" OR eventMessage CONTAINS "response")' \
        --last 1d --style compact 2>/dev/null | grep -iE "\.xyz|\.top|\.tk|\.ml|\.ga|\.cf|duckdns|ngrok|serveo|portmap|pagekite|burp|interact\.sh|oast" | head -100 | while read -r line; do
        ts=$(echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
        [ -z "$ts" ] && continue
        tl "$ts" "HIGH" "Command and Control" "T1071.004 DNS C2" "mDNSResponder" "Suspicious DNS: $(echo "$line" | cut -c1-200)"
        echo "$line" >> "$report"
    done

    info "C2 analysis → phases/11_c2.txt"
}

# ============================================================
# PHASE 12: IMPACT (TA0040)
# ============================================================
phase_impact() {
    hdr "[PHASE 12/12] IMPACT (TA0040)"
    local report="$OUTDIR/phases/12_impact.txt"
    echo "PHASE 12: IMPACT" > "$report"

    # Ransomware indicators
    info "Checking for ransomware/destruction indicators..."
    find /Users -maxdepth 4 -name "*.encrypted" -o -name "*.locked" -o -name "*.crypt" -o -name "README_DECRYPT*" -o -name "HOW_TO_RECOVER*" -o -name "RANSOM*" 2>/dev/null | while read -r f; do
        ts=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$f" 2>/dev/null || echo "UNKNOWN")
        tl "$ts" "CRITICAL" "Impact" "T1486 Data Encrypted" "filesystem" "Ransomware indicator: $f"
        crit "Ransomware indicator: $f"
        echo "[$ts] $f" >> "$report"
    done

    # Mass file deletion
    for hf in "$HOME/.zsh_history" "$HOME/.bash_history"; do
        [ -f "$hf" ] || continue
        grep -nE "rm -rf /|rm -rf ~/|srm|shred|diskutil erase|dd if=/dev/zero|dd if=/dev/urandom" "$hf" 2>/dev/null | while IFS=: read -r linenum cmd; do
            tl "UNKNOWN" "CRITICAL" "Impact" "T1485 Data Destruction" "shell_history" "Destruction: $cmd"
            crit "Data destruction in history: $cmd"
            echo "[L:$linenum] $cmd" >> "$report"
        done
    done

    # Cryptominer
    local miners=$(ps aux 2>/dev/null | grep -iE "xmrig|minerd|minergate|cryptonight|stratum\+tcp|hashrate" | grep -v grep || true)
    if [ -n "$miners" ]; then
        tl "$(date '+%Y-%m-%d %H:%M:%S')" "HIGH" "Impact" "T1496 Resource Hijacking" "processes" "Cryptominer: $miners"
        crit "Cryptominer running!"
        echo "$miners" >> "$report"
    fi

    info "Impact → phases/12_impact.txt"
}

# ============================================================
# BUILD FINAL TIMELINE
# ============================================================
build_timeline() {
    hdr "BUILDING UNIFIED ATTACK TIMELINE"

    # Sort by timestamp
    sort -t$'\t' -k1,1 "$TIMELINE_RAW" > "$OUTDIR/raw/_timeline_sorted.tsv"

    # Generate the readable timeline
    {
        echo "============================================================"
        echo "  ATTACK TIMELINE — $(hostname)"
        echo "  Generated: $(date)"
        echo "  Scope: Last ${DAYS_BACK} days"
        echo "============================================================"
        echo ""
        echo "SEVERITY LEGEND:  [!!!] CRITICAL  [!!] HIGH  [!] MEDIUM  [.] LOW/INFO"
        echo ""
        echo "============================================================"
        echo ""

        local prev_date=""
        while IFS=$'\t' read -r ts sev tactic technique source detail; do
            # Date separator
            local cur_date=$(echo "$ts" | cut -d' ' -f1)
            if [ "$cur_date" != "$prev_date" ] && [ -n "$cur_date" ] && [ "$cur_date" != "UNKNOWN" ]; then
                echo ""
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "  📅 $cur_date"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                prev_date="$cur_date"
            fi

            # Severity marker
            local marker="[.]"
            case "$sev" in
                CRITICAL) marker="[!!!]" ;;
                HIGH)     marker="[!! ]" ;;
                MEDIUM)   marker="[ ! ]" ;;
                LOW)      marker="[ . ]" ;;
                INFO)     marker="[   ]" ;;
            esac

            # Format: MARKER TIME | TACTIC > TECHNIQUE | SOURCE | detail
            local time_part=$(echo "$ts" | awk '{print $2}')
            [ -z "$time_part" ] && time_part="??:??:??"

            printf "%s %s | %-22s > %-35s | %-15s | %s\n" \
                "$marker" "$time_part" "$tactic" "$technique" "$source" "$detail"

        done < "$OUTDIR/raw/_timeline_sorted.tsv"

        echo ""
        echo "============================================================"
        echo "  END OF TIMELINE"
        echo "  Total events: $(wc -l < "$OUTDIR/raw/_timeline_sorted.tsv")"
        echo "  Critical:     $(grep -c 'CRITICAL' "$OUTDIR/raw/_timeline_sorted.tsv" || echo 0)"
        echo "  High:         $(grep -c 'HIGH' "$OUTDIR/raw/_timeline_sorted.tsv" || echo 0)"
        echo "============================================================"
    } > "$TIMELINE_FINAL"

    # Also generate CSV for import into SIEM / spreadsheet
    {
        echo "Timestamp,Severity,MITRE_Tactic,MITRE_Technique,Source,Details"
        while IFS=$'\t' read -r ts sev tactic technique source detail; do
            # Escape commas in detail
            detail=$(echo "$detail" | sed 's/,/;/g' | cut -c1-500)
            echo "\"$ts\",\"$sev\",\"$tactic\",\"$technique\",\"$source\",\"$detail\""
        done < "$OUTDIR/raw/_timeline_sorted.tsv"
    } > "$TIMELINE_CSV"

    # Generate phase summary
    local phase_summary="$OUTDIR/PHASE_SUMMARY.txt"
    {
        echo "============================================================"
        echo "  MITRE ATT&CK PHASE SUMMARY"
        echo "============================================================"
        echo ""
        for tactic in "Initial Access" "Execution" "Persistence" "Privilege Escalation" "Defense Evasion" "Credential Access" "Discovery" "Lateral Movement" "Collection" "Exfiltration" "Command and Control" "Impact"; do
            total=$(grep -c "$tactic" "$OUTDIR/raw/_timeline_sorted.tsv" 2>/dev/null || echo 0)
            crits=$(grep "$tactic" "$OUTDIR/raw/_timeline_sorted.tsv" 2>/dev/null | grep -c "CRITICAL" || echo 0)
            highs=$(grep "$tactic" "$OUTDIR/raw/_timeline_sorted.tsv" 2>/dev/null | grep -c "HIGH" || echo 0)

            local bar=""
            for ((i=0; i<total && i<50; i++)); do bar+="█"; done

            printf "  %-25s %4d events (%d crit, %d high) %s\n" "$tactic" "$total" "$crits" "$highs" "$bar"
        done
    } > "$phase_summary"

    cat "$phase_summary" | tee -a "$LOGFILE"

    info ""
    info "Timeline events: $(wc -l < "$OUTDIR/raw/_timeline_sorted.tsv")"
}

# ============================================================
# FINAL SUMMARY
# ============================================================
final_summary() {
    log ""
    log "${BLD}${CYN}============================================================${NC}"
    log "${BLD}${CYN}  SCAN COMPLETE${NC}"
    log "${BLD}${CYN}============================================================${NC}"
    log ""
    log "  ${BLD}Total findings: ${FINDINGS}${NC}"
    if [ "$CRITICAL" -gt 0 ]; then
        log "  ${RED}Critical:       ${CRITICAL}${NC}"
    fi
    log ""
    log "  ${BLD}${YEL}📋 KEY FILES — READ IN THIS ORDER:${NC}"
    log ""
    log "    1. ${RED}ATTACK_TIMELINE.txt${NC}          — Full chronological attack narrative"
    log "    2. ${RED}PHASE_SUMMARY.txt${NC}            — MITRE ATT&CK heatmap"
    log "    3. ${RED}ATTACK_TIMELINE.csv${NC}          — Import into SIEM/Excel/Splunk"
    log ""
    log "  ${BLD}${YEL}📁 PHASE DETAILS:${NC}"
    log "    phases/01_initial_access.txt       — How they got in"
    log "    phases/02_execution.txt            — What they ran"
    log "    phases/03_persistence.txt          — How they stayed"
    log "    phases/04_privilege_escalation.txt  — How they escalated"
    log "    phases/05_defense_evasion.txt       — How they hid (MDE/Defender tampering)"
    log "    phases/06_credential_access.txt     — What creds they stole"
    log "    phases/07_discovery.txt             — What they mapped"
    log "    phases/08_lateral_movement.txt      — Where they moved"
    log "    phases/09_collection.txt            — What they gathered"
    log "    phases/10_exfiltration.txt          — What they exfiltrated"
    log "    phases/11_c2.txt                    — How they communicated"
    log "    phases/12_impact.txt                — What damage they did"
    log ""
    log "  ${BLD}Tip: Import ATTACK_TIMELINE.csv into your SIEM for correlation${NC}"
    log ""
}

# ============================================================
# MAIN
# ============================================================
banner
phase_initial_access
phase_execution
phase_persistence
phase_privesc
phase_defense_evasion
phase_credential_access
phase_discovery
phase_lateral_movement
phase_collection
phase_exfiltration
phase_c2
phase_impact
build_timeline
final_summary
