#!/bin/bash
#=============================================================================
# EVTX Forensic Analyzer v2 — ATTACK TIMELINE EDITION (libevtx-utils)
# Uses ONLY evtxexport & evtxinfo — no Python dependencies
#
# Reconstructs attack kill chain using MITRE ATT&CK phases:
#   1. Initial Access  2. Execution  3. Persistence  4. Priv Escalation
#   5. Defense Evasion  6. Credential Access  7. Discovery  8. Lateral Movement
#   9. Collection  10. Exfiltration  11. C2  12. Impact
#
# All events → single chronological timeline + CSV for SIEM import
# Usage: sudo ./evtx_attack_timeline.sh /path/to/evtx/files
#=============================================================================
set -uo pipefail

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; CYN='\033[0;36m'
MAG='\033[0;35m'; BLD='\033[1m'; NC='\033[0m'

EVTX_DIR="${1:-.}"
OUTDIR="./evtx_attack_timeline_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR/xml_exports" "$OUTDIR/phases" "$OUTDIR/raw"

LOGFILE="$OUTDIR/00_scan_log.txt"
TL_RAW="$OUTDIR/raw/_timeline_unsorted.tsv"
TL_FINAL="$OUTDIR/ATTACK_TIMELINE.txt"
TL_CSV="$OUTDIR/ATTACK_TIMELINE.csv"
FINDINGS=0; CRITICAL=0
> "$TL_RAW"

log()  { echo -e "$1" | tee -a "$LOGFILE"; }
hdr()  { log "\n${BLD}${CYN}$1${NC}"; }
warn() { log "  ${YEL}[!] $1${NC}"; FINDINGS=$((FINDINGS+1)); }
crit() { log "  ${RED}[!!!] $1${NC}"; FINDINGS=$((FINDINGS+1)); CRITICAL=$((CRITICAL+1)); }
ok()   { log "  ${GRN}[✓] $1${NC}"; }
info() { log "  $1"; }

tl() {
    local ts="${1:-UNKNOWN}" sev="${2:-INFO}" tactic="${3:-Unknown}" tech="${4:-}" src="${5:-}" det="${6:-}"
    det=$(echo "$det" | tr '\t\n\r' '   ' | cut -c1-500)
    printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$ts" "$sev" "$tactic" "$tech" "$src" "$det" >> "$TL_RAW"
}

# Extract timestamp/eventid/user/computer from XML near a line
ectx() {
    local xf="$1" ln="$2"
    local s=$((ln - 30)); [ "$s" -lt 1 ] && s=1
    local blk=$(sed -n "${s},$((ln+5))p" "$xf" 2>/dev/null)
    _TS=$(echo "$blk" | grep -oP 'SystemTime="\K[^"]+' 2>/dev/null | tail -1 || true)
    [ -z "$_TS" ] && _TS=$(echo "$blk" | grep -o 'SystemTime="[^"]*"' | tail -1 | sed 's/SystemTime="//;s/"//' 2>/dev/null || true)
    [ -z "$_TS" ] && _TS="UNKNOWN"
    _EID=$(echo "$blk" | grep -oP '<EventID[^>]*>\K[^<]+' 2>/dev/null | tail -1 || true)
    [ -z "$_EID" ] && _EID=$(echo "$blk" | grep '<EventID' | sed -E 's/.*>([0-9]+)<.*/\1/' | tail -1 2>/dev/null || true)
    [ -z "$_EID" ] && _EID="?"
    _USER=$(echo "$blk" | grep -oP 'TargetUserName">\K[^<]+' 2>/dev/null | tail -1 || true)
    [ -z "$_USER" ] && _USER=$(echo "$blk" | grep -oP 'SubjectUserName">\K[^<]+' 2>/dev/null | tail -1 || true)
}

banner() {
    log "${BLD}${CYN}================================================================${NC}"
    log "${BLD}${CYN}  EVTX ATTACK TIMELINE ANALYZER v2 (libevtx-utils only)        ${NC}"
    log "${BLD}${CYN}  MITRE ATT&CK Kill Chain Reconstruction                       ${NC}"
    log "${BLD}${CYN}================================================================${NC}"
    log "  Target: $EVTX_DIR | Output: $OUTDIR | $(date)"
    log ""
}

preflight() {
    for cmd in evtxexport evtxinfo grep awk sed sort; do
        command -v "$cmd" &>/dev/null || { log "${RED}Missing: $cmd${NC}"; exit 1; }
    done
}

step_inventory() {
    hdr "[1/4] Inventory (evtxinfo)"
    local c=0; local rpt="$OUTDIR/01_inventory.txt"
    echo "EVTX INVENTORY — $(date)" > "$rpt"
    while IFS= read -r -d '' f; do
        c=$((c+1)); local fn=$(basename "$f"); local sz=$(ls -lh "$f" | awk '{print $5}')
        echo "[$c] $fn ($sz)" >> "$rpt"; evtxinfo "$f" >> "$rpt" 2>/dev/null; echo "" >> "$rpt"
        info "[$c] $fn ($sz)"
    done < <(find "$EVTX_DIR" -iname "*.evtx" -print0 2>/dev/null | sort -z)
    [ "$c" -eq 0 ] && { log "${RED}No .evtx files found${NC}"; exit 1; }
    log "  ${BLD}Total: $c files${NC}"
}

step_export() {
    hdr "[2/4] Exporting EVTX → XML"
    local i=0
    while IFS= read -r -d '' f; do
        i=$((i+1)); local fn=$(basename "$f" .evtx); fn=$(basename "$fn" .EVTX)
        local ox="$OUTDIR/xml_exports/${fn}.xml"
        echo -ne "  [$i] $fn... "
        evtxexport -f xml -m all "$f" > "$ox" 2>/dev/null
        echo -e "${GRN}$(wc -l < "$ox") lines${NC}"
    done < <(find "$EVTX_DIR" -iname "*.evtx" -print0 2>/dev/null | sort -z)
}

# ============================================================
# PHASE 1: INITIAL ACCESS (TA0001)
# ============================================================
phase_initial_access() {
    log "\n  ${MAG}── Phase 1: Initial Access${NC}"
    local rpt="$OUTDIR/phases/01_initial_access.txt"; local h=0
    echo "PHASE 1: INITIAL ACCESS — How did the attacker get in?" > "$rpt"
    for xf in "$OUTDIR/xml_exports/"*.xml; do [ -f "$xf" ] || continue; local fn=$(basename "$xf")
        # EID 4624: Logon — focus on Type 3(network),10(RDP),8(cleartext)
        grep -n '>4624<' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"
            local blk=$(sed -n "$((ln)),$((ln+40))p" "$xf" 2>/dev/null)
            local lt=$(echo "$blk" | grep -oP 'LogonType">\K[^<]+' 2>/dev/null | head -1)
            local ip=$(echo "$blk" | grep -oP 'IpAddress">\K[^<]+' 2>/dev/null | head -1)
            local u=$(echo "$blk" | grep -oP 'TargetUserName">\K[^<]+' 2>/dev/null | head -1)
            local d=$(echo "$blk" | grep -oP 'TargetDomainName">\K[^<]+' 2>/dev/null | head -1)
            case "$lt" in
                3)  tl "$_TS" "MEDIUM" "Initial Access" "T1078 Valid Accounts" "$fn" "Network logon(3): ${d}\\${u} from ${ip} [4624]" ;;
                10) tl "$_TS" "HIGH" "Initial Access" "T1021.001 RDP" "$fn" "RDP logon(10): ${d}\\${u} from ${ip} [4624]"
                    crit "RDP logon: ${d}\\${u} from ${ip}" ;;
                8)  tl "$_TS" "HIGH" "Initial Access" "T1078 Valid Accounts" "$fn" "Cleartext logon(8): ${d}\\${u} from ${ip} [4624]" ;;
            esac; h=$((h+1))
        done
        # EID 4625: Failed logons (brute force)
        local fc=$(grep -c '>4625<' "$xf" 2>/dev/null || echo 0)
        if [ "$fc" -gt 10 ]; then
            local fl=$(grep -n '>4625<' "$xf" | head -1 | cut -d: -f1)
            [ -n "$fl" ] && ectx "$xf" "$fl"
            tl "$_TS" "HIGH" "Initial Access" "T1110 Brute Force" "$fn" "${fc} failed logons [4625]"
            warn "Brute force: $fc failures in $fn"; h=$((h+1))
        fi
        # EID 4648: Explicit credentials
        grep -n '>4648<' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"
            local blk=$(sed -n "$((ln)),$((ln+30))p" "$xf" 2>/dev/null)
            local ts=$(echo "$blk" | grep -oP 'TargetServerName">\K[^<]+' 2>/dev/null | head -1)
            tl "$_TS" "MEDIUM" "Initial Access" "T1078 Valid Accounts" "$fn" "Explicit creds: $_USER → $ts [4648]"; h=$((h+1))
        done
    done; info "Initial Access: $h events"
}

# ============================================================
# PHASE 2: EXECUTION (TA0002)
# ============================================================
phase_execution() {
    log "\n  ${MAG}── Phase 2: Execution${NC}"
    local rpt="$OUTDIR/phases/02_execution.txt"; local h=0
    echo "PHASE 2: EXECUTION — What did the attacker run?" > "$rpt"
    for xf in "$OUTDIR/xml_exports/"*.xml; do [ -f "$xf" ] || continue; local fn=$(basename "$xf")
        # EID 4104: PowerShell ScriptBlock — THE KEY EVENT
        grep -n '>4104<' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"
            local blk=$(sed -n "$((ln)),$((ln+80))p" "$xf" 2>/dev/null)
            local sc=$(echo "$blk" | grep -oP 'ScriptBlockText">\K[^<]+' 2>/dev/null | head -1)
            [ -z "$sc" ] && sc=$(echo "$blk" | sed -n '/ScriptBlockText/,/<\/Data>/p' | head -5 | tr '\n' ' ')
            local sev="MEDIUM" tech="T1059.001 PowerShell"
            echo "$sc" | grep -qiE "MpPreference|DisableRealtime|ExclusionPath|amsiInitFailed" && { sev="CRITICAL"; tech="T1059.001+T1562.001 PS+DefenderTamper"; }
            echo "$sc" | grep -qiE "EncodedCommand|FromBase64|GZipStream|MemoryStream|Decompress" && { sev="CRITICAL"; tech="T1059.001+T1027 PS+Obfuscation"; }
            echo "$sc" | grep -qiE "Invoke-WebRequest|DownloadString|DownloadFile|Net\.WebClient|BitsTransfer" && { sev="HIGH"; tech="T1059.001+T1105 PS+Download"; }
            echo "$sc" | grep -qiE "Mimikatz|sekurlsa|lsass|credential" && { sev="CRITICAL"; tech="T1059.001+T1003 PS+CredDump"; }
            echo "$sc" | grep -qiE "VirtualAlloc|WriteProcessMemory|CreateRemoteThread|Reflection\.Assembly" && { sev="CRITICAL"; tech="T1059.001+T1055 PS+Injection"; }
            echo "$sc" | grep -qiE "[Nn]ova|beacon|payload|stager|implant|callbackURI" && { sev="CRITICAL"; tech="T1059.001 PS+Nova/C2"; }
            echo "$sc" | grep -qiE "Invoke-Expression|IEX" && [ "$sev" = "MEDIUM" ] && sev="HIGH"
            tl "$_TS" "$sev" "Execution" "$tech" "$fn" "ScriptBlock[4104]: $(echo "$sc" | cut -c1-350)"
            echo "[$_TS][$sev] $sc" >> "$rpt"; h=$((h+1))
        done
        # EID 4688: Process Creation
        grep -n '>4688<' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"
            local blk=$(sed -n "$((ln)),$((ln+40))p" "$xf" 2>/dev/null)
            local np=$(echo "$blk" | grep -oP 'NewProcessName">\K[^<]+' 2>/dev/null | head -1)
            local cl=$(echo "$blk" | grep -oP 'CommandLine">\K[^<]+' 2>/dev/null | head -1)
            local pp=$(echo "$blk" | grep -oP 'ParentProcessName">\K[^<]+' 2>/dev/null | head -1)
            local sev="INFO" tech="T1106 Execution"
            echo "$np$cl" | grep -qiE "powershell|pwsh" && { sev="MEDIUM"; tech="T1059.001 PowerShell"; }
            echo "$cl" | grep -qiE "certutil|bitsadmin|mshta|regsvr32|rundll32|wscript|cscript" && { sev="HIGH"; tech="T1218 Signed Binary Proxy"; }
            echo "$cl" | grep -qiE "EncodedCommand|hidden|bypass|downloadstring|IEX|nova|beacon" && { sev="CRITICAL"; tech="T1059 Suspicious Exec"; }
            echo "$np" | grep -qiE "\\\\temp\\\\|\\\\tmp\\\\|\\\\appdata\\\\" && [ "$sev" = "INFO" ] && { sev="HIGH"; tech="T1204 User Execution"; }
            [ "$sev" != "INFO" ] && {
                tl "$_TS" "$sev" "Execution" "$tech" "$fn" "Proc[4688]: $np | Cmd:$(echo "$cl" | cut -c1-200) | Parent:$pp"
                echo "[$_TS][$sev] $np | $cl" >> "$rpt"; h=$((h+1))
            }
        done
        # EID 4103: PowerShell Module + EID 800: Pipeline
        grep -n -E '>4103<|>800<' "$xf" 2>/dev/null | head -200 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"
            local blk=$(sed -n "$((ln)),$((ln+40))p" "$xf" 2>/dev/null)
            if echo "$blk" | grep -qiE "MpPreference|Invoke-|Download|EncodedCommand|nova|beacon|base64"; then
                local det=$(echo "$blk" | grep -iE "MpPreference|Invoke-|Download|EncodedCommand|nova|beacon|base64" | head -1 | sed 's/^[[:space:]]*//' | cut -c1-300)
                tl "$_TS" "HIGH" "Execution" "T1059.001 PowerShell" "$fn" "Module/Pipeline[$_EID]: $det"
                echo "[$_TS] $det" >> "$rpt"; h=$((h+1))
            fi
        done
        # Sysmon EID 1: Process Creation
        grep -n '>1<' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; [ "$_EID" = "1" ] || continue
            local blk=$(sed -n "$((ln)),$((ln+50))p" "$xf" 2>/dev/null)
            local img=$(echo "$blk" | grep -oP 'Image">\K[^<]+' 2>/dev/null | head -1)
            local cl=$(echo "$blk" | grep -oP 'CommandLine">\K[^<]+' 2>/dev/null | head -1)
            local pi=$(echo "$blk" | grep -oP 'ParentImage">\K[^<]+' 2>/dev/null | head -1)
            if echo "$img$cl" | grep -qiE "powershell|cmd\.exe|certutil|bitsadmin|mshta|regsvr32|rundll32|nova|beacon|\\\\temp\\\\"; then
                tl "$_TS" "HIGH" "Execution" "T1059 Scripting" "$fn" "Sysmon[1]: $img | $(echo "$cl" | cut -c1-200) | parent:$pi"
                echo "[$_TS] Sysmon: $img | $cl" >> "$rpt"; h=$((h+1))
            fi
        done
    done; info "Execution: $h events"
}

# ============================================================
# PHASE 3: PERSISTENCE (TA0003)
# ============================================================
phase_persistence() {
    log "\n  ${MAG}── Phase 3: Persistence${NC}"
    local rpt="$OUTDIR/phases/03_persistence.txt"; local h=0
    echo "PHASE 3: PERSISTENCE — How did they stay?" > "$rpt"
    for xf in "$OUTDIR/xml_exports/"*.xml; do [ -f "$xf" ] || continue; local fn=$(basename "$xf")
        # EID 7045: New Service
        grep -n '>7045<' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local blk=$(sed -n "$((ln)),$((ln+30))p" "$xf" 2>/dev/null)
            local sn=$(echo "$blk" | grep -oP 'ServiceName">\K[^<]+' 2>/dev/null | head -1)
            local sp=$(echo "$blk" | grep -oP 'ImagePath">\K[^<]+' 2>/dev/null | head -1)
            local sev="MEDIUM"; echo "$sp" | grep -qiE "powershell|cmd|temp\\\\|tmp\\\\|nova|beacon|payload" && { sev="CRITICAL"; crit "Suspicious svc: $sn → $sp"; }
            tl "$_TS" "$sev" "Persistence" "T1543.003 Windows Service" "$fn" "New svc: $sn | $sp [7045]"
            echo "[$_TS][$sev] Svc: $sn → $sp" >> "$rpt"; h=$((h+1))
        done
        # EID 4698: Scheduled Task Created
        grep -n '>4698<' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local blk=$(sed -n "$((ln)),$((ln+50))p" "$xf" 2>/dev/null)
            local tn=$(echo "$blk" | grep -oP 'TaskName">\K[^<]+' 2>/dev/null | head -1)
            local sev="MEDIUM"; echo "$tn" | grep -qiE "nova|beacon|payload|update.*check|sync.*task" && { sev="CRITICAL"; crit "Suspicious task: $tn"; }
            tl "$_TS" "$sev" "Persistence" "T1053.005 Scheduled Task" "$fn" "Task created: $tn [4698]"
            echo "[$_TS] Task: $tn" >> "$rpt"; h=$((h+1))
        done
        # Registry Run keys
        grep -n -iE 'HKLM.*\\Run|HKCU.*\\Run|New-ItemProperty.*Run|CurrentVersion.*\\Run' "$xf" 2>/dev/null | head -50 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "CRITICAL" "Persistence" "T1547.001 Registry Run Keys" "$fn" "Run key: $ml [$_EID]"
            crit "Run key persistence"; echo "[$_TS] Run key: $ml" >> "$rpt"; h=$((h+1))
        done
        # schtasks /create
        grep -n -iE 'schtasks.*/create' "$xf" 2>/dev/null | head -30 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "HIGH" "Persistence" "T1053.005 Scheduled Task" "$fn" "schtasks: $ml [$_EID]"
            echo "[$_TS] schtasks: $ml" >> "$rpt"; h=$((h+1))
        done
        # WMI subscriptions
        grep -n -iE 'EventConsumer|EventFilter|FilterToConsumer|__EventSubscription|CommandLineEventConsumer' "$xf" 2>/dev/null | head -20 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "CRITICAL" "Persistence" "T1546.003 WMI Subscription" "$fn" "WMI persist: $ml [$_EID]"
            crit "WMI persistence"; echo "[$_TS] WMI: $ml" >> "$rpt"; h=$((h+1))
        done
        # Sysmon 13: Registry Run keys
        grep -n '>13<' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; [ "$_EID" = "13" ] || continue
            local blk=$(sed -n "$((ln)),$((ln+25))p" "$xf" 2>/dev/null)
            local to=$(echo "$blk" | grep -oP 'TargetObject">\K[^<]+' 2>/dev/null | head -1)
            echo "$to" | grep -qiE "\\\\Run\\\\|\\\\RunOnce\\\\|\\\\Startup" && {
                local dt=$(echo "$blk" | grep -oP 'Details">\K[^<]+' 2>/dev/null | head -1)
                tl "$_TS" "CRITICAL" "Persistence" "T1547.001 Registry Run" "$fn" "Sysmon Reg[13]: $to → $(echo "$dt" | cut -c1-200)"
                echo "[$_TS] Reg: $to → $dt" >> "$rpt"; h=$((h+1))
            }
        done
    done; info "Persistence: $h events"
}

# ============================================================
# PHASE 4: PRIVILEGE ESCALATION (TA0004)
# ============================================================
phase_privesc() {
    log "\n  ${MAG}── Phase 4: Privilege Escalation${NC}"
    local rpt="$OUTDIR/phases/04_privesc.txt"; local h=0
    echo "PHASE 4: PRIVILEGE ESCALATION" > "$rpt"
    for xf in "$OUTDIR/xml_exports/"*.xml; do [ -f "$xf" ] || continue; local fn=$(basename "$xf")
        # EID 4720: Account Created
        grep -n '>4720<' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local blk=$(sed -n "$((ln)),$((ln+30))p" "$xf" 2>/dev/null)
            local nu=$(echo "$blk" | grep -oP 'TargetUserName">\K[^<]+' 2>/dev/null | head -1)
            local by=$(echo "$blk" | grep -oP 'SubjectUserName">\K[^<]+' 2>/dev/null | head -1)
            tl "$_TS" "HIGH" "Privilege Escalation" "T1136.001 Local Account" "$fn" "Account created: $nu by $by [4720]"
            warn "Account created: $nu"; echo "[$_TS] New: $nu by $by" >> "$rpt"; h=$((h+1))
        done
        # EID 4728/4732: Group membership change
        grep -n -E '>(4728|4732)<' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local blk=$(sed -n "$((ln)),$((ln+30))p" "$xf" 2>/dev/null)
            local mb=$(echo "$blk" | grep -oP 'MemberName">\K[^<]+' 2>/dev/null | head -1)
            local grp=$(echo "$blk" | grep -oP 'TargetUserName">\K[^<]+' 2>/dev/null | head -1)
            tl "$_TS" "CRITICAL" "Privilege Escalation" "T1098 Account Manipulation" "$fn" "$mb added to $grp [$_EID]"
            crit "$mb added to $grp"; echo "[$_TS] Group: $mb → $grp" >> "$rpt"; h=$((h+1))
        done
        # EID 4672: Special privileges (non-system only)
        grep -n '>4672<' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local blk=$(sed -n "$((ln)),$((ln+20))p" "$xf" 2>/dev/null)
            local u=$(echo "$blk" | grep -oP 'SubjectUserName">\K[^<]+' 2>/dev/null | head -1)
            echo "$u" | grep -qiE "^SYSTEM$|^LOCAL SERVICE$|^NETWORK SERVICE$|\\$$" && continue
            [ -z "$u" ] && continue
            tl "$_TS" "MEDIUM" "Privilege Escalation" "T1134 Token Manipulation" "$fn" "Special privs: $u [4672]"
            echo "[$_TS] Privs: $u" >> "$rpt"; h=$((h+1))
        done
        # UAC bypass
        grep -n -iE 'fodhelper|eventvwr.*bypassuac|sdclt|computerdefaults' "$xf" 2>/dev/null | head -10 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "CRITICAL" "Privilege Escalation" "T1548.002 UAC Bypass" "$fn" "UAC bypass: $ml"
            crit "UAC bypass!"; echo "[$_TS] UAC: $ml" >> "$rpt"; h=$((h+1))
        done
    done; info "Privilege Escalation: $h events"
}

# ============================================================
# PHASE 5: DEFENSE EVASION (TA0005) ★ PRIMARY
# ============================================================
phase_defense_evasion() {
    log "\n  ${MAG}── Phase 5: Defense Evasion ★ PRIMARY${NC}"
    local rpt="$OUTDIR/phases/05_defense_evasion.txt"; local h=0
    echo "PHASE 5: DEFENSE EVASION ★ MpPreference / Defender Tampering" > "$rpt"
    for xf in "$OUTDIR/xml_exports/"*.xml; do [ -f "$xf" ] || continue; local fn=$(basename "$xf")
        # ★ MpPreference / Defender tampering
        local mp="MpPreference|Set-Mp|Add-Mp|Remove-Mp|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableScriptScanning|DisableBlockAtFirstSeen|ExclusionPath|ExclusionProcess|ExclusionExtension|ThreatIDDefaultAction|DisableArchiveScanning|MAPSReporting|SubmitSamplesConsent|DisableIntrusionPreventionSystem"
        grep -n -iE "$mp" "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-400)
            if echo "$ml" | grep -qiE "DisableRealtimeMonitoring"; then
                tl "$_TS" "CRITICAL" "Defense Evasion" "T1562.001 Disable Defenses" "$fn" "★ DEFENDER RTP DISABLED: $ml [$_EID]"
                crit "DEFENDER RTP DISABLED!"
            elif echo "$ml" | grep -qiE "ExclusionPath|ExclusionProcess|ExclusionExtension"; then
                tl "$_TS" "CRITICAL" "Defense Evasion" "T1562.001 Disable Defenses" "$fn" "★ EXCLUSION ADDED: $ml [$_EID]"
                crit "Defender exclusion added!"
            elif echo "$ml" | grep -qiE "DisableBehaviorMonitoring|DisableIOAVProtection|DisableScriptScanning"; then
                tl "$_TS" "CRITICAL" "Defense Evasion" "T1562.001 Disable Defenses" "$fn" "★ PROTECTION DISABLED: $ml [$_EID]"
                crit "Defender protection disabled!"
            else
                tl "$_TS" "HIGH" "Defense Evasion" "T1562.001 Disable Defenses" "$fn" "Defender change: $ml [$_EID]"
            fi
            echo "[$_TS] MpPref: $ml" >> "$rpt"; h=$((h+1))
        done
        # EID 5001: RTP OFF / 5007: Config Change / 1116-1117: Malware
        grep -n -E '>(5001|5007|1116|1117)<' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local blk=$(sed -n "$((ln)),$((ln+20))p" "$xf" 2>/dev/null)
            case "$_EID" in
                5001) tl "$_TS" "CRITICAL" "Defense Evasion" "T1562.001 Disable Defenses" "$fn" "★ Defender RTP OFF [5001]"
                      crit "Defender RTP OFF event" ;;
                5007) tl "$_TS" "HIGH" "Defense Evasion" "T1562.001 Disable Defenses" "$fn" "Defender config changed [5007]" ;;
                1116|1117) local th=$(echo "$blk" | grep -i threat | head -1 | sed 's/^[[:space:]]*//' | cut -c1-200)
                      tl "$_TS" "HIGH" "Defense Evasion" "T1562 Impair Defenses" "$fn" "Malware event[$_EID]: $th" ;;
            esac; echo "[$_TS] Defender[$_EID]" >> "$rpt"; h=$((h+1))
        done
        # AMSI Bypass
        grep -n -iE 'AmsiUtils|amsiInitFailed|AmsiScanBuffer|amsi\.dll|SetValue.*NonPublic.*amsi' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "CRITICAL" "Defense Evasion" "T1562.001 AMSI Bypass" "$fn" "AMSI bypass: $ml [$_EID]"
            crit "AMSI bypass!"; echo "[$_TS] AMSI: $ml" >> "$rpt"; h=$((h+1))
        done
        # EID 1102: Audit Log Cleared
        grep -n '>1102<' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"
            tl "$_TS" "CRITICAL" "Defense Evasion" "T1070.001 Clear Logs" "$fn" "★ AUDIT LOG CLEARED by $_USER [1102]"
            crit "AUDIT LOG CLEARED!"; echo "[$_TS] LOG CLEARED by $_USER" >> "$rpt"; h=$((h+1))
        done
        # Log clearing commands
        grep -n -iE 'Clear-EventLog|wevtutil.*cl|Remove-Item.*\.evtx|Stop-Service.*EventLog' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "CRITICAL" "Defense Evasion" "T1070.001 Clear Logs" "$fn" "Log clear cmd: $ml [$_EID]"
            echo "[$_TS] Log clear: $ml" >> "$rpt"; h=$((h+1))
        done
        # Obfuscation/Encoding
        grep -n -iE 'EncodedCommand|FromBase64String|ToBase64String|GZipStream|DeflateStream|IO\.Compression|MemoryStream' "$xf" 2>/dev/null | head -100 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "HIGH" "Defense Evasion" "T1027 Obfuscation" "$fn" "Encoded: $ml [$_EID]"
            echo "[$_TS] Encoded: $ml" >> "$rpt"; h=$((h+1))
        done
        # Execution policy bypass
        grep -n -iE 'ExecutionPolicy.*Bypass|Set-ExecutionPolicy.*Unrestricted' "$xf" 2>/dev/null | head -50 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-200)
            tl "$_TS" "MEDIUM" "Defense Evasion" "T1059.001 ExecPolicy Bypass" "$fn" "Bypass: $ml [$_EID]"
            echo "[$_TS] Bypass: $ml" >> "$rpt"; h=$((h+1))
        done
        # Timestomping (Sysmon 2)
        grep -n '>2<' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; [ "$_EID" = "2" ] || continue
            local blk=$(sed -n "$((ln)),$((ln+20))p" "$xf" 2>/dev/null)
            local tf=$(echo "$blk" | grep -oP 'TargetFilename">\K[^<]+' 2>/dev/null | head -1)
            tl "$_TS" "HIGH" "Defense Evasion" "T1070.006 Timestomp" "$fn" "Timestomp: $tf [Sysmon2]"
            echo "[$_TS] Timestomp: $tf" >> "$rpt"; h=$((h+1))
        done
    done
    [ "$h" -gt 0 ] && log "  ${RED}Defense Evasion: $h events ★ REVIEW NOW${NC}" || info "Defense Evasion: $h events"
}

# ============================================================
# PHASE 6: CREDENTIAL ACCESS (TA0006)
# ============================================================
phase_credential_access() {
    log "\n  ${MAG}── Phase 6: Credential Access${NC}"
    local rpt="$OUTDIR/phases/06_credential_access.txt"; local h=0
    echo "PHASE 6: CREDENTIAL ACCESS" > "$rpt"
    for xf in "$OUTDIR/xml_exports/"*.xml; do [ -f "$xf" ] || continue; local fn=$(basename "$xf")
        # Mimikatz / LSASS / credential dumping
        grep -n -iE 'Mimikatz|sekurlsa|lsass\.exe|procdump.*lsass|comsvcs.*MiniDump|privilege::debug|token::elevate|vault::cred|dpapi::' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "CRITICAL" "Credential Access" "T1003 Credential Dumping" "$fn" "CredDump: $ml [$_EID]"
            crit "Credential dumping!"; echo "[$_TS] $ml" >> "$rpt"; h=$((h+1))
        done
        # Sysmon 10: ProcessAccess to LSASS
        grep -n '>10<' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; [ "$_EID" = "10" ] || continue
            local blk=$(sed -n "$((ln)),$((ln+30))p" "$xf" 2>/dev/null)
            local tgt=$(echo "$blk" | grep -oP 'TargetImage">\K[^<]+' 2>/dev/null | head -1)
            local src=$(echo "$blk" | grep -oP 'SourceImage">\K[^<]+' 2>/dev/null | head -1)
            echo "$tgt" | grep -qi "lsass" && {
                tl "$_TS" "CRITICAL" "Credential Access" "T1003.001 LSASS Memory" "$fn" "LSASS access by $src [Sysmon10]"
                crit "LSASS access: $src"; echo "[$_TS] LSASS: $src → $tgt" >> "$rpt"; h=$((h+1))
            }
        done
        # Credential commands
        grep -n -iE 'Get-Credential|SecureStringToBSTR|Net\.NetworkCredential|cmdkey.*/add' "$xf" 2>/dev/null | head -50 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "HIGH" "Credential Access" "T1555 Credential Stores" "$fn" "Cred cmd: $ml [$_EID]"
            echo "[$_TS] $ml" >> "$rpt"; h=$((h+1))
        done
        # NTLM brute force (EID 4776)
        local nf=$(grep -c '>4776<' "$xf" 2>/dev/null || echo 0)
        [ "$nf" -gt 20 ] && {
            local fl=$(grep -n '>4776<' "$xf" | head -1 | cut -d: -f1)
            [ -n "$fl" ] && ectx "$xf" "$fl"
            tl "$_TS" "HIGH" "Credential Access" "T1110 Brute Force" "$fn" "$nf NTLM auth events [4776]"
            warn "NTLM brute: $nf events"; echo "[$_TS] NTLM: $nf events" >> "$rpt"; h=$((h+1))
        }
    done; info "Credential Access: $h events"
}

# ============================================================
# PHASES 7-12: Discovery, Lateral, Collection, Exfil, C2, Impact
# ============================================================
phase_discovery() {
    log "\n  ${MAG}── Phase 7: Discovery${NC}"
    local rpt="$OUTDIR/phases/07_discovery.txt"; local h=0
    echo "PHASE 7: DISCOVERY" > "$rpt"
    for xf in "$OUTDIR/xml_exports/"*.xml; do [ -f "$xf" ] || continue; local fn=$(basename "$xf")
        grep -n -iE 'Get-ADUser|Get-ADComputer|Get-ADGroup|Get-DomainUser|Get-NetComputer|nltest|dsquery' "$xf" 2>/dev/null | head -50 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "HIGH" "Discovery" "T1087 Account Discovery" "$fn" "AD recon: $ml [$_EID]"; h=$((h+1))
        done
        grep -n -iE 'whoami.*/priv|net user|net group|net localgroup|net share|net view|ipconfig.*/all|systeminfo|tasklist' "$xf" 2>/dev/null | head -100 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-200)
            tl "$_TS" "MEDIUM" "Discovery" "T1082 System Info" "$fn" "Recon: $ml [$_EID]"; h=$((h+1))
        done
        # Sysmon 22: DNS with suspicious TLDs
        grep -n '>22<' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; [ "$_EID" = "22" ] || continue
            local blk=$(sed -n "$((ln)),$((ln+15))p" "$xf" 2>/dev/null)
            local qn=$(echo "$blk" | grep -oP 'QueryName">\K[^<]+' 2>/dev/null | head -1)
            echo "$qn" | grep -qiE "\.xyz|\.top|\.tk|\.ml|\.ga|duckdns|ngrok|interactsh|oast|nova|c2|beacon" && {
                tl "$_TS" "HIGH" "Discovery" "T1018 Remote Discovery" "$fn" "Suspicious DNS: $qn [Sysmon22]"; h=$((h+1))
            }
        done
    done; info "Discovery: $h events"
}

phase_lateral_movement() {
    log "\n  ${MAG}── Phase 8: Lateral Movement${NC}"
    local rpt="$OUTDIR/phases/08_lateral_movement.txt"; local h=0
    echo "PHASE 8: LATERAL MOVEMENT" > "$rpt"
    for xf in "$OUTDIR/xml_exports/"*.xml; do [ -f "$xf" ] || continue; local fn=$(basename "$xf")
        grep -n -iE 'Enter-PSSession|Invoke-Command.*-Computer|New-PSSession|Enable-PSRemoting|WinRM|Test-WSMan' "$xf" 2>/dev/null | head -50 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "HIGH" "Lateral Movement" "T1021.006 WinRM" "$fn" "PSRemoting: $ml [$_EID]"; h=$((h+1))
        done
        grep -n -iE 'psexec|wmic.*process.*call.*create|wmic.*/node:' "$xf" 2>/dev/null | head -30 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "HIGH" "Lateral Movement" "T1021.002 SMB/Admin" "$fn" "PsExec/WMIC: $ml [$_EID]"; h=$((h+1))
        done
        grep -n -iE 'tscon\.exe|mstsc.*/v:' "$xf" 2>/dev/null | head -20 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-200)
            tl "$_TS" "HIGH" "Lateral Movement" "T1021.001 RDP" "$fn" "RDP: $ml [$_EID]"; h=$((h+1))
        done
        # Sysmon 3: Internal network pivots
        grep -n '>3<' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; [ "$_EID" = "3" ] || continue
            local blk=$(sed -n "$((ln)),$((ln+25))p" "$xf" 2>/dev/null)
            local di=$(echo "$blk" | grep -oP 'DestinationIp">\K[^<]+' 2>/dev/null | head -1)
            local dp=$(echo "$blk" | grep -oP 'DestinationPort">\K[^<]+' 2>/dev/null | head -1)
            local img=$(echo "$blk" | grep -oP 'Image">\K[^<]+' 2>/dev/null | head -1)
            echo "$dp" | grep -qE "^(445|5985|5986|3389|22|135)$" && echo "$di" | grep -qE "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" && {
                tl "$_TS" "MEDIUM" "Lateral Movement" "T1021 Remote Services" "$fn" "Internal: $img → $di:$dp [Sysmon3]"; h=$((h+1))
            }
        done
    done; info "Lateral Movement: $h events"
}

phase_collection() {
    log "\n  ${MAG}── Phase 9: Collection${NC}"
    local rpt="$OUTDIR/phases/09_collection.txt"; local h=0
    echo "PHASE 9: COLLECTION" > "$rpt"
    for xf in "$OUTDIR/xml_exports/"*.xml; do [ -f "$xf" ] || continue; local fn=$(basename "$xf")
        grep -n -iE 'Compress-Archive|7z\.exe.*a |rar\.exe.*a |makecab|tar.*czf' "$xf" 2>/dev/null | head -30 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "HIGH" "Collection" "T1560.001 Archive Data" "$fn" "Archive: $ml [$_EID]"; h=$((h+1))
        done
        grep -n -iE 'GetAsyncKeyState|SetWindowsHookEx|keylog|Get-Keystrokes|screenshot|CopyFromScreen' "$xf" 2>/dev/null | head -20 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-200)
            tl "$_TS" "CRITICAL" "Collection" "T1056 Input Capture" "$fn" "Keylog/Screen: $ml [$_EID]"
            crit "Keylogger/screen capture!"; h=$((h+1))
        done
    done; info "Collection: $h events"
}

phase_exfiltration() {
    log "\n  ${MAG}── Phase 10: Exfiltration${NC}"
    local rpt="$OUTDIR/phases/10_exfiltration.txt"; local h=0
    echo "PHASE 10: EXFILTRATION" > "$rpt"
    for xf in "$OUTDIR/xml_exports/"*.xml; do [ -f "$xf" ] || continue; local fn=$(basename "$xf")
        grep -n -iE 'Invoke-WebRequest.*POST|Invoke-RestMethod.*POST|WebClient.*Upload|UploadFile|UploadString|BitsTransfer.*Upload' "$xf" 2>/dev/null | head -30 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "CRITICAL" "Exfiltration" "T1041 C2 Channel Exfil" "$fn" "Upload: $ml [$_EID]"
            crit "Data exfiltration!"; h=$((h+1))
        done
        grep -n -iE 'aws.*s3.*cp|azcopy|gsutil.*cp|rclone|mega-put' "$xf" 2>/dev/null | head -20 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "CRITICAL" "Exfiltration" "T1567 Cloud Exfil" "$fn" "Cloud: $ml [$_EID]"; h=$((h+1))
        done
    done; info "Exfiltration: $h events"
}

phase_c2() {
    log "\n  ${MAG}── Phase 11: Command & Control${NC}"
    local rpt="$OUTDIR/phases/11_c2.txt"; local h=0
    echo "PHASE 11: C2" > "$rpt"
    for xf in "$OUTDIR/xml_exports/"*.xml; do [ -f "$xf" ] || continue; local fn=$(basename "$xf")
        # Download cradles
        grep -n -iE 'Invoke-WebRequest|Net\.WebClient|DownloadString|DownloadFile|DownloadData|Start-BitsTransfer|certutil.*-urlcache|certutil.*-decode|bitsadmin.*transfer' "$xf" 2>/dev/null | head -100 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "HIGH" "Command and Control" "T1105 Ingress Tool" "$fn" "Download: $ml [$_EID]"; h=$((h+1))
        done
        # C2 framework IOCs
        grep -n -iE '[Nn]ova|beacon|cobalt.?strike|sliver|havoc|metasploit|meterpreter|empire|callbackURI|stager|implant' "$xf" 2>/dev/null | head -50 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "CRITICAL" "Command and Control" "T1071 App Layer C2" "$fn" "★ C2 IOC: $ml [$_EID]"
            crit "C2 framework: $ml"; h=$((h+1))
        done
        # Sysmon 3: C2 ports
        grep -n '>3<' "$xf" 2>/dev/null | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; [ "$_EID" = "3" ] || continue
            local blk=$(sed -n "$((ln)),$((ln+25))p" "$xf" 2>/dev/null)
            local di=$(echo "$blk" | grep -oP 'DestinationIp">\K[^<]+' 2>/dev/null | head -1)
            local dp=$(echo "$blk" | grep -oP 'DestinationPort">\K[^<]+' 2>/dev/null | head -1)
            local img=$(echo "$blk" | grep -oP 'Image">\K[^<]+' 2>/dev/null | head -1)
            echo "$dp" | grep -qE "^(4444|5555|8443|8080|9090|1337|31337|6666|6667|4443|2222|3333|7777|9999|13337)$" && {
                tl "$_TS" "CRITICAL" "Command and Control" "T1571 Non-Standard Port" "$fn" "C2 port: $img → $di:$dp [Sysmon3]"
                crit "C2 port: $di:$dp"; h=$((h+1))
            }
        done
        # Tunneling
        grep -n -iE 'netsh.*portproxy|ssh.*-R |ssh.*-D |plink.*-R|chisel|ligolo|ngrok' "$xf" 2>/dev/null | head -20 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "HIGH" "Command and Control" "T1572 Tunneling" "$fn" "Tunnel: $ml [$_EID]"; h=$((h+1))
        done
    done; info "C2: $h events"
}

phase_impact() {
    log "\n  ${MAG}── Phase 12: Impact${NC}"
    local rpt="$OUTDIR/phases/12_impact.txt"; local h=0
    echo "PHASE 12: IMPACT" > "$rpt"
    for xf in "$OUTDIR/xml_exports/"*.xml; do [ -f "$xf" ] || continue; local fn=$(basename "$xf")
        grep -n -iE 'ransom|\.locked|decrypt|bitcoin|vssadmin.*delete.*shadows|bcdedit.*recoveryenabled.*no|wbadmin.*delete.*catalog' "$xf" 2>/dev/null | head -30 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-300)
            tl "$_TS" "CRITICAL" "Impact" "T1486 Ransomware" "$fn" "Ransomware: $ml [$_EID]"
            crit "Ransomware!"; h=$((h+1))
        done
        grep -n -iE 'Stop-Service|net stop|sc\.exe.*stop|taskkill.*/f' "$xf" 2>/dev/null | head -30 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-200)
            tl "$_TS" "MEDIUM" "Impact" "T1489 Service Stop" "$fn" "Svc stop: $ml [$_EID]"; h=$((h+1))
        done
        grep -n -iE 'Remove-Item.*-Recurse.*-Force|del.*/f.*/s.*/q|format.*c:|cipher.*/w:' "$xf" 2>/dev/null | head -20 | while IFS=: read -r ln _; do
            ectx "$xf" "$ln"; local ml=$(sed -n "${ln}p" "$xf" | sed 's/^[[:space:]]*//' | cut -c1-200)
            tl "$_TS" "CRITICAL" "Impact" "T1485 Data Destruction" "$fn" "Destroy: $ml [$_EID]"; h=$((h+1))
        done
    done; info "Impact: $h events"
}

# ============================================================
# BUILD UNIFIED TIMELINE + REPORTS
# ============================================================
build_timeline() {
    hdr "[4/4] Building Unified Attack Timeline"

    sort -t$'\t' -k1,1 "$TL_RAW" > "$OUTDIR/raw/_timeline_sorted.tsv"
    local tot=$(wc -l < "$OUTDIR/raw/_timeline_sorted.tsv")
    local nc=$(grep -c 'CRITICAL' "$OUTDIR/raw/_timeline_sorted.tsv" 2>/dev/null || echo 0)
    local nh=$(grep -c 'HIGH' "$OUTDIR/raw/_timeline_sorted.tsv" 2>/dev/null || echo 0)

    # Human-readable timeline
    {
        echo "================================================================"
        echo "  ATTACK TIMELINE — EVTX FORENSIC ANALYSIS"
        echo "  Generated: $(date)"
        echo "  Source:    $EVTX_DIR"
        echo "  Events:    $tot total | $nc critical | $nh high"
        echo "================================================================"
        echo "SEVERITY: [!!!] CRITICAL  [!! ] HIGH  [ ! ] MEDIUM  [ . ] LOW"
        echo "================================================================"
        local pd=""
        while IFS=$'\t' read -r ts sev tac tch src det; do
            local cd=$(echo "$ts" | cut -dT -f1 | cut -d' ' -f1)
            if [ "$cd" != "$pd" ] && [ -n "$cd" ] && [ "$cd" != "UNKNOWN" ]; then
                printf "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n  📅 %s\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" "$cd"
                pd="$cd"
            fi
            local m="[   ]"
            case "$sev" in CRITICAL) m="[!!!]";; HIGH) m="[!! ]";; MEDIUM) m="[ ! ]";; LOW) m="[ . ]";; esac
            local tp=$(echo "$ts" | grep -oE '[0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
            [ -z "$tp" ] && tp="??:??:??"
            printf "%s %s | %-22s > %-35s | %-18s | %s\n" "$m" "$tp" "$tac" "$tch" "$src" "$det"
        done < "$OUTDIR/raw/_timeline_sorted.tsv"
        printf "\n================================================================\n  END — %d events\n================================================================\n" "$tot"
    } > "$TL_FINAL"

    # CSV for SIEM
    {
        echo "Timestamp,Severity,MITRE_Tactic,MITRE_Technique,Source_File,Details"
        while IFS=$'\t' read -r ts sev tac tch src det; do
            det=$(echo "$det" | sed 's/,/;/g; s/"/'\''/g' | cut -c1-500)
            echo "\"$ts\",\"$sev\",\"$tac\",\"$tch\",\"$src\",\"$det\""
        done < "$OUTDIR/raw/_timeline_sorted.tsv"
    } > "$TL_CSV"

    # MITRE heatmap
    local hm="$OUTDIR/MITRE_HEATMAP.txt"
    {
        echo "================================================================"
        echo "  MITRE ATT&CK PHASE HEATMAP"
        echo "================================================================"
        echo ""
        for tac in "Initial Access" "Execution" "Persistence" "Privilege Escalation" "Defense Evasion" "Credential Access" "Discovery" "Lateral Movement" "Collection" "Exfiltration" "Command and Control" "Impact"; do
            local t=$(grep -c "$tac" "$OUTDIR/raw/_timeline_sorted.tsv" 2>/dev/null || echo 0)
            local c=$(grep "$tac" "$OUTDIR/raw/_timeline_sorted.tsv" 2>/dev/null | grep -c "CRITICAL" 2>/dev/null || echo 0)
            local hi=$(grep "$tac" "$OUTDIR/raw/_timeline_sorted.tsv" 2>/dev/null | grep -c "HIGH" 2>/dev/null || echo 0)
            local bar=""; for ((i=0;i<t&&i<60;i++)); do bar+="█"; done; [ "$t" -gt 60 ] && bar+="→"
            printf "  %-24s %5d (%d crit %d high) %s\n" "$tac" "$t" "$c" "$hi" "$bar"
        done
        echo ""
        echo "  TOP TECHNIQUES:"
        awk -F'\t' '{print $4}' "$OUTDIR/raw/_timeline_sorted.tsv" | sort | uniq -c | sort -rn | head -15 | while read -r cnt tech; do
            printf "    %5d  %s\n" "$cnt" "$tech"
        done
    } > "$hm"
    cat "$hm" | tee -a "$LOGFILE"

    # EID distribution
    local eid_rpt="$OUTDIR/EVENT_ID_DISTRIBUTION.txt"
    echo "EVENT ID DISTRIBUTION" > "$eid_rpt"
    grep -h '<EventID' "$OUTDIR/xml_exports/"*.xml 2>/dev/null | sed -E 's/.*<EventID[^>]*>([^<]+)<.*/\1/' | sort | uniq -c | sort -rn | head -50 | while read -r c e; do
        local l=""
        case "$e" in 4104) l="PS ScriptBlock";; 4103) l="PS Module";; 4688) l="Proc Create";; 4624) l="Logon OK";; 4625) l="Logon Fail";;
            4672) l="Special Privs";; 4698) l="Task Created";; 7045) l="New Service";; 1102) l="★LOG CLEARED";; 5001) l="★Defender OFF";;
            5007) l="★Defender Cfg";; 1116) l="★Malware Det";; 1) l="Sysmon Proc";; 3) l="Sysmon Net";; 10) l="Sysmon ProcAccess";;
            13) l="Sysmon Reg";; 22) l="Sysmon DNS";; esac
        printf "  %8s  EID %-6s %s\n" "$c" "$e" "$l" >> "$eid_rpt"
    done
}

final_summary() {
    log ""
    log "${BLD}${CYN}================================================================${NC}"
    log "${BLD}${CYN}  ANALYSIS COMPLETE${NC}"
    log "${BLD}${CYN}================================================================${NC}"
    log "  ${BLD}Findings: $FINDINGS${NC}"
    [ "$CRITICAL" -gt 0 ] && log "  ${RED}Critical: $CRITICAL${NC}"
    log ""
    log "  ${BLD}${YEL}📋 READ IN THIS ORDER:${NC}"
    log "    1. ${RED}ATTACK_TIMELINE.txt${NC}    — Full attack narrative (chronological)"
    log "    2. ${RED}MITRE_HEATMAP.txt${NC}      — Which ATT&CK phases were hit"
    log "    3. ${RED}ATTACK_TIMELINE.csv${NC}    — Import into Splunk/Excel/SIEM"
    log ""
    log "  ${BLD}${YEL}📁 KILL CHAIN DETAILS:${NC}"
    log "    phases/01_initial_access.txt    — How they got in"
    log "    phases/02_execution.txt         — What they ran (PowerShell/Scripts)"
    log "    phases/03_persistence.txt       — How they stayed (services/tasks/reg)"
    log "    phases/04_privesc.txt           — How they escalated"
    log "    phases/05_defense_evasion.txt   — ★ MpPreference/AMSI/log clearing"
    log "    phases/06_credential_access.txt — Cred theft (Mimikatz/LSASS)"
    log "    phases/07_discovery.txt         — AD/network recon"
    log "    phases/08_lateral_movement.txt  — PSRemoting/RDP/SMB pivots"
    log "    phases/09_collection.txt        — Archives/keyloggers/screenshots"
    log "    phases/10_exfiltration.txt      — Data uploads/DNS exfil"
    log "    phases/11_c2.txt                — Nova/beacon/C2 comms"
    log "    phases/12_impact.txt            — Ransomware/destruction"
    log ""
    log "  ${YEL}Custom IOC grep:${NC}  grep -riE 'your_ioc' ${OUTDIR}/xml_exports/"
    log ""
}

# ============================================================
# MAIN
# ============================================================
banner
preflight
step_inventory
step_export
hdr "[3/4] MITRE ATT&CK Kill Chain Analysis (12 phases)"
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
