#!/bin/bash
#=============================================================================
# EVTX Forensic Analyzer (libevtx-utils edition)
# Uses ONLY evtxexport & evtxinfo — no Python dependencies
# Focus: PowerShell abuse, MpPreference tampering, Nova IOCs, defense evasion
#=============================================================================

set -uo pipefail

# Colors
RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
NC='\033[0m'

EVTX_DIR="${1:-.}"
OUTDIR="./evtx_analysis_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR/xml_exports"

banner() {
    echo -e "${BLD}${CYN}=================================================${NC}"
    echo -e "${BLD}${CYN}  EVTX FORENSIC ANALYZER (libevtx-utils)        ${NC}"
    echo -e "${BLD}${CYN}=================================================${NC}"
    echo -e "${YEL}Target:  ${EVTX_DIR}${NC}"
    echo -e "${YEL}Output:  ${OUTDIR}${NC}"
    echo ""
}

# ============================================================
# Preflight checks
# ============================================================
preflight() {
    for cmd in evtxexport evtxinfo grep awk sed sort uniq; do
        if ! command -v "$cmd" &>/dev/null; then
            echo -e "${RED}ERROR: '$cmd' not found. Install libevtx-utils.${NC}"
            exit 1
        fi
    done
}

# ============================================================
# STEP 1: Inventory — evtxinfo on all files
# ============================================================
step_inventory() {
    echo -e "${BLD}${CYN}[STEP 1/6] Inventory (evtxinfo)${NC}"
    local count=0
    local report="$OUTDIR/01_inventory.txt"

    echo "EVTX FILE INVENTORY" > "$report"
    echo "Generated: $(date)" >> "$report"
    echo "========================================" >> "$report"

    while IFS= read -r -d '' f; do
        count=$((count + 1))
        fname=$(basename "$f")
        fsize=$(ls -lh "$f" | awk '{print $5}')
        echo "" >> "$report"
        echo "--- [$count] $fname ($fsize) ---" >> "$report"
        evtxinfo "$f" 2>/dev/null >> "$report"
        echo -e "  ${GRN}[$count]${NC} $fname ($fsize)"
    done < <(find "$EVTX_DIR" -iname "*.evtx" -print0 2>/dev/null | sort -z)

    echo ""
    echo -e "  ${BLD}Total EVTX files: $count${NC}"
    echo "" >> "$report"
    echo "Total files: $count" >> "$report"

    if [ "$count" -eq 0 ]; then
        echo -e "${RED}No .evtx files found in $EVTX_DIR${NC}"
        exit 1
    fi
}

# ============================================================
# STEP 2: Export all EVTX to XML
# ============================================================
step_export() {
    echo ""
    echo -e "${BLD}${CYN}[STEP 2/6] Exporting EVTX → XML (evtxexport -f xml)${NC}"
    echo -e "  ${YEL}This may take a while for large files...${NC}"
    echo ""

    local idx=0
    while IFS= read -r -d '' f; do
        idx=$((idx + 1))
        fname=$(basename "$f" .evtx)
        fname=$(basename "$fname" .EVTX)
        outxml="$OUTDIR/xml_exports/${fname}.xml"

        echo -ne "  [${idx}] Exporting ${fname}... "
        evtxexport -f xml -m all "$f" > "$outxml" 2>/dev/null
        local lines=$(wc -l < "$outxml")
        echo -e "${GRN}${lines} lines${NC}"
    done < <(find "$EVTX_DIR" -iname "*.evtx" -print0 2>/dev/null | sort -z)
}

# ============================================================
# STEP 3: Event ID distribution
# ============================================================
step_eventid_stats() {
    echo ""
    echo -e "${BLD}${CYN}[STEP 3/6] Event ID Distribution${NC}"

    local report="$OUTDIR/02_event_id_distribution.txt"

    echo "EVENT ID DISTRIBUTION" > "$report"
    echo "========================================" >> "$report"

    # Extract EventID from all XML exports
    grep -h '<EventID' "$OUTDIR/xml_exports/"*.xml 2>/dev/null | \
        sed -E 's/.*<EventID[^>]*>([^<]+)<.*/\1/' | \
        sort | uniq -c | sort -rn > "$OUTDIR/_eid_counts.tmp"

    # Annotate known event IDs
    while read -r count eid; do
        label=""
        case "$eid" in
            4104) label="PowerShell ScriptBlock Logging" ;;
            4103) label="PowerShell Module Logging" ;;
            4688) label="Process Creation" ;;
            4624) label="Successful Logon" ;;
            4625) label="Failed Logon" ;;
            4648) label="Logon Explicit Credentials" ;;
            4672) label="Special Privileges" ;;
            4697) label="Service Installed" ;;
            4698) label="Scheduled Task Created" ;;
            4720) label="User Account Created" ;;
            4732) label="Member Added to Local Group" ;;
            4776) label="NTLM Auth" ;;
            7045) label="New Service Installed" ;;
            1102) label="*** AUDIT LOG CLEARED ***" ;;
            5001) label="*** Defender Realtime Protection DISABLED ***" ;;
            5007) label="*** Defender Config Changed ***" ;;
            1116) label="*** Defender Detected Malware ***" ;;
            1117) label="*** Defender Action on Malware ***" ;;
            400)  label="PowerShell Engine Start" ;;
            403)  label="PowerShell Engine Stop" ;;
            800)  label="PowerShell Pipeline Execution" ;;
            1)    label="Sysmon Process Creation" ;;
            3)    label="Sysmon Network Connection" ;;
            8)    label="Sysmon CreateRemoteThread" ;;
            10)   label="Sysmon ProcessAccess" ;;
            11)   label="Sysmon FileCreate" ;;
            13)   label="Sysmon RegistryEvent" ;;
            22)   label="Sysmon DNS Query" ;;
            25)   label="Sysmon ProcessTampering" ;;
        esac
        printf "  %8s  EventID %-6s %s\n" "$count" "$eid" "$label" >> "$report"
    done < "$OUTDIR/_eid_counts.tmp"

    head -25 "$report"
    echo "  ..."
    echo -e "  ${GRN}Full list in: 02_event_id_distribution.txt${NC}"
}

# ============================================================
# STEP 4: MpPreference / Defender Tampering
# ============================================================
step_mp_defender() {
    echo ""
    echo -e "${BLD}${CYN}[STEP 4/6] MpPreference & Defender Tampering${NC}"

    local report="$OUTDIR/03_mppreference_defender_tampering.txt"
    local mp_patterns=(
        "MpPreference"
        "Set-Mp"
        "Add-Mp"
        "Remove-Mp"
        "DisableRealtimeMonitoring"
        "DisableBehaviorMonitoring"
        "DisableIOAVProtection"
        "DisableScriptScanning"
        "DisableBlockAtFirstSeen"
        "ExclusionPath"
        "ExclusionProcess"
        "ExclusionExtension"
        "ThreatIDDefaultAction"
        "DisableArchiveScanning"
        "DisableIntrusionPreventionSystem"
        "MAPSReporting"
        "SubmitSamplesConsent"
    )

    echo "MpPreference / DEFENDER TAMPERING EVENTS" > "$report"
    echo "=========================================" >> "$report"
    echo "Searched patterns: ${mp_patterns[*]}" >> "$report"
    echo "" >> "$report"

    local combined_pattern
    combined_pattern=$(printf "|%s" "${mp_patterns[@]}")
    combined_pattern="${combined_pattern:1}"  # remove leading |

    local total_hits=0

    for xmlfile in "$OUTDIR/xml_exports/"*.xml; do
        [ -f "$xmlfile" ] || continue
        fname=$(basename "$xmlfile")

        # Use grep with context to grab surrounding XML
        hits=$(grep -c -iE "$combined_pattern" "$xmlfile" 2>/dev/null || true)

        if [ "$hits" -gt 0 ]; then
            total_hits=$((total_hits + hits))
            echo "" >> "$report"
            echo "=== FILE: $fname === ($hits matches)" >> "$report"
            echo "" >> "$report"

            # Extract blocks around matches (30 lines of context)
            grep -n -iE "$combined_pattern" "$xmlfile" 2>/dev/null | while IFS=: read -r linenum _; do
                start=$((linenum - 15))
                [ "$start" -lt 1 ] && start=1
                end=$((linenum + 15))
                echo "--- Match near line $linenum ---" >> "$report"
                sed -n "${start},${end}p" "$xmlfile" >> "$report"
                echo "" >> "$report"
            done
        fi
    done

    echo "" >> "$report"
    echo "TOTAL MATCHES: $total_hits" >> "$report"

    if [ "$total_hits" -gt 0 ]; then
        echo -e "  ${RED}FOUND $total_hits MpPreference/Defender tampering hits!${NC}"
    else
        echo -e "  ${GRN}No MpPreference tampering found.${NC}"
    fi
    echo -e "  Report: 03_mppreference_defender_tampering.txt"
}

# ============================================================
# STEP 5: Suspicious patterns (broad scan)
# ============================================================
step_suspicious() {
    echo ""
    echo -e "${BLD}${CYN}[STEP 5/6] Scanning for Suspicious Patterns${NC}"

    local report="$OUTDIR/04_suspicious_events.txt"

    echo "SUSPICIOUS EVENT SCAN" > "$report"
    echo "=========================================" >> "$report"

    # Define pattern categories
    declare -A CATEGORIES
    CATEGORIES=(
        ["ENCODED_COMMANDS"]="EncodedCommand|FromBase64String|ToBase64String|GZipStream|DeflateStream|IO\.Compression|MemoryStream|Convert\]::FromBase64"
        ["DOWNLOAD_EXEC"]="Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|DownloadString|DownloadFile|DownloadData|Start-BitsTransfer|Invoke-Expression|IEX\(|iex |bitsadmin.*transfer|certutil.*urlcache|certutil.*decode"
        ["CREDENTIAL_ACCESS"]="Mimikatz|sekurlsa|lsass|Get-Credential|SecureStringToBSTR|cmdkey|vault::cred|token::elevate|privilege::debug"
        ["PERSISTENCE"]="New-ScheduledTask|Register-ScheduledTask|schtasks|New-Service|sc\.exe.*create|HKLM.*\\\\Run|HKCU.*\\\\Run|Startup|New-ItemProperty.*Run"
        ["LATERAL_MOVEMENT"]="Enter-PSSession|Invoke-Command.*-Computer|New-PSSession|Enable-PSRemoting|WinRM|Test-WSMan|psexec|wmic.*process.*call"
        ["RECON"]="Get-ADUser|Get-ADComputer|Get-ADGroup|nltest|dsquery|whoami.*priv|net user|net group|net localgroup|net share|net view|ipconfig|systeminfo|tasklist"
        ["AMSI_BYPASS"]="AmsiUtils|amsiInitFailed|AmsiScanBuffer|amsi\.dll|Reflection\.Assembly.*Load|SetValue.*NonPublic"
        ["EXEC_EVASION"]="ExecutionPolicy.*Bypass|WindowStyle.*Hidden|NoProfile|NonInteractive|rundll32|regsvr32|mshta|wscript|cscript|COMSPEC|cmd\.exe.*/c"
        ["PROCESS_INJECTION"]="VirtualAlloc|VirtualProtect|WriteProcessMemory|CreateRemoteThread|NtCreateThread|QueueUserAPC|OpenProcess|LoadLibrary"
        ["NOVA_IOCs"]="[Nn]ova|beacon|payload|reverse.*shell|bind.*shell|C2|callbackURI|stager|implant"
        ["DATA_EXFIL"]="Compress-Archive|Out-File|Copy-Item.*-Destination|Invoke-WebRequest.*-Method.*POST|upload|exfil"
        ["LOG_TAMPERING"]="Clear-EventLog|wevtutil.*cl|Remove-Item.*\.evtx|Stop-Service.*EventLog"
    )

    for category in "${!CATEGORIES[@]}"; do
        pattern="${CATEGORIES[$category]}"
        echo "" >> "$report"
        echo "=========================================" >> "$report"
        echo "CATEGORY: $category" >> "$report"
        echo "=========================================" >> "$report"

        local cat_hits=0
        for xmlfile in "$OUTDIR/xml_exports/"*.xml; do
            [ -f "$xmlfile" ] || continue
            fname=$(basename "$xmlfile")
            hits=$(grep -c -iE "$pattern" "$xmlfile" 2>/dev/null || true)

            if [ "$hits" -gt 0 ]; then
                cat_hits=$((cat_hits + hits))
                echo "" >> "$report"
                echo "--- $fname ($hits matches) ---" >> "$report"

                # Extract matching lines with context
                grep -n -iE "$pattern" "$xmlfile" 2>/dev/null | head -50 | while IFS=: read -r linenum content; do
                    start=$((linenum - 10))
                    [ "$start" -lt 1 ] && start=1
                    end=$((linenum + 10))
                    echo "" >> "$report"
                    echo "[Line $linenum]" >> "$report"
                    sed -n "${start},${end}p" "$xmlfile" >> "$report"
                done
            fi
        done

        if [ "$cat_hits" -gt 0 ]; then
            echo -e "  ${RED}$category: $cat_hits hits${NC}"
        else
            echo -e "  ${GRN}$category: clean${NC}"
        fi
    done
}

# ============================================================
# STEP 6: Timeline of critical events
# ============================================================
step_timeline() {
    echo ""
    echo -e "${BLD}${CYN}[STEP 6/6] Building Attack Timeline${NC}"

    local report="$OUTDIR/05_timeline.txt"

    echo "ATTACK TIMELINE" > "$report"
    echo "=========================================" >> "$report"
    echo "Showing events with timestamps sorted chronologically" >> "$report"
    echo "" >> "$report"

    # Extract timestamps + event IDs + any suspicious context
    local critical_pattern="MpPreference|Set-Mp|DisableRealtime|ExclusionPath|EncodedCommand|FromBase64|DownloadString|DownloadFile|Invoke-Expression|IEX|Mimikatz|sekurlsa|schtasks|New-Service|AmsiUtils|amsiInitFailed|VirtualAlloc|CreateRemoteThread|Clear-EventLog|wevtutil|[Nn]ova|beacon|payload"

    for xmlfile in "$OUTDIR/xml_exports/"*.xml; do
        [ -f "$xmlfile" ] || continue
        fname=$(basename "$xmlfile")

        grep -n -iE "$critical_pattern" "$xmlfile" 2>/dev/null | while IFS=: read -r linenum _; do
            # Look backwards from the match to find the timestamp
            start=$((linenum - 20))
            [ "$start" -lt 1 ] && start=1

            block=$(sed -n "${start},${linenum}p" "$xmlfile")

            timestamp=$(echo "$block" | grep -oP 'SystemTime="\K[^"]+' | tail -1)
            eventid=$(echo "$block" | grep -oP '<EventID[^>]*>\K[^<]+' | tail -1)
            matchline=$(sed -n "${linenum}p" "$xmlfile" | sed 's/^[[:space:]]*//' | cut -c1-200)

            [ -z "$timestamp" ] && timestamp="UNKNOWN"
            [ -z "$eventid" ] && eventid="?"

            printf "%s | EID=%-5s | %-20s | %s\n" "$timestamp" "$eventid" "$fname" "$matchline" >> "$report"
        done
    done

    # Sort the timeline
    sort -o "$report.sorted" "$report.sorted" 2>/dev/null || \
        (head -4 "$report" > "$report.sorted"; tail -n +5 "$report" | sort >> "$report.sorted"; mv "$report.sorted" "$report")

    local tl_count
    tl_count=$(wc -l < "$report")
    echo -e "  Timeline entries: $tl_count"
    echo -e "  Report: 05_timeline.txt"
}

# ============================================================
# STEP 7: Quick summary
# ============================================================
step_summary() {
    echo ""
    echo -e "${BLD}${CYN}=================================================${NC}"
    echo -e "${BLD}${CYN}  ANALYSIS COMPLETE${NC}"
    echo -e "${BLD}${CYN}=================================================${NC}"
    echo ""
    echo -e "${BLD}Reports generated:${NC}"
    ls -lh "$OUTDIR"/*.txt 2>/dev/null | awk '{print "  "$5" "$9}'
    echo ""
    echo -e "${BLD}${YEL}Priority reading order:${NC}"
    echo -e "  1. ${RED}03_mppreference_defender_tampering.txt${NC} — Defender evasion (your main concern)"
    echo -e "  2. ${RED}04_suspicious_events.txt${NC}              — All malicious patterns by category"
    echo -e "  3. ${YEL}05_timeline.txt${NC}                       — Chronological attack sequence"
    echo -e "  4. ${GRN}02_event_id_distribution.txt${NC}          — Event ID overview"
    echo -e "  5. ${GRN}01_inventory.txt${NC}                      — File metadata"
    echo ""
    echo -e "${BLD}XML exports in: ${OUTDIR}/xml_exports/${NC}"
    echo -e "${YEL}Tip: You can grep the XML exports directly for custom IOCs:${NC}"
    echo -e "  grep -riE 'your_pattern' ${OUTDIR}/xml_exports/"
    echo ""
}

# ============================================================
# MAIN
# ============================================================
banner
preflight
step_inventory
step_export
step_eventid_stats
step_mp_defender
step_suspicious
step_timeline
step_summary
