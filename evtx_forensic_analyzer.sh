#!/bin/bash
#=============================================================================
# EVTX Forensic Analyzer
# Parses all .evtx files in a directory using python-evtx
# Focuses on: PowerShell abuse, defense evasion, Nova IOCs, persistence
#=============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

EVTX_DIR="${1:-.}"
OUTPUT_DIR="./evtx_analysis_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo -e "${BOLD}${CYAN}=============================================${NC}"
echo -e "${BOLD}${CYAN}   EVTX FORENSIC ANALYZER                   ${NC}"
echo -e "${BOLD}${CYAN}=============================================${NC}"
echo -e "${YELLOW}Target directory: ${EVTX_DIR}${NC}"
echo -e "${YELLOW}Output directory: ${OUTPUT_DIR}${NC}"
echo ""

# Count EVTX files
EVTX_COUNT=$(find "$EVTX_DIR" -iname "*.evtx" 2>/dev/null | wc -l)
echo -e "${GREEN}Found ${EVTX_COUNT} EVTX files${NC}"
echo ""

if [ "$EVTX_COUNT" -eq 0 ]; then
    echo -e "${RED}No .evtx files found in ${EVTX_DIR}${NC}"
    echo "Usage: $0 /path/to/evtx/files"
    exit 1
fi

#=============================================================================
# STEP 1: List all EVTX files with basic info
#=============================================================================
echo -e "${BOLD}${CYAN}[STEP 1] Inventory of EVTX files${NC}"
echo "================================================================" | tee "$OUTPUT_DIR/00_inventory.txt"

find "$EVTX_DIR" -iname "*.evtx" -exec ls -lh {} \; 2>/dev/null | \
    awk '{print $5, $9}' | sort -k2 | tee -a "$OUTPUT_DIR/00_inventory.txt"
echo ""

#=============================================================================
# STEP 2: Python script to parse ALL events and generate reports
#=============================================================================
cat > "$OUTPUT_DIR/_parser.py" << 'PYEOF'
#!/usr/bin/env python3
"""
EVTX Forensic Parser
Extracts all events, flags suspicious activity related to:
- PowerShell abuse (MpPreference, encoded commands, downloads)
- Defense evasion (Defender tampering, firewall changes)
- Nova / RAT indicators
- Persistence mechanisms
- Lateral movement
- Credential access
"""

import sys
import os
import json
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime
import re
import glob

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as e_views
except ImportError:
    print("ERROR: python-evtx not installed. Run: pip install python-evtx")
    sys.exit(1)

# ============================================================
# SUSPICIOUS PATTERNS
# ============================================================
POWERSHELL_SUSPICIOUS = [
    # Defense Evasion - MpPreference abuse
    r'Set-MpPreference',
    r'Add-MpPreference',
    r'Remove-MpPreference',
    r'DisableRealtimeMonitoring',
    r'DisableBehaviorMonitoring',
    r'DisableIOAVProtection',
    r'DisableScriptScanning',
    r'DisableBlockAtFirstSeen',
    r'ExclusionPath',
    r'ExclusionProcess',
    r'ExclusionExtension',
    # Encoded / Obfuscated commands
    r'-[Ee]nc(?:odedCommand)?',
    r'[Ff]rom[Bb]ase64[Ss]tring',
    r'[Dd]ecompress',
    r'GZipStream',
    r'MemoryStream',
    r'IO\.Compression',
    r'Convert\]::FromBase64',
    # Download / Execution
    r'Invoke-WebRequest',
    r'Invoke-RestMethod',
    r'wget\s',
    r'curl\s',
    r'Net\.WebClient',
    r'DownloadString',
    r'DownloadFile',
    r'DownloadData',
    r'Start-BitsTransfer',
    r'Invoke-Expression',
    r'iex\s*\(',
    r'IEX\s*\(',
    # Credential Access
    r'Mimikatz',
    r'sekurlsa',
    r'Get-Credential',
    r'ConvertTo-SecureString',
    r'SecureStringToBSTR',
    r'Net\.NetworkCredential',
    r'cmdkey',
    # Persistence
    r'New-ScheduledTask',
    r'Register-ScheduledTask',
    r'schtasks',
    r'New-Service',
    r'sc\.exe\s+create',
    r'reg\s+add.*Run',
    r'HKLM.*Run',
    r'HKCU.*Run',
    r'Startup',
    # Lateral Movement
    r'Enter-PSSession',
    r'Invoke-Command',
    r'New-PSSession',
    r'WinRM',
    r'Test-WSMan',
    r'Enable-PSRemoting',
    # Reconnaissance
    r'Get-ADUser',
    r'Get-ADComputer',
    r'Get-ADGroup',
    r'Get-DomainUser',
    r'Get-NetComputer',
    r'nltest',
    r'dsquery',
    r'whoami\s*/priv',
    r'net\s+user',
    r'net\s+group',
    r'net\s+localgroup',
    r'net\s+share',
    r'net\s+view',
    # Process Injection / AMSI Bypass
    r'AmsiUtils',
    r'amsiInitFailed',
    r'VirtualAlloc',
    r'VirtualProtect',
    r'WriteProcessMemory',
    r'CreateRemoteThread',
    r'Reflection\.Assembly',
    r'LoadLibrary',
    # Nova specific IOCs
    r'[Nn]ova',
    r'beacon',
    r'payload',
    r'shell\.ps1',
    r'reverse',
    r'bind.*shell',
    r'C2',
    r'callbackURI',
    # Evasion techniques
    r'Set-ExecutionPolicy\s+Bypass',
    r'ExecutionPolicy\s+Bypass',
    r'-[Ww]indowStyle\s+[Hh]idden',
    r'-[Nn]o[Pp]rofile',
    r'-[Nn]on[Ii]nteractive',
    r'COMSPEC',
    r'rundll32',
    r'regsvr32',
    r'mshta',
    r'certutil.*-decode',
    r'certutil.*-urlcache',
    r'bitsadmin.*\/transfer',
]

# Event IDs of interest
INTERESTING_EVENT_IDS = {
    # PowerShell
    '4103': 'PowerShell Module Logging',
    '4104': 'PowerShell ScriptBlock Logging',
    '4105': 'PowerShell ScriptBlock Start',
    '4106': 'PowerShell ScriptBlock Stop',
    '400': 'PowerShell Engine Start',
    '403': 'PowerShell Engine Stop',
    '800': 'PowerShell Pipeline Execution',
    # Security
    '4624': 'Successful Logon',
    '4625': 'Failed Logon',
    '4648': 'Logon with Explicit Credentials',
    '4672': 'Special Privileges Assigned',
    '4688': 'Process Creation',
    '4689': 'Process Termination',
    '4697': 'Service Installed',
    '4698': 'Scheduled Task Created',
    '4699': 'Scheduled Task Deleted',
    '4700': 'Scheduled Task Enabled',
    '4720': 'User Account Created',
    '4722': 'User Account Enabled',
    '4724': 'Password Reset Attempt',
    '4728': 'Member Added to Security Group',
    '4732': 'Member Added to Local Group',
    '4738': 'User Account Changed',
    '4776': 'NTLM Authentication',
    # System
    '7045': 'New Service Installed',
    '7036': 'Service State Changed',
    '1102': 'Audit Log Cleared',
    # Defender
    '5001': 'Real-time Protection Disabled',
    '5007': 'Defender Config Changed',
    '5010': 'Malware Scanning Disabled',
    '5012': 'Malware Scanning Disabled',
    '1116': 'Defender Detected Malware',
    '1117': 'Defender Action on Malware',
    '1006': 'Malware or Unwanted Software Detected',
    '1007': 'Action Taken on Malware',
    '1008': 'Action Failed on Malware',
    # Sysmon (if available)
    '1': 'Sysmon Process Creation',
    '3': 'Sysmon Network Connection',
    '7': 'Sysmon Image Loaded',
    '8': 'Sysmon CreateRemoteThread',
    '10': 'Sysmon ProcessAccess',
    '11': 'Sysmon FileCreate',
    '12': 'Sysmon RegistryEvent Create/Delete',
    '13': 'Sysmon RegistryEvent Value Set',
    '22': 'Sysmon DNS Query',
    '23': 'Sysmon FileDelete',
    '25': 'Sysmon ProcessTampering',
}

class EVTXAnalyzer:
    def __init__(self, evtx_dir, output_dir):
        self.evtx_dir = evtx_dir
        self.output_dir = output_dir
        self.all_events = []
        self.suspicious_events = []
        self.event_id_counts = Counter()
        self.file_event_counts = {}
        self.timeline = []
        self.users_seen = set()
        self.ips_seen = set()
        self.mp_events = []

    def parse_all(self):
        evtx_files = sorted(glob.glob(os.path.join(self.evtx_dir, '**', '*.evtx'), recursive=True))
        evtx_files += sorted(glob.glob(os.path.join(self.evtx_dir, '**', '*.EVTX'), recursive=True))
        evtx_files = list(set(evtx_files))  # dedupe

        total = len(evtx_files)
        for idx, filepath in enumerate(evtx_files, 1):
            fname = os.path.basename(filepath)
            print(f"  [{idx}/{total}] Parsing: {fname}", flush=True)
            try:
                self._parse_file(filepath)
            except Exception as e:
                print(f"    ERROR parsing {fname}: {e}")

    def _parse_file(self, filepath):
        fname = os.path.basename(filepath)
        count = 0
        try:
            with evtx.Evtx(filepath) as log:
                for record in log.records():
                    count += 1
                    try:
                        xml_str = record.xml()
                        self._process_event(xml_str, fname)
                    except Exception:
                        pass
        except Exception as e:
            print(f"    Could not open {fname}: {e}")
        self.file_event_counts[fname] = count

    def _process_event(self, xml_str, source_file):
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return

        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        # Extract System fields
        system = root.find('ns:System', ns)
        if system is None:
            return

        event_id_elem = system.find('ns:EventID', ns)
        event_id = event_id_elem.text if event_id_elem is not None else 'Unknown'

        time_elem = system.find('ns:TimeCreated', ns)
        timestamp = time_elem.get('SystemTime', '') if time_elem is not None else ''

        computer_elem = system.find('ns:Computer', ns)
        computer = computer_elem.text if computer_elem is not None else ''

        channel_elem = system.find('ns:Channel', ns)
        channel = channel_elem.text if channel_elem is not None else ''

        provider_elem = system.find('ns:Provider', ns)
        provider = provider_elem.get('Name', '') if provider_elem is not None else ''

        # Count event IDs
        self.event_id_counts[f"{event_id} ({channel})"] += 1

        # Extract EventData
        event_data = {}
        event_data_elem = root.find('ns:EventData', ns)
        if event_data_elem is not None:
            for data in event_data_elem:
                name = data.get('Name', 'unnamed')
                value = data.text or ''
                event_data[name] = value

        # Also check UserData
        user_data_elem = root.find('ns:UserData', ns)
        if user_data_elem is not None:
            for child in user_data_elem:
                for elem in child:
                    tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                    event_data[tag] = elem.text or ''

        # Full text for pattern matching
        full_text = xml_str

        # Track users
        user = event_data.get('SubjectUserName', event_data.get('TargetUserName', ''))
        if user and user != '-' and user != 'SYSTEM':
            self.users_seen.add(user)

        # Track IPs
        ip = event_data.get('IpAddress', event_data.get('SourceAddress', ''))
        if ip and ip != '-' and ip != '::1' and ip != '127.0.0.1':
            self.ips_seen.add(ip)

        # Check for MpPreference / Defender related
        is_mp = False
        if re.search(r'[Mm][Pp][Pp]reference|MpPreference|Set-Mp|Add-Mp|Remove-Mp|DisableRealtime|ExclusionPath', full_text):
            is_mp = True
            self.mp_events.append({
                'timestamp': timestamp,
                'event_id': event_id,
                'channel': channel,
                'source_file': source_file,
                'computer': computer,
                'data': event_data,
                'snippet': full_text[:2000]
            })

        # Check for suspicious patterns
        matched_patterns = []
        for pattern in POWERSHELL_SUSPICIOUS:
            if re.search(pattern, full_text, re.IGNORECASE):
                matched_patterns.append(pattern)

        if matched_patterns or event_id in INTERESTING_EVENT_IDS or is_mp:
            event_record = {
                'timestamp': timestamp,
                'event_id': event_id,
                'channel': channel,
                'provider': provider,
                'computer': computer,
                'source_file': source_file,
                'event_data': event_data,
                'matched_patterns': matched_patterns,
                'is_interesting_event': event_id in INTERESTING_EVENT_IDS,
                'is_mp': is_mp,
            }

            if matched_patterns:
                event_record['severity'] = 'HIGH' if len(matched_patterns) > 2 else 'MEDIUM'
                self.suspicious_events.append(event_record)

            self.timeline.append(event_record)

    def generate_reports(self):
        print("\n[*] Generating reports...\n")

        # Report 1: Overview
        self._report_overview()

        # Report 2: Event ID distribution
        self._report_event_ids()

        # Report 3: Suspicious / malicious events
        self._report_suspicious()

        # Report 4: MpPreference / Defender tampering
        self._report_mp_events()

        # Report 5: Timeline
        self._report_timeline()

        # Report 6: Users and IPs
        self._report_users_ips()

        # Report 7: Full suspicious event details (JSON)
        self._report_full_json()

        print(f"\n{'='*60}")
        print(f"ANALYSIS COMPLETE - Reports saved to: {self.output_dir}")
        print(f"{'='*60}")

    def _report_overview(self):
        path = os.path.join(self.output_dir, '01_overview.txt')
        with open(path, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("EVTX FORENSIC ANALYSIS - OVERVIEW\n")
            f.write(f"Analysis Time: {datetime.now().isoformat()}\n")
            f.write("=" * 60 + "\n\n")

            f.write("FILES ANALYZED:\n")
            f.write("-" * 40 + "\n")
            for fname, count in sorted(self.file_event_counts.items()):
                f.write(f"  {fname}: {count:,} events\n")
            total = sum(self.file_event_counts.values())
            f.write(f"\n  TOTAL EVENTS: {total:,}\n")
            f.write(f"  SUSPICIOUS EVENTS: {len(self.suspicious_events)}\n")
            f.write(f"  MpPreference EVENTS: {len(self.mp_events)}\n")
            f.write(f"  UNIQUE USERS: {len(self.users_seen)}\n")
            f.write(f"  UNIQUE IPs: {len(self.ips_seen)}\n")

        # Also print to console
        print(f"  TOTAL EVENTS PARSED: {total:,}")
        print(f"  SUSPICIOUS EVENTS:   {len(self.suspicious_events)}")
        print(f"  MpPreference EVENTS: {len(self.mp_events)}")
        print(f"  UNIQUE USERS:        {len(self.users_seen)}")
        print(f"  UNIQUE IPs:          {len(self.ips_seen)}")

    def _report_event_ids(self):
        path = os.path.join(self.output_dir, '02_event_id_distribution.txt')
        with open(path, 'w') as f:
            f.write("EVENT ID DISTRIBUTION (Top 50)\n")
            f.write("=" * 60 + "\n")
            for eid, count in self.event_id_counts.most_common(50):
                label = ''
                eid_num = eid.split(' ')[0]
                if eid_num in INTERESTING_EVENT_IDS:
                    label = f" *** {INTERESTING_EVENT_IDS[eid_num]}"
                f.write(f"  {eid}: {count:>8,}{label}\n")

    def _report_suspicious(self):
        path = os.path.join(self.output_dir, '03_suspicious_events.txt')
        with open(path, 'w') as f:
            f.write("SUSPICIOUS EVENTS\n")
            f.write("=" * 60 + "\n")
            f.write(f"Total suspicious: {len(self.suspicious_events)}\n\n")

            # Group by severity
            high = [e for e in self.suspicious_events if e.get('severity') == 'HIGH']
            med = [e for e in self.suspicious_events if e.get('severity') == 'MEDIUM']

            f.write(f"HIGH severity: {len(high)}\n")
            f.write(f"MEDIUM severity: {len(med)}\n\n")

            # Pattern frequency
            pattern_counts = Counter()
            for e in self.suspicious_events:
                for p in e.get('matched_patterns', []):
                    pattern_counts[p] += 1

            f.write("PATTERN MATCH FREQUENCY:\n")
            f.write("-" * 40 + "\n")
            for pat, cnt in pattern_counts.most_common(30):
                f.write(f"  {cnt:>5} hits : {pat}\n")

            f.write("\n\n" + "=" * 60 + "\n")
            f.write("HIGH SEVERITY EVENTS (Detail)\n")
            f.write("=" * 60 + "\n")
            for e in sorted(high, key=lambda x: x.get('timestamp', '')):
                f.write(f"\n[{e.get('timestamp','')}] EventID={e['event_id']} "
                        f"Channel={e.get('channel','')} File={e.get('source_file','')}\n")
                f.write(f"  Patterns: {', '.join(e.get('matched_patterns',[]))}\n")
                for k, v in e.get('event_data', {}).items():
                    if v and len(v.strip()) > 0:
                        f.write(f"  {k}: {v[:500]}\n")
                f.write("-" * 40 + "\n")

            f.write("\n\n" + "=" * 60 + "\n")
            f.write("MEDIUM SEVERITY EVENTS (Detail)\n")
            f.write("=" * 60 + "\n")
            for e in sorted(med, key=lambda x: x.get('timestamp', '')):
                f.write(f"\n[{e.get('timestamp','')}] EventID={e['event_id']} "
                        f"Channel={e.get('channel','')} File={e.get('source_file','')}\n")
                f.write(f"  Patterns: {', '.join(e.get('matched_patterns',[]))}\n")
                for k, v in e.get('event_data', {}).items():
                    if v and len(v.strip()) > 0:
                        f.write(f"  {k}: {v[:500]}\n")
                f.write("-" * 40 + "\n")

    def _report_mp_events(self):
        path = os.path.join(self.output_dir, '04_mppreference_defender_tampering.txt')
        with open(path, 'w') as f:
            f.write("MpPreference / DEFENDER TAMPERING EVENTS\n")
            f.write("=" * 60 + "\n")
            f.write(f"Total MpPreference events: {len(self.mp_events)}\n\n")

            for e in sorted(self.mp_events, key=lambda x: x.get('timestamp', '')):
                f.write(f"\n[{e.get('timestamp','')}] EventID={e['event_id']} "
                        f"Channel={e.get('channel','')} Computer={e.get('computer','')}\n")
                f.write(f"  Source: {e.get('source_file','')}\n")
                for k, v in e.get('data', {}).items():
                    if v and len(v.strip()) > 0:
                        f.write(f"  {k}: {v[:1000]}\n")
                f.write("-" * 40 + "\n")

            # Also dump raw XML snippets
            f.write("\n\n" + "=" * 60 + "\n")
            f.write("RAW XML SNIPPETS\n")
            f.write("=" * 60 + "\n")
            for e in self.mp_events[:50]:  # limit to first 50
                f.write(f"\n--- {e.get('timestamp','')} ---\n")
                f.write(e.get('snippet', '') + "\n")

    def _report_timeline(self):
        path = os.path.join(self.output_dir, '05_timeline.txt')
        with open(path, 'w') as f:
            f.write("EVENT TIMELINE (Suspicious & Interesting)\n")
            f.write("=" * 60 + "\n")

            sorted_events = sorted(self.timeline, key=lambda x: x.get('timestamp', ''))
            for e in sorted_events:
                severity = e.get('severity', 'INFO')
                marker = '!!!' if severity == 'HIGH' else '! ' if severity == 'MEDIUM' else '  '
                eid = e['event_id']
                label = INTERESTING_EVENT_IDS.get(eid, '')
                mp_flag = ' [MP/DEFENDER]' if e.get('is_mp') else ''

                f.write(f"{marker} [{e.get('timestamp','')}] "
                        f"EID={eid} {label}{mp_flag} "
                        f"({e.get('source_file','')})\n")

                if e.get('matched_patterns'):
                    f.write(f"     Patterns: {', '.join(e['matched_patterns'][:5])}\n")

    def _report_users_ips(self):
        path = os.path.join(self.output_dir, '06_users_and_ips.txt')
        with open(path, 'w') as f:
            f.write("USERS OBSERVED\n")
            f.write("=" * 40 + "\n")
            for u in sorted(self.users_seen):
                f.write(f"  {u}\n")

            f.write(f"\nIP ADDRESSES OBSERVED\n")
            f.write("=" * 40 + "\n")
            for ip in sorted(self.ips_seen):
                f.write(f"  {ip}\n")

    def _report_full_json(self):
        path = os.path.join(self.output_dir, '07_suspicious_full.json')
        with open(path, 'w') as f:
            json.dump(self.suspicious_events, f, indent=2, default=str)

        path2 = os.path.join(self.output_dir, '08_mp_events_full.json')
        with open(path2, 'w') as f:
            json.dump(self.mp_events, f, indent=2, default=str)


if __name__ == '__main__':
    evtx_dir = sys.argv[1] if len(sys.argv) > 1 else '.'
    output_dir = sys.argv[2] if len(sys.argv) > 2 else './evtx_analysis_output'

    analyzer = EVTXAnalyzer(evtx_dir, output_dir)
    print("[*] Starting EVTX parsing...")
    analyzer.parse_all()
    analyzer.generate_reports()
PYEOF

chmod +x "$OUTPUT_DIR/_parser.py"

#=============================================================================
# STEP 3: Run the parser
#=============================================================================
echo ""
echo -e "${BOLD}${CYAN}[STEP 2] Parsing EVTX files...${NC}"
echo ""
python3 "$OUTPUT_DIR/_parser.py" "$EVTX_DIR" "$OUTPUT_DIR"

#=============================================================================
# STEP 4: Summary
#=============================================================================
echo ""
echo -e "${BOLD}${CYAN}[STEP 3] Report Files Generated:${NC}"
echo -e "${GREEN}"
ls -lh "$OUTPUT_DIR"/*.txt "$OUTPUT_DIR"/*.json 2>/dev/null
echo -e "${NC}"

echo -e "${BOLD}${YELLOW}KEY REPORTS TO CHECK:${NC}"
echo -e "  ${RED}03_suspicious_events.txt${NC}   - All flagged malicious activity"
echo -e "  ${RED}04_mppreference_defender_tampering.txt${NC} - Defender evasion (YOUR PRIMARY CONCERN)"
echo -e "  ${YELLOW}05_timeline.txt${NC}            - Chronological attack timeline"
echo -e "  ${GREEN}01_overview.txt${NC}            - High-level summary"
echo -e "  ${GREEN}02_event_id_distribution.txt${NC} - Event ID breakdown"
echo ""
echo -e "${BOLD}Quick view of critical findings:${NC}"
echo ""

if [ -f "$OUTPUT_DIR/03_suspicious_events.txt" ]; then
    head -30 "$OUTPUT_DIR/03_suspicious_events.txt"
fi

echo ""
echo -e "${BOLD}${CYAN}Done. All reports in: ${OUTPUT_DIR}${NC}"
