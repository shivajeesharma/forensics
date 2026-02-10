#!/usr/bin/env python3
"""
================================================================================
 NOVA (formerly RALord) RANSOMWARE - INCIDENT RESPONSE & THREAT HUNTING TOOLKIT
================================================================================
 Author:  SOC/IR Team
 Version: 2.1
 Date:    2026-02-09
 
 PURPOSE:
   Comprehensive IR toolkit for detecting, investigating, and timeline-building
   a Nova/RALord ransomware intrusion across Windows, Linux, and macOS endpoints.

 THREAT PROFILE:
   - Group:     Nova RaaS (formerly RALord, rebranded April 2025)
   - Payload:   Rust-based ransomware binary
   - Extension: .ralord (appended to encrypted files)
   - Model:     RaaS (85% affiliate / 15% operator)
   - TTPs:      Credential abuse, exposed RDP/VPN, phishing, backup destruction,
                security tool disabling, lateral movement via admin tools, data exfil + encryption
   - MITRE:     T1574, T1562, T1083, T1486, T1490, T1059, T1021, T1078, T1048

 MODULES:
   1.  IOC Scanner          - Known hashes, file extensions, ransom notes, network IOCs
   2.  Persistence Hunter   - Registry, services, tasks, cron, IFEO, COM, AppInit, LSA, LD_PRELOAD
   3.  Lateral Movement     - RDP, SMB, WMI, PsExec, SSH traces
   4.  Exfiltration Detect  - Large outbound transfers, cloud upload tools, staging dirs
   5a. Defense Evasion      - Disabled AV/EDR, tampered logs, shadow copies, firewall, NTFS ADS, XProtect, TCC
   5b. Credential Artifacts - LSASS dumps, hive copies, PowerShell history, user accounts
   5c. Rootkit Detector     - Unsigned drivers, hidden processes, kernel module tampering
   5d. Web Shell Detector   - Web shell pattern detection in web server directories
   5e. Certificate Auditor  - Trust store audit for rogue/recently added CA certificates
   6.  Live Triage          - Current connections, processes, users, open files
   7.  Timeline Builder     - Consolidates all findings into a chronological timeline
   8.  EVTX Analyzer        - Offline .evtx event log parsing (Security, System, Sysmon, PS, RDP)
   *   Nova Confidence Scorer - Weighted attribution scoring for definitive Nova identification
   *   MITRE ATT&CK Report   - Tactic-by-tactic MITRE mapped report (JSON + TXT)

 MODES:
   LIVE    - Full system analysis with all modules (default)
   OFFLINE - EVTX-only analysis, no live system checks (auto when --evtx without --modules)

 USAGE:
   Run as Administrator/root:
     python3 nova_ir_toolkit.py                                  (LIVE: all modules)
     python3 nova_ir_toolkit.py --modules all --evtx /path/      (LIVE + EVTX)
     python3 nova_ir_toolkit.py --evtx /path/to/logs/            (OFFLINE: auto-detected)
     python3 nova_ir_toolkit.py --offline --evtx /path/to/logs/  (OFFLINE: explicit)
     python3 nova_ir_toolkit.py --modules ioc,persistence,rootkit,certs
     python3 nova_ir_toolkit.py --quick                          (IOC + Triage only)

 NOTES:
   - Does NOT modify the system (read-only forensics)
   - Saves all findings to JSON + CSV + human-readable report
   - Designed for incident responders; run on potentially compromised hosts
================================================================================
"""

import os
import sys
import json
import csv
import hashlib
import platform
import subprocess
import re
import socket
import struct
import glob
import argparse
import logging
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Optional, Any, Tuple
import xml.etree.ElementTree as ET

# Optional: python-evtx for offline .evtx file parsing
try:
    import Evtx.Evtx as evtx
    import Evtx.Views as evtx_views
    HAS_EVTX = True
except ImportError:
    HAS_EVTX = False

# ============================================================================
# CONFIGURATION & KNOWN IOCs
# ============================================================================

NOVA_IOCS = {
    "sha256_hashes": [
        "456b9adaabae9f3dce2207aa71410987f0a571cd8c11f2e7b41468501a863606",
    ],
    "md5_hashes": [
        "be15f62d14d1cbe2aecce8396f4c6289",   # Primary Nova payload
        "ef846baabc14fe461cff4c4a0fd5056f",    # RALord-era payload variant
        "4566f5ba6d1a1db0dd7794ea8d791b3f",    # Nova dropper component
        "4924b945cfdc5bfece03f5140a546384",    # Nova encryptor module
    ],
    "file_extensions": [
        ".ralord",   # Primary extension (RALord era)
        ".nova",     # Used by some Nova affiliates
        ".LORD",     # Alternate RALord extension (case-sensitive)
        ".RNOVA",    # Seen in recent Nova campaigns
    ],
    "ransom_note_names": [
        "README.txt",
        "RECOVERY.txt",
        "HOW_TO_RECOVER.txt",
        "RESTORE_FILES.txt",
        "!README!.txt",
    ],
    # Pattern: README-<12_random_alphanum>.txt (e.g. README-a8b3f1c9e2d4.txt)
    "ransom_note_pattern": r"^README-[A-Za-z0-9]{8,14}\.txt$",
    "ransom_note_keywords": [
        "nova", "ralord", "qtox", "tox id", "your files have been encrypted",
        "data has been stolen", "onion", "session messenger", "jabber",
        "novavdivko2zvtrvtllnq45lxhba2rfzp76qigb4nrliklem5au7czqd",
        "pifk3xu3vad6cuxsjll4qjomyaaaoyvnyqppro75pazadzctrrvpdnyd",
        "novadmrkp4vbk2padk5t6pb",
        "ralordt7gywtkkkkq2suldao6mpibsb7cpjvdfezpzwgltyj2laiuuid",
        "ralordqe33mpufkpsr6zkdatktlu3t2uei4ught3sitxgtzfmqmbsuyd",
    ],
    "tox_ids": [
        "8E9A6195A769FE7115F087C61D75CF32874C339B3AB0947D07480C9A8A12DA5009151BE6A51F",
        "0C8E5B45C57AE244E9C904C5BC74F73306937469D9CEA22541CA69AC162B8D42A20F4C0382AC",
    ],
    "session_tokens": [
        "054f55ec93aca9bac362b9d91eff36a7ce451e7caba47c0b2e004ba429f9529c79",
    ],
    "onion_domains": [
        # Nova-era domains
        "novavdivko2zvtrvtllnq45lxhba2rfzp76qigb4nrliklem5au7czqd.onion",
        "pifk3xu3vad6cuxsjll4qjomyaaaoyvnyqppro75pazadzctrrvpdnyd.onion",
        "novadmrkp4vbk2padk5t6pbxolndceuc7hrcq4mjaoyed6nxsqiuzyyd.onion",
        "novav75eqkjoxct7xuhhwnjw5uaaxvznhtbykq6zal5x7tfevxzjyqyd.onion",
        "novavagygnhqyf7a5tgbuvmujve5a2jzgbrq2n4dvetkhvr2zjg27cad.onion",
        # RALord-era domains (still operational)
        "ralordt7gywtkkkkq2suldao6mpibsb7cpjvdfezpzwgltyj2laiuuid.onion",
        "ralord3htj7v2dkavss2hjzviviwgsf4anfdnihn5qcjl6eb5if3cuqd.onion",
        "ralordqe33mpufkpsr6zkdatktlu3t2uei4ught3sitxgtzfmqmbsuyd.onion",
    ],
    # Suspected C2 infrastructure IPs
    "c2_ips": [
        "144.172.92.192",
        "144.172.95.78",
    ],
    # Common tools used by Nova affiliates (dual-use / LOLBins)
    "suspicious_tools": [
        "rclone", "rclone.exe",
        "psexec", "psexec.exe", "psexec64.exe",
        "megasync", "megasync.exe",
        "winscp", "winscp.exe",
        "filezilla", "filezilla.exe",
        "netscan", "netscan.exe",
        "advanced_ip_scanner", "advanced_ip_scanner.exe",
        "mimikatz", "mimikatz.exe",
        "lazagne", "lazagne.exe",
        "sharphound", "sharphound.exe",
        "bloodhound",
        "cobalt", "beacon",
        "anydesk", "anydesk.exe",
        "splashtop",
        "atera_agent",
        "chisel", "chisel.exe",
        "ngrok", "ngrok.exe",
    ],
    # Suspicious process names
    "suspicious_processes": [
        "rclone", "psexec", "megasync", "winscp", "netscan",
        "mimikatz", "lazagne", "sharphound", "bloodhound",
        "anydesk", "chisel", "ngrok", "tor",
    ],
}

# MITRE ATT&CK mapping for Nova/RALord
MITRE_MAPPING = {
    "T1078": "Valid Accounts - Compromised credentials / exposed RDP-VPN",
    "T1566": "Phishing - Spear-phishing for initial access",
    "T1574": "Hijack Execution Flow - Registry/file path poisoning for persistence",
    "T1562": "Impair Defenses - Disable AV, EDR, tamper protection",
    "T1083": "File and Directory Discovery - .ini files, sensitive data hunting",
    "T1486": "Data Encrypted for Impact - .ralord extension encryption",
    "T1490": "Inhibit System Recovery - Shadow copy & backup deletion",
    "T1059": "Command and Scripting Interpreter - PowerShell, cmd, bash",
    "T1021": "Remote Services - RDP, SMB, SSH lateral movement",
    "T1048": "Exfiltration Over Alternative Protocol - rclone, mega, etc.",
    "T1053": "Scheduled Task/Job - Persistence via scheduled tasks/cron",
    "T1112": "Modify Registry - Disable security features via registry",
    "T1018": "Remote System Discovery - Network scanning tools",
    "T1570": "Lateral Tool Transfer - Moving tools across network",
    "T1055": "Process Injection - Evading detection",
    "T1003": "OS Credential Dumping - LSASS, SAM, NTDS.dit extraction",
    "T1136": "Create Account - Attacker-created local/domain accounts",
    "T1197": "BITS Jobs - Background transfer for persistence/exfil",
    "T1546": "Event Triggered Execution - WMI event subscriptions",
    "T1547": "Boot or Logon Autostart Execution - Registry run keys",
    "T1074": "Data Staged - Archives staged for exfiltration",
    "T1133": "External Remote Services - Exposed VPN/RDP/Citrix for initial access",
    "T1204": "User Execution - User opens malicious attachment/link",
    "T1106": "Native API - Direct Windows API calls to bypass security hooks",
    "T1068": "Exploitation for Privilege Escalation - Kernel/software exploit for SYSTEM",
    "T1027": "Obfuscated Files or Information - Packed/encrypted payloads",
    "T1497": "Virtualization/Sandbox Evasion - Anti-VM/anti-sandbox checks",
    "T1082": "System Information Discovery - Enumerating OS, hardware, domain",
    "T1012": "Query Registry - Reading registry for config/credential data",
    "T1550": "Use Alternate Authentication Material - Pass-the-hash/pass-the-ticket",
    "T1005": "Data from Local System - Collecting files for exfiltration",
    "T1071": "Application Layer Protocol - C2 over HTTP/HTTPS/DNS",
    "T1491": "Defacement - Desktop wallpaper changed to ransom message",
    "T1070": "Indicator Removal - Log clearing and anti-forensics",
    "T1543": "Create or Modify System Process - Persistence via services",
    "T1110": "Brute Force - Repeated failed logon attempts",
    "T1098": "Account Manipulation - Modifying account permissions/group membership",
    "T1014": "Rootkit - Hiding processes, files, or drivers from OS view",
    "T1505.003": "Web Shell - Persistent backdoor in web-accessible directory",
    "T1553": "Subvert Trust Controls - Certificate/trust store tampering",
    "T1564": "Hide Artifacts - NTFS Alternate Data Streams or hidden files",
    "T1546.008": "Accessibility Features - sethc/utilman/osk/narrator hijacking",
    "T1546.012": "Image File Execution Options Injection - IFEO debugger hijacking",
    "T1546.015": "Component Object Model Hijacking - COM object persistence",
    "T1547.010": "Port Monitors - Print monitor DLL persistence",
    "T1547.002": "Authentication Package - LSA authentication/notification package persistence",
    "T1574.001": "DLL Search Order Hijacking - AppInit_DLLs / DLL preloading",
}


# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging(output_dir: str) -> logging.Logger:
    logger = logging.getLogger("nova_ir")
    logger.setLevel(logging.DEBUG)
    
    fh = logging.FileHandler(os.path.join(output_dir, "nova_ir_debug.log"))
    fh.setLevel(logging.DEBUG)
    
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    
    fmt = logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
    fh.setFormatter(fmt)
    ch.setFormatter(fmt)
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_os_type() -> str:
    s = platform.system().lower()
    if s == "darwin":
        return "macos"
    return s  # "windows" or "linux"


def get_os_info() -> Dict[str, str]:
    """Return detailed OS identification: type, version, distribution, architecture."""
    info: Dict[str, str] = {
        "os_type": get_os_type(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "hostname": socket.gethostname(),
        "version": "",
        "distribution": "",
        "kernel": "",
    }
    os_type = info["os_type"]

    if os_type == "windows":
        info["version"] = platform.version()  # e.g. "10.0.19041"
        win_ver = platform.win32_ver()  # ('10', '10.0.19041', 'SP0', 'Multiprocessor Free')
        if win_ver and win_ver[0]:
            info["distribution"] = f"Windows {win_ver[0]}"
        else:
            info["distribution"] = f"Windows {platform.release()}"
        # Try to get edition (Pro, Server, Enterprise)
        try:
            out, _, rc = run_cmd('wmic os get Caption /value 2>nul', timeout=10)
            if rc == 0 and out:
                for line in out.split("\n"):
                    if "Caption=" in line:
                        info["distribution"] = line.split("=", 1)[1].strip()
                        break
        except Exception:
            pass

    elif os_type == "linux":
        info["kernel"] = platform.release()  # e.g. "5.15.0-76-generic"
        # Read /etc/os-release for distro info (works on all modern distros)
        distro_name = ""
        distro_version = ""
        try:
            with open("/etc/os-release", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("PRETTY_NAME="):
                        info["distribution"] = line.split("=", 1)[1].strip().strip('"')
                    elif line.startswith("NAME="):
                        distro_name = line.split("=", 1)[1].strip().strip('"')
                    elif line.startswith("VERSION_ID="):
                        distro_version = line.split("=", 1)[1].strip().strip('"')
                    elif line.startswith("VERSION="):
                        info["version"] = line.split("=", 1)[1].strip().strip('"')
        except (FileNotFoundError, PermissionError):
            pass

        if not info["distribution"]:
            # Fallback: try lsb_release, /etc/redhat-release, etc.
            for release_file in ["/etc/redhat-release", "/etc/centos-release",
                                 "/etc/fedora-release", "/etc/debian_version",
                                 "/etc/SuSE-release", "/etc/alpine-release"]:
                try:
                    with open(release_file, "r") as f:
                        info["distribution"] = f.read().strip()
                        break
                except (FileNotFoundError, PermissionError):
                    continue

        if not info["distribution"] and distro_name:
            info["distribution"] = f"{distro_name} {distro_version}".strip()

        if not info["distribution"]:
            info["distribution"] = f"Linux ({info['kernel']})"

    elif os_type == "macos":
        info["kernel"] = platform.release()
        mac_ver = platform.mac_ver()  # ('14.5', ('', '', ''), 'arm64')
        if mac_ver and mac_ver[0]:
            info["version"] = mac_ver[0]
            # Map macOS version to name
            major = int(mac_ver[0].split(".")[0]) if mac_ver[0] else 0
            mac_names = {
                11: "Big Sur", 12: "Monterey", 13: "Ventura",
                14: "Sonoma", 15: "Sequoia",
            }
            name = mac_names.get(major, "")
            info["distribution"] = f"macOS {mac_ver[0]} {name}".strip()
        else:
            info["distribution"] = f"macOS ({platform.platform()})"

    return info


# Module applicability per OS
OS_MODULE_MAP = {
    "windows": {
        "ioc": "Full (file scan, hash check, tools, ransom notes)",
        "persistence": "Full (registry, services, scheduled tasks, WMI, BITS, IFEO, COM, AppInit, Print Monitors, LSA, Accessibility)",
        "lateral": "Full (RDP, SMB, WMI, PsExec, logon events)",
        "exfil": "Full (rclone config, staging dirs, outbound connections)",
        "evasion": "Full (Defender, shadow copies, event logs, tamper protection, firewall audit, NTFS ADS)",
        "creds": "Full (LSASS dumps, hive copies, PowerShell history, user accounts)",
        "triage": "Full (processes, connections, DNS cache, listeners)",
        "evtx": "Full (offline .evtx event log parsing)",
        "rootkit": "Full (unsigned drivers, test signing, known rootkit driver names)",
        "webshell": "Full (IIS/XAMPP web root scanning)",
        "certs": "Full (root certificate store audit)",
    },
    "linux": {
        "ioc": "Full (file scan, hash check, tools, ransom notes)",
        "persistence": "Full (cron, systemd, authorized_keys, rc.local, profiles, LD_PRELOAD, kernel modules)",
        "lateral": "Full (SSH history, auth.log, failed logins)",
        "exfil": "Full (rclone config, staging dirs, outbound connections)",
        "evasion": "Full (security services, log integrity, iptables, bash history)",
        "creds": "Full (/proc analysis, shadow copies, user accounts, network recon)",
        "triage": "Full (processes, connections, listeners)",
        "evtx": "Offline only (parses Windows .evtx files collected from other hosts)",
        "rootkit": "Full (hidden processes, deleted binaries, kernel module discrepancies)",
        "webshell": "Full (Apache/Nginx web root scanning)",
        "certs": "Full (CA certificate store freshness audit)",
    },
    "macos": {
        "ioc": "Full (file scan, hash check, tools, ransom notes)",
        "persistence": "Full (LaunchAgents, LaunchDaemons, login items)",
        "lateral": "Partial (login history, Screen Sharing/ARD)",
        "exfil": "Full (rclone config, staging dirs, outbound connections)",
        "evasion": "Full (Gatekeeper, SIP, XProtect freshness, TCC permissions)",
        "creds": "Partial (user accounts, network recon)",
        "triage": "Full (processes, connections, listeners)",
        "evtx": "Offline only (parses Windows .evtx files collected from other hosts)",
        "rootkit": "Full (non-Apple kexts, system extensions, binary code signing)",
        "webshell": "Full (macOS web server root scanning)",
        "certs": "Full (System keychain certificate audit)",
    },
}

def run_cmd(cmd: str, shell: bool = True, timeout: int = 60) -> Tuple[str, str, int]:
    """Execute a command and return stdout, stderr, returncode."""
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except Exception as e:
        return "", str(e), -1

def hash_file(filepath: str, algo: str = "sha256") -> Optional[str]:
    """Hash a file without reading it entirely into memory."""
    try:
        h = hashlib.new(algo)
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError):
        return None

def safe_stat(filepath: str) -> Optional[Dict]:
    """Get file timestamps safely."""
    try:
        st = os.stat(filepath)
        return {
            "path": filepath,
            "size_bytes": st.st_size,
            "created": datetime.fromtimestamp(st.st_ctime, tz=timezone.utc).isoformat(),
            "modified": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
            "accessed": datetime.fromtimestamp(st.st_atime, tz=timezone.utc).isoformat(),
        }
    except (PermissionError, OSError):
        return None

def run_cmd_list(cmd_args: List[str], timeout: int = 60) -> Tuple[str, str, int]:
    """Execute a command as a list (no shell) — safer on compromised hosts."""
    try:
        r = subprocess.run(cmd_args, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except Exception as e:
        return "", str(e), -1

def severity_label(sev: int) -> str:
    return {1: "INFO", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}.get(sev, "UNKNOWN")


class SystemDataCache:
    """Cache shared data so modules don't re-run the same expensive commands."""

    def __init__(self):
        self._process_list: Optional[str] = None
        self._netstat_output: Optional[str] = None

    def get_process_list(self) -> str:
        if self._process_list is None:
            os_type = get_os_type()
            if os_type == "windows":
                self._process_list, _, _ = run_cmd("tasklist /v /fo csv 2>nul")
            else:
                self._process_list, _, _ = run_cmd("ps auxww 2>/dev/null")
        return self._process_list

    def get_netstat_output(self) -> str:
        if self._netstat_output is None:
            os_type = get_os_type()
            if os_type == "windows":
                self._netstat_output, _, _ = run_cmd("netstat -naob 2>nul", timeout=15)
            else:
                self._netstat_output, _, _ = run_cmd("ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null", timeout=15)
        return self._netstat_output


# Global shared cache — instantiated once in main()
_system_cache: Optional[SystemDataCache] = None

def get_system_cache() -> SystemDataCache:
    global _system_cache
    if _system_cache is None:
        _system_cache = SystemDataCache()
    return _system_cache


# ============================================================================
# FINDING DATA STRUCTURE
# ============================================================================

class Finding:
    """Represents a single IR finding."""
    def __init__(self, module: str, title: str, description: str,
                 severity: int = 3, mitre_id: str = "",
                 evidence: Any = None, timestamp: str = ""):
        self.module = module
        self.title = title
        self.description = description
        self.severity = severity  # 1-5
        self.mitre_id = mitre_id
        self.mitre_name = MITRE_MAPPING.get(mitre_id, "")
        self.evidence = evidence or {}
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> Dict:
        return {
            "module": self.module,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "severity_label": severity_label(self.severity),
            "mitre_id": self.mitre_id,
            "mitre_name": self.mitre_name,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }


# ============================================================================
# MODULE 1: IOC SCANNER
# ============================================================================

class IOCScanner:
    """Scan for known Nova/RALord indicators of compromise."""
    
    MODULE = "IOC_SCANNER"
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.findings: List[Finding] = []
    
    def scan_encrypted_files(self) -> List[Finding]:
        """Find files with Nova/RALord encryption extensions."""
        extensions = NOVA_IOCS["file_extensions"]
        ext_list = ", ".join(extensions)
        self.logger.info(f"[IOC] Scanning for encrypted files with extensions: {ext_list}")
        self.logger.info("  WHY: Nova/RALord appends these extensions to files after encryption.")
        self.logger.info("       Finding these confirms active encryption on this host.")
        os_type = get_os_type()

        if os_type == "windows":
            drives = []
            for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
                if os.path.exists(f"{letter}:\\"):
                    drives.append(f"{letter}:\\")
            search_roots = drives
        elif os_type == "macos":
            search_roots = ["/Users", "/Volumes", "/tmp", "/var"]
        else:  # linux
            search_roots = ["/home", "/tmp", "/var", "/opt", "/srv", "/root"]

        encrypted_files = []
        ext_set = set(e.lower() for e in extensions)
        for root in search_roots:
            if len(encrypted_files) >= 500:  # global cap across all roots
                break
            try:
                for dirpath, _, filenames in os.walk(root, followlinks=False):
                    for fname in filenames:
                        # Check against all known Nova encrypted file extensions
                        _, fext = os.path.splitext(fname)
                        if fext.lower() in ext_set:
                            fpath = os.path.join(dirpath, fname)
                            stat_info = safe_stat(fpath)
                            entry = stat_info or {"path": fpath}
                            entry["extension"] = fext
                            encrypted_files.append(entry)
                            if len(encrypted_files) >= 500:
                                break
                    if len(encrypted_files) >= 500:
                        break
            except (PermissionError, OSError):
                continue

        if encrypted_files:
            f = Finding(
                self.MODULE,
                "ENCRYPTED FILES DETECTED",
                f"Found {len(encrypted_files)} files encrypted by Nova/RALord ransomware (extensions: {ext_list})",
                severity=5,
                mitre_id="T1486",
                evidence={"encrypted_files": encrypted_files[:100], "total_count": len(encrypted_files)},
            )
            self.findings.append(f)
            self.logger.critical(f"[IOC] CRITICAL: Found {len(encrypted_files)} encrypted files!")
        else:
            self.logger.info(f"[IOC] No encrypted files found with extensions: {ext_list}")

        return self.findings
    
    def scan_ransom_notes(self) -> List[Finding]:
        """Find ransom notes by name, pattern, and keyword content."""
        note_names = NOVA_IOCS["ransom_note_names"]
        note_pattern = NOVA_IOCS.get("ransom_note_pattern", "")
        self.logger.info(f"[IOC] Scanning for ransom notes matching: {', '.join(note_names)}")
        self.logger.info(f"  ALSO: Pattern-matching README-<random>.txt (Nova's randomized naming)")
        self.logger.info("  WHY: Nova drops ransom notes in every encrypted directory. Finding these")
        self.logger.info("       confirms the ransomware ran, and note content reveals the threat actor,")
        self.logger.info("       their Tox ID, onion domains, and negotiation terms.")
        os_type = get_os_type()

        if os_type == "windows":
            search_roots = ["C:\\Users", "C:\\"]
        elif os_type == "macos":
            search_roots = ["/Users", "/tmp"]
        else:
            search_roots = ["/home", "/tmp", "/root", "/var"]

        note_pattern_re = re.compile(note_pattern) if note_pattern else None
        found_notes = []
        for root in search_roots:
            try:
                for dirpath, _, filenames in os.walk(root, followlinks=False):
                    for fname in filenames:
                        matched_name = fname in note_names
                        matched_pattern = bool(note_pattern_re and note_pattern_re.match(fname))
                        if matched_name or matched_pattern:
                            fpath = os.path.join(dirpath, fname)
                            stat_info = safe_stat(fpath)
                            note_info = {
                                "path": fpath,
                                "filename": fname,
                                "directory": dirpath,
                                "matched_by": "pattern" if matched_pattern else "filename",
                            }
                            if stat_info:
                                note_info["size_bytes"] = stat_info.get("size_bytes", 0)
                                note_info["created"] = stat_info.get("created", "")
                                note_info["modified"] = stat_info.get("modified", "")
                            # Check content for Nova-specific keywords and extract contact info
                            try:
                                with open(fpath, "r", errors="ignore") as nf:
                                    raw_content = nf.read(4096)
                                    content = raw_content.lower()
                                    matched_kw = [kw for kw in NOVA_IOCS["ransom_note_keywords"] if kw in content]
                                    if matched_kw:
                                        note_info["matched_keywords"] = matched_kw
                                        note_info["confirmed_nova"] = True
                                        note_info["matched_by"] += "+content"
                                    # Extract Tox IDs (64-76 hex chars)
                                    tox_matches = re.findall(r'[A-Fa-f0-9]{64,76}', raw_content)
                                    if tox_matches:
                                        note_info["extracted_tox_ids"] = tox_matches[:5]
                                    # Extract onion domains
                                    onion_matches = re.findall(r'[a-z2-7]{16,56}\.onion', raw_content, re.I)
                                    if onion_matches:
                                        note_info["extracted_onion_domains"] = onion_matches[:5]
                                    # Extract email addresses
                                    email_matches = re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', raw_content)
                                    if email_matches:
                                        note_info["extracted_emails"] = email_matches[:5]
                                    # Extract BTC/XMR wallet addresses
                                    btc_matches = re.findall(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', raw_content)
                                    xmr_matches = re.findall(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b', raw_content)
                                    if btc_matches:
                                        note_info["extracted_btc_wallets"] = btc_matches[:3]
                                    if xmr_matches:
                                        note_info["extracted_xmr_wallets"] = xmr_matches[:3]
                            except (PermissionError, OSError):
                                pass
                            found_notes.append(note_info)
            except (PermissionError, OSError):
                continue
        
        if found_notes:
            confirmed = [n for n in found_notes if n.get("confirmed_nova")]
            sev = 5 if confirmed else 4
            f = Finding(
                self.MODULE,
                "RANSOM NOTES FOUND" + (" (CONFIRMED NOVA)" if confirmed else " (POTENTIAL)"),
                f"Found {len(found_notes)} ransom notes, {len(confirmed)} confirmed Nova/RALord",
                severity=sev,
                mitre_id="T1486",
                evidence={"ransom_notes": found_notes[:50]},
            )
            self.findings.append(f)
        
        return self.findings
    
    def scan_known_hashes(self, scan_dirs: Optional[List[str]] = None) -> List[Finding]:
        """Scan common directories for files matching known Nova hashes."""
        self.logger.info(f"[IOC] Scanning for known malware hashes ({len(NOVA_IOCS['sha256_hashes'])} SHA256, {len(NOVA_IOCS['md5_hashes'])} MD5)")
        self.logger.info("  WHY: These are confirmed Nova/RALord ransomware binaries, droppers, and")
        self.logger.info("       encryptor modules. A hash match is definitive proof of the malware.")
        os_type = get_os_type()
        
        if scan_dirs is None:
            if os_type == "windows":
                scan_dirs = [
                    os.path.expandvars(r"%TEMP%"),
                    os.path.expandvars(r"%APPDATA%"),
                    os.path.expandvars(r"%LOCALAPPDATA%"),
                    os.path.expandvars(r"%PROGRAMDATA%"),
                    r"C:\PerfLogs",
                    r"C:\Windows\Temp",
                    os.path.expandvars(r"%USERPROFILE%\Downloads"),
                    os.path.expandvars(r"%USERPROFILE%\Desktop"),
                ]
            elif os_type == "macos":
                scan_dirs = ["/tmp", "/var/tmp", "/private/tmp",
                             os.path.expanduser("~/Downloads"),
                             os.path.expanduser("~/Desktop"),
                             "/Library/Application Support"]
            else:
                scan_dirs = ["/tmp", "/var/tmp", "/dev/shm",
                             os.path.expanduser("~/Downloads") if os.path.expanduser("~") != "~" else "/tmp",
                             "/opt", "/var/log"]
        
        known_sha256 = set(h.lower() for h in NOVA_IOCS["sha256_hashes"])
        known_md5 = set(h.lower() for h in NOVA_IOCS["md5_hashes"])
        matched = []
        
        for scan_dir in scan_dirs:
            if not os.path.exists(scan_dir):
                continue
            try:
                for dirpath, _, filenames in os.walk(scan_dir, followlinks=False):
                    for fname in filenames:
                        fpath = os.path.join(dirpath, fname)
                        try:
                            fsize = os.path.getsize(fpath)
                            if fsize > 100_000_000 or fsize < 100:  # skip very large/tiny
                                continue
                        except OSError:
                            continue
                        
                        sha = hash_file(fpath, "sha256")
                        if sha and sha.lower() in known_sha256:
                            matched.append({"path": fpath, "sha256": sha, "match_type": "sha256"})
                            continue
                        
                        md5 = hash_file(fpath, "md5")
                        if md5 and md5.lower() in known_md5:
                            matched.append({"path": fpath, "md5": md5, "match_type": "md5"})
            except (PermissionError, OSError):
                continue
        
        if matched:
            f = Finding(
                self.MODULE,
                "KNOWN NOVA MALWARE BINARY DETECTED",
                f"Found {len(matched)} file(s) matching known Nova/RALord malware hashes",
                severity=5,
                mitre_id="T1486",
                evidence={"matched_files": matched},
            )
            self.findings.append(f)
            self.logger.critical(f"[IOC] CRITICAL: {len(matched)} known malware hash matches!")
        
        return self.findings
    
    def scan_suspicious_tools(self) -> List[Finding]:
        """Find known attacker tools on disk."""
        self.logger.info(f"[IOC] Scanning for {len(NOVA_IOCS['suspicious_tools'])} known attacker/dual-use tools on disk")
        self.logger.info("  SEARCHING: rclone, PsExec, mimikatz, LaZagne, SharpHound, BloodHound,")
        self.logger.info("             AnyDesk, Chisel, ngrok, MegaSync, WinSCP, netscan, etc.")
        self.logger.info("  WHY: Nova affiliates deploy these tools for credential theft (mimikatz),")
        self.logger.info("       data exfiltration (rclone, MegaSync), lateral movement (PsExec),")
        self.logger.info("       network recon (netscan), and tunneling (chisel, ngrok).")
        os_type = get_os_type()
        
        if os_type == "windows":
            search_dirs = [
                os.path.expandvars(r"%TEMP%"),
                os.path.expandvars(r"%APPDATA%"),
                os.path.expandvars(r"%PROGRAMDATA%"),
                os.path.expandvars(r"%USERPROFILE%\Desktop"),
                os.path.expandvars(r"%USERPROFILE%\Downloads"),
                r"C:\PerfLogs",
                r"C:\Windows\Temp",
            ]
        elif os_type == "macos":
            search_dirs = ["/tmp", "/var/tmp", os.path.expanduser("~/Downloads"),
                           os.path.expanduser("~/Desktop"), "/usr/local/bin"]
        else:
            search_dirs = ["/tmp", "/var/tmp", "/dev/shm", "/opt",
                           os.path.expanduser("~/Downloads") if os.path.expanduser("~") != "~" else "/tmp"]
        
        found_tools = []
        tool_names = set(t.lower() for t in NOVA_IOCS["suspicious_tools"])
        
        for scan_dir in search_dirs:
            if not os.path.exists(scan_dir):
                continue
            try:
                for dirpath, _, filenames in os.walk(scan_dir, followlinks=False):
                    for fname in filenames:
                        if fname.lower() in tool_names:
                            fpath = os.path.join(dirpath, fname)
                            stat_info = safe_stat(fpath) or {"path": fpath}
                            stat_info["tool_name"] = fname
                            stat_info["directory"] = dirpath
                            # Hash the tool for attribution
                            sha = hash_file(fpath, "sha256")
                            if sha:
                                stat_info["sha256"] = sha
                            # Check if tool is currently running
                            proc_list = get_system_cache().get_process_list()
                            if proc_list and fname.lower() in proc_list.lower():
                                stat_info["currently_running"] = True
                            else:
                                stat_info["currently_running"] = False
                            found_tools.append(stat_info)
            except (PermissionError, OSError):
                continue
        
        if found_tools:
            f = Finding(
                self.MODULE,
                "SUSPICIOUS/DUAL-USE TOOLS FOUND",
                f"Found {len(found_tools)} potentially attacker-deployed tools",
                severity=4,
                mitre_id="T1570",
                evidence={"tools": found_tools},
            )
            self.findings.append(f)
        
        return self.findings
    
    def run_all(self) -> List[Finding]:
        self.scan_encrypted_files()
        self.scan_ransom_notes()
        self.scan_known_hashes()
        self.scan_suspicious_tools()
        return self.findings


# ============================================================================
# MODULE 2: PERSISTENCE HUNTER
# ============================================================================

class PersistenceHunter:
    """Detect persistence mechanisms planted by Nova affiliates."""
    
    MODULE = "PERSISTENCE"
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.findings: List[Finding] = []
    
    def check_windows_persistence(self) -> List[Finding]:
        """Check Windows registry run keys, services, scheduled tasks."""
        self.logger.info("[PERSIST] Checking Windows persistence mechanisms...")
        self.logger.info("  SEARCHING: Registry Run/RunOnce keys, scheduled tasks, WMI event subscriptions,")
        self.logger.info("             BITS transfer jobs, auto-start services")
        self.logger.info("  WHY: Nova affiliates establish persistence to survive reboots and maintain")
        self.logger.info("       access. WMI subscriptions and BITS jobs are stealthy methods often missed.")
        
        # --- Registry Run Keys ---
        reg_paths = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ]
        
        suspicious_entries = []
        for rpath in reg_paths:
            out, _, rc = run_cmd(f'reg query "{rpath}" 2>nul')
            if rc == 0 and out:
                for line in out.split("\n"):
                    line_lower = line.lower()
                    suspicious_indicators = [
                        "temp", "appdata", "perflog", "programdata",
                        "powershell", "cmd.exe /c", "mshta", "wscript", "cscript",
                        "rundll32", ".bat", ".vbs", ".ps1", ".hta",
                    ]
                    if any(ind in line_lower for ind in suspicious_indicators):
                        # Parse REG_SZ / REG_EXPAND_SZ lines: "  ValueName    REG_SZ    ValueData"
                        parts = re.split(r'\s{4,}', line.strip(), maxsplit=2)
                        entry = {
                            "registry_key": rpath,
                            "value_name": parts[0].strip() if len(parts) >= 1 else "",
                            "value_type": parts[1].strip() if len(parts) >= 2 else "",
                            "value_data": parts[2].strip() if len(parts) >= 3 else line.strip(),
                            "matched_indicator": next((ind for ind in suspicious_indicators if ind in line_lower), ""),
                        }
                        suspicious_entries.append(entry)
        
        if suspicious_entries:
            self.findings.append(Finding(
                self.MODULE,
                "SUSPICIOUS REGISTRY AUTORUN ENTRIES",
                f"Found {len(suspicious_entries)} suspicious autorun registry entries",
                severity=4, mitre_id="T1547",
                evidence={"entries": suspicious_entries},
            ))
        
        # --- Scheduled Tasks ---
        out, _, rc = run_cmd("schtasks /query /fo CSV /v 2>nul", timeout=30)
        if rc == 0 and out:
            suspicious_tasks = []
            lines = out.split("\n")
            # Parse CSV: first line is header
            header = []
            if lines:
                header = [h.strip().strip('"') for h in lines[0].split(",")]
            for line in lines[1:]:
                line_lower = line.lower()
                if any(t in line_lower for t in ["temp", "appdata", "perflog", "powershell -enc",
                                                  "cmd /c", "wscript", "cscript", ".bat", ".ps1"]):
                    fields = [f.strip().strip('"') for f in line.split(",")]
                    task_entry = {}
                    for i, h in enumerate(header):
                        if i < len(fields):
                            key = h.lower().replace(" ", "_")
                            if key in ("taskname", "task_to_run", "start_in", "run_as_user",
                                       "next_run_time", "last_run_time", "status", "schedule_type"):
                                task_entry[key] = fields[i]
                    if not task_entry:
                        task_entry = {"raw_line": line.strip()}
                    suspicious_tasks.append(task_entry)

            if suspicious_tasks:
                self.findings.append(Finding(
                    self.MODULE,
                    "SUSPICIOUS SCHEDULED TASKS",
                    f"Found {len(suspicious_tasks)} potentially malicious scheduled tasks",
                    severity=4, mitre_id="T1053",
                    evidence={"tasks": suspicious_tasks[:30]},
                ))
        
        # --- WMI Event Subscriptions (common Nova persistence) ---
        wmi_queries = [
            ("EventConsumer", 'wmic /namespace:"\\\\root\\subscription" path __EventConsumer get Name,__CLASS /format:csv 2>nul'),
            ("EventFilter", 'wmic /namespace:"\\\\root\\subscription" path __EventFilter get Name,Query /format:csv 2>nul'),
            ("FilterToConsumerBinding", 'wmic /namespace:"\\\\root\\subscription" path __FilterToConsumerBinding get Consumer,Filter /format:csv 2>nul'),
        ]
        wmi_persist = []
        for wmi_name, wmi_cmd in wmi_queries:
            out, _, rc = run_cmd(wmi_cmd, timeout=15)
            if rc == 0 and out:
                lines = [l.strip() for l in out.split("\n") if l.strip() and not l.startswith("Node")]
                if lines:
                    wmi_persist.append({"type": wmi_name, "entries": lines[:20]})

        if wmi_persist:
            self.findings.append(Finding(
                self.MODULE,
                "WMI EVENT SUBSCRIPTION PERSISTENCE",
                f"Found WMI persistence subscriptions - commonly used by ransomware affiliates",
                severity=5, mitre_id="T1546",
                evidence={"wmi_subscriptions": wmi_persist},
            ))

        # --- BITS Transfer Jobs ---
        out, _, rc = run_cmd("bitsadmin /list /allusers /verbose 2>nul", timeout=15)
        if rc == 0 and out and "GUID" in out:
            # Parse BITS job details
            bits_jobs = []
            current_job: Dict[str, str] = {}
            for line in out.split("\n"):
                line = line.strip()
                if line.startswith("GUID:"):
                    if current_job:
                        bits_jobs.append(current_job)
                    current_job = {"guid": line.split(":", 1)[1].strip()}
                elif ":" in line and current_job:
                    key, _, val = line.partition(":")
                    key = key.strip().lower().replace(" ", "_")
                    if key in ("display_name", "type", "state", "owner", "priority",
                               "files_total", "bytes_total", "bytes_transferred",
                               "creation_time", "modification_time", "no_progress_timeout"):
                        current_job[key] = val.strip()
            if current_job:
                bits_jobs.append(current_job)
            self.findings.append(Finding(
                self.MODULE,
                "BITS TRANSFER JOBS FOUND",
                f"Found {len(bits_jobs)} active BITS jobs - can be used for persistence and data exfiltration",
                severity=3, mitre_id="T1197",
                evidence={"bits_jobs": bits_jobs[:20]},
            ))

        # --- New/Modified Services ---
        out, _, rc = run_cmd(
            'wmic service where "StartMode=\'Auto\'" get Name,PathName,StartName /format:csv 2>nul',
            timeout=30
        )
        if rc == 0 and out:
            suspicious_svcs = []
            for line in out.split("\n"):
                line_lower = line.lower()
                if any(t in line_lower for t in ["temp", "appdata", "perflog", "powershell",
                                                  "cmd.exe", ".bat", "programdata"]):
                    # Parse CSV: Node,Name,PathName,StartName
                    fields = [f.strip() for f in line.split(",")]
                    svc_entry = {
                        "service_name": fields[1] if len(fields) > 1 else "",
                        "executable_path": fields[2] if len(fields) > 2 else "",
                        "run_as_account": fields[3] if len(fields) > 3 else "",
                        "matched_indicator": next((t for t in ["temp", "appdata", "perflog", "powershell",
                                                                "cmd.exe", ".bat", "programdata"]
                                                   if t in line_lower), ""),
                    }
                    suspicious_svcs.append(svc_entry)
            if suspicious_svcs:
                self.findings.append(Finding(
                    self.MODULE,
                    "SUSPICIOUS WINDOWS SERVICES",
                    f"Found {len(suspicious_svcs)} suspicious auto-start services",
                    severity=4, mitre_id="T1543",
                    evidence={"services": suspicious_svcs},
                ))

        # --- IFEO Debugger Hijacking ---
        self.logger.info("  SEARCHING: Image File Execution Options debugger hijacks")
        out, _, rc = run_cmd(
            r'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /v Debugger 2>nul'
        )
        if rc == 0 and out:
            ifeo_entries = []
            current_key = ""
            for line in out.split("\n"):
                line = line.strip()
                if line.startswith("HKEY_"):
                    current_key = line
                elif "Debugger" in line and "REG_SZ" in line:
                    debugger_val = line.split("REG_SZ")[-1].strip().lower()
                    known_safe = ["ntsd.exe", "vsjitdebugger.exe", "windbg.exe", "devenv.exe"]
                    if debugger_val and not any(safe in debugger_val for safe in known_safe):
                        ifeo_entries.append({
                            "registry_key": current_key,
                            "debugger_value": line.split("REG_SZ")[-1].strip(),
                        })
            if ifeo_entries:
                self.findings.append(Finding(
                    self.MODULE,
                    "IFEO DEBUGGER HIJACKING DETECTED",
                    f"Found {len(ifeo_entries)} suspicious IFEO debugger entries - attackers redirect legitimate binaries to malicious payloads",
                    severity=5, mitre_id="T1546.012",
                    evidence={"ifeo_entries": ifeo_entries},
                ))

        # --- COM Object Hijacking ---
        self.logger.info("  SEARCHING: COM object hijacking in HKCU\\CLSID")
        out, _, rc = run_cmd(
            r'reg query "HKCU\SOFTWARE\Classes\CLSID" /s 2>nul', timeout=30
        )
        if rc == 0 and out:
            suspicious_com = []
            current_clsid = ""
            for line in out.split("\n"):
                line = line.strip()
                if "HKEY_CURRENT_USER" in line and "CLSID" in line:
                    current_clsid = line
                elif ("InprocServer32" in line or "LocalServer32" in line) and "REG_" in line:
                    val = line.split("REG_SZ")[-1].strip().lower() if "REG_SZ" in line else line.split("REG_EXPAND_SZ")[-1].strip().lower()
                    suspect_paths = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp", "\\downloads\\",
                                     "\\programdata\\", "\\users\\public\\", "\\perflogs\\"]
                    if any(sp in val for sp in suspect_paths):
                        suspicious_com.append({
                            "clsid_key": current_clsid,
                            "server_path": line.strip(),
                        })
            if suspicious_com:
                self.findings.append(Finding(
                    self.MODULE,
                    "COM OBJECT HIJACKING DETECTED",
                    f"Found {len(suspicious_com)} HKCU COM objects pointing to suspicious paths",
                    severity=4, mitre_id="T1546.015",
                    evidence={"com_entries": suspicious_com},
                ))

        # --- AppInit_DLLs ---
        self.logger.info("  SEARCHING: AppInit_DLLs DLL injection")
        out, _, rc = run_cmd(
            r'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs 2>nul'
        )
        if rc == 0 and out:
            for line in out.split("\n"):
                if "AppInit_DLLs" in line and "REG_SZ" in line:
                    dll_val = line.split("REG_SZ")[-1].strip()
                    if dll_val:
                        # Check if LoadAppInit_DLLs is enabled
                        out2, _, rc2 = run_cmd(
                            r'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs 2>nul'
                        )
                        load_enabled = "0x1" in out2 if rc2 == 0 else False
                        self.findings.append(Finding(
                            self.MODULE,
                            "APPINIT_DLLS INJECTION CONFIGURED",
                            f"AppInit_DLLs set to '{dll_val}' (LoadAppInit_DLLs enabled: {load_enabled}) - used for process-wide DLL injection",
                            severity=5 if load_enabled else 3, mitre_id="T1574.001",
                            evidence={"appinit_dlls": dll_val, "load_enabled": load_enabled},
                        ))

        # --- Print Monitor DLLs ---
        self.logger.info("  SEARCHING: Print Monitor DLL persistence")
        out, _, rc = run_cmd(
            r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors" /s 2>nul'
        )
        if rc == 0 and out:
            known_monitors = ["localspl.dll", "tcpmon.dll", "usbmon.dll", "wsdmon.dll",
                              "apmon.dll", "lprmon.dll", "localui.dll", "tcpmonui.dll",
                              "wsdmonui.dll", "apmui.dll"]
            suspicious_monitors = []
            current_monitor = ""
            for line in out.split("\n"):
                line = line.strip()
                if line.startswith("HKEY_"):
                    current_monitor = line.split("\\")[-1] if "\\" in line else line
                elif "Driver" in line and "REG_SZ" in line:
                    driver_dll = line.split("REG_SZ")[-1].strip().lower()
                    if driver_dll and driver_dll not in known_monitors:
                        suspicious_monitors.append({
                            "monitor_name": current_monitor,
                            "driver_dll": line.split("REG_SZ")[-1].strip(),
                        })
            if suspicious_monitors:
                self.findings.append(Finding(
                    self.MODULE,
                    "SUSPICIOUS PRINT MONITOR DLL",
                    f"Found {len(suspicious_monitors)} non-standard print monitor DLLs - can be used for SYSTEM-level persistence",
                    severity=4, mitre_id="T1547.010",
                    evidence={"monitors": suspicious_monitors},
                ))

        # --- LSA Authentication/Security/Notification Packages ---
        self.logger.info("  SEARCHING: LSA authentication/notification packages")
        known_lsa_defaults = {
            "authentication packages": ["msv1_0", ""],
            "notification packages": ["scecli", ""],
            "security packages": ["kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", ""],
        }
        lsa_suspicious = []
        for value_name, defaults in known_lsa_defaults.items():
            out, _, rc = run_cmd(
                f'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v "{value_name}" 2>nul'
            )
            if rc == 0 and out:
                for line in out.split("\n"):
                    if value_name.lower() in line.lower() and "REG_MULTI_SZ" in line:
                        packages_raw = line.split("REG_MULTI_SZ")[-1].strip()
                        packages = [p.strip().lower() for p in packages_raw.split("\\0") if p.strip()]
                        non_default = [p for p in packages if p not in defaults]
                        if non_default:
                            lsa_suspicious.append({
                                "package_type": value_name,
                                "non_default_entries": non_default,
                                "all_entries": packages,
                            })
        if lsa_suspicious:
            self.findings.append(Finding(
                self.MODULE,
                "NON-DEFAULT LSA PACKAGES DETECTED",
                f"Found {len(lsa_suspicious)} LSA package categories with non-default entries - may indicate credential interception",
                severity=4, mitre_id="T1547.002",
                evidence={"lsa_packages": lsa_suspicious},
            ))

        # --- Accessibility Feature Backdoors ---
        self.logger.info("  SEARCHING: Accessibility feature backdoors (sethc, utilman, osk, narrator, magnify)")
        accessibility_binaries = [
            "sethc.exe", "utilman.exe", "osk.exe", "narrator.exe",
            "magnify.exe", "DisplaySwitch.exe", "AtBroker.exe",
        ]
        accessibility_findings = []
        for binary in accessibility_binaries:
            # Check IFEO debugger for this binary
            out, _, rc = run_cmd(
                f'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{binary}" /v Debugger 2>nul'
            )
            if rc == 0 and "Debugger" in out and "REG_SZ" in out:
                debugger_val = out.split("REG_SZ")[-1].strip()
                if debugger_val:
                    accessibility_findings.append({
                        "binary": binary,
                        "attack_type": "IFEO_debugger",
                        "debugger_value": debugger_val,
                    })
            # Check if binary has been replaced (wrong file size or signature)
            sys_path = f"C:\\Windows\\System32\\{binary}"
            out2, _, rc2 = run_cmd(
                f'powershell -Command "(Get-AuthenticodeSignature \'{sys_path}\').Status" 2>nul',
                timeout=10
            )
            if rc2 == 0 and out2.strip().lower() not in ["valid", "notsigned", ""]:
                accessibility_findings.append({
                    "binary": binary,
                    "attack_type": "invalid_signature",
                    "signature_status": out2.strip(),
                    "path": sys_path,
                })
        if accessibility_findings:
            self.findings.append(Finding(
                self.MODULE,
                "ACCESSIBILITY FEATURE BACKDOOR DETECTED",
                f"Found {len(accessibility_findings)} accessibility binaries with IFEO hijacks or invalid signatures - classic persistence/privilege escalation",
                severity=5, mitre_id="T1546.008",
                evidence={"accessibility_backdoors": accessibility_findings},
            ))

        return self.findings
    
    def check_linux_persistence(self) -> List[Finding]:
        """Check cron, systemd, rc.local, profile scripts, authorized_keys."""
        self.logger.info("[PERSIST] Checking Linux persistence mechanisms...")
        self.logger.info("  SEARCHING: cron jobs, systemd units, rc.local, SSH authorized_keys,")
        self.logger.info("             profile scripts (.bashrc, .profile, .bash_profile)")
        self.logger.info("  WHY: Nova Linux/ESXi payloads use cron and systemd for persistence.")
        self.logger.info("       Attacker SSH keys in authorized_keys provide backdoor re-entry.")
        
        suspicious = []
        
        # --- Cron jobs (all users) ---
        out, _, rc = run_cmd("for user in $(cut -f1 -d: /etc/passwd); do echo \"==$user==\"; crontab -l -u $user 2>/dev/null; done")
        if out:
            for line in out.split("\n"):
                if line.startswith("==") or line.startswith("#") or not line.strip():
                    continue
                line_lower = line.lower()
                if any(t in line_lower for t in ["curl", "wget", "python", "bash -c", "nc ", "ncat",
                                                  "/tmp/", "/dev/shm", "base64", "chmod"]):
                    suspicious.append({"type": "cron", "entry": line.strip()})
        
        # --- System cron directories ---
        cron_dirs = ["/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/",
                     "/etc/cron.weekly/", "/etc/cron.monthly/"]
        for cdir in cron_dirs:
            if os.path.exists(cdir):
                for f in os.listdir(cdir):
                    fpath = os.path.join(cdir, f)
                    stat = safe_stat(fpath)
                    if stat:
                        suspicious.append({"type": "cron_dir_file", "details": stat})
        
        # --- Systemd units (user and system) ---
        systemd_dirs = [
            "/etc/systemd/system/",
            "/usr/lib/systemd/system/",
            os.path.expanduser("~/.config/systemd/user/"),
        ]
        for sdir in systemd_dirs:
            if os.path.exists(sdir):
                try:
                    for f in os.listdir(sdir):
                        if f.endswith(".service") or f.endswith(".timer"):
                            fpath = os.path.join(sdir, f)
                            try:
                                with open(fpath, "r", errors="ignore") as sf:
                                    content = sf.read()
                                    if any(t in content.lower() for t in ["/tmp/", "/dev/shm", "curl",
                                                                           "wget", "python", "base64"]):
                                        suspicious.append({
                                            "type": "systemd_unit",
                                            "path": fpath,
                                            "suspicious_content": True,
                                        })
                            except (PermissionError, OSError):
                                pass
                except (PermissionError, OSError):
                    pass
        
        # --- SSH authorized_keys anomalies ---
        ak_paths = glob.glob("/home/*/.ssh/authorized_keys") + ["/root/.ssh/authorized_keys"]
        for akp in ak_paths:
            if os.path.exists(akp):
                stat = safe_stat(akp)
                try:
                    with open(akp, "r") as f:
                        keys = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                        if keys:
                            suspicious.append({
                                "type": "authorized_keys",
                                "path": akp,
                                "key_count": len(keys),
                                "file_info": stat,
                            })
                except (PermissionError, OSError):
                    pass
        
        # --- rc.local ---
        if os.path.exists("/etc/rc.local"):
            try:
                with open("/etc/rc.local", "r") as f:
                    content = f.read()
                    if len(content.strip()) > 20:  # not just "exit 0"
                        suspicious.append({"type": "rc.local", "content_preview": content[:500]})
            except (PermissionError, OSError):
                pass
        
        # --- Profile scripts ---
        profile_files = ["/etc/profile", "/etc/bash.bashrc", "/etc/environment"]
        profile_files += glob.glob("/home/*/.bashrc") + glob.glob("/home/*/.profile")
        profile_files += glob.glob("/home/*/.bash_profile")
        for pf in profile_files:
            if os.path.exists(pf):
                stat = safe_stat(pf)
                if stat:
                    # Flag recently modified profiles
                    try:
                        mtime = os.path.getmtime(pf)
                        if (datetime.now(timezone.utc).timestamp() - mtime) < 7 * 86400:  # last 7 days
                            suspicious.append({
                                "type": "recently_modified_profile",
                                "details": stat,
                            })
                    except OSError:
                        pass

        # --- LD_PRELOAD Hijacking ---
        self.logger.info("  SEARCHING: LD_PRELOAD hijacking (ld.so.preload, env vars, ld.so.conf)")
        ld_preload_findings = []
        if os.path.exists("/etc/ld.so.preload"):
            try:
                with open("/etc/ld.so.preload", "r") as f:
                    content = f.read().strip()
                    if content:
                        ld_preload_findings.append({
                            "type": "ld.so.preload",
                            "path": "/etc/ld.so.preload",
                            "libraries": [l.strip() for l in content.split("\n") if l.strip()],
                        })
            except (PermissionError, OSError):
                pass
        # Check LD_PRELOAD env in /proc
        for pid_dir in glob.glob("/proc/[0-9]*/environ"):
            try:
                with open(pid_dir, "r", errors="ignore") as f:
                    env_data = f.read()
                    if "LD_PRELOAD=" in env_data:
                        pid = pid_dir.split("/")[2]
                        for entry in env_data.split("\x00"):
                            if entry.startswith("LD_PRELOAD="):
                                ld_preload_findings.append({
                                    "type": "process_env",
                                    "pid": pid,
                                    "ld_preload": entry,
                                })
                                break
            except (PermissionError, OSError):
                pass
        # Check ld.so.conf for entries pointing to suspicious dirs
        ld_conf_files = ["/etc/ld.so.conf"]
        ld_conf_files += glob.glob("/etc/ld.so.conf.d/*.conf")
        for conf_file in ld_conf_files:
            try:
                with open(conf_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            suspect_dirs = ["/tmp", "/dev/shm", "/var/tmp", "/run/shm"]
                            if any(line.startswith(sd) for sd in suspect_dirs):
                                ld_preload_findings.append({
                                    "type": "ld.so.conf_suspicious",
                                    "config_file": conf_file,
                                    "entry": line,
                                })
            except (PermissionError, OSError):
                pass
        if ld_preload_findings:
            self.findings.append(Finding(
                self.MODULE,
                "LD_PRELOAD HIJACKING DETECTED",
                f"Found {len(ld_preload_findings)} LD_PRELOAD-related persistence indicators - used to intercept library calls",
                severity=5, mitre_id="T1574.001",
                evidence={"ld_preload_items": ld_preload_findings},
            ))

        # --- Hidden Kernel Modules ---
        self.logger.info("  SEARCHING: Hidden kernel modules (lsmod vs /proc/modules comparison)")
        try:
            lsmod_out, _, rc1 = run_cmd("lsmod 2>/dev/null")
            proc_out = ""
            if os.path.exists("/proc/modules"):
                with open("/proc/modules", "r") as f:
                    proc_out = f.read()
            if rc1 == 0 and lsmod_out and proc_out:
                lsmod_modules = set()
                for line in lsmod_out.split("\n")[1:]:  # skip header
                    parts = line.split()
                    if parts:
                        lsmod_modules.add(parts[0])
                proc_modules = set()
                for line in proc_out.split("\n"):
                    parts = line.split()
                    if parts:
                        proc_modules.add(parts[0])
                # Modules in /proc but NOT in lsmod = potentially hidden
                hidden = proc_modules - lsmod_modules
                # Modules in lsmod but NOT in /proc = potentially tampered lsmod
                ghost = lsmod_modules - proc_modules
                discrepancies = []
                for m in hidden:
                    discrepancies.append({"module": m, "issue": "in /proc/modules but NOT in lsmod (potentially hidden)"})
                for m in ghost:
                    discrepancies.append({"module": m, "issue": "in lsmod but NOT in /proc/modules (lsmod may be tampered)"})
                if discrepancies:
                    self.findings.append(Finding(
                        self.MODULE,
                        "KERNEL MODULE DISCREPANCIES DETECTED",
                        f"Found {len(discrepancies)} discrepancies between lsmod and /proc/modules - may indicate rootkit",
                        severity=5, mitre_id="T1014",
                        evidence={"discrepancies": discrepancies},
                    ))
        except (PermissionError, OSError):
            pass

        if suspicious:
            self.findings.append(Finding(
                self.MODULE,
                "LINUX PERSISTENCE MECHANISMS",
                f"Found {len(suspicious)} persistence-related items to investigate",
                severity=3, mitre_id="T1053",
                evidence={"items": suspicious},
            ))
        
        return self.findings
    
    def check_macos_persistence(self) -> List[Finding]:
        """Check LaunchAgents, LaunchDaemons, login items."""
        self.logger.info("[PERSIST] Checking macOS persistence mechanisms...")
        self.logger.info("  SEARCHING: LaunchAgents, LaunchDaemons, login items")
        self.logger.info("  WHY: Non-Apple plists in launch directories can indicate malware persistence.")
        
        suspicious = []
        
        launch_dirs = [
            "/Library/LaunchAgents/",
            "/Library/LaunchDaemons/",
            os.path.expanduser("~/Library/LaunchAgents/"),
        ]
        
        for ldir in launch_dirs:
            if not os.path.exists(ldir):
                continue
            try:
                for f in os.listdir(ldir):
                    if f.endswith(".plist"):
                        fpath = os.path.join(ldir, f)
                        stat = safe_stat(fpath)
                        # Flag non-Apple, non-standard plists
                        if not f.startswith("com.apple."):
                            suspicious.append({
                                "type": "launch_plist",
                                "path": fpath,
                                "name": f,
                                "file_info": stat,
                            })
            except (PermissionError, OSError):
                pass
        
        # Login items
        out, _, rc = run_cmd("osascript -e 'tell application \"System Events\" to get the name of every login item' 2>/dev/null")
        if rc == 0 and out:
            suspicious.append({"type": "login_items", "items": out})
        
        if suspicious:
            self.findings.append(Finding(
                self.MODULE,
                "MACOS PERSISTENCE MECHANISMS",
                f"Found {len(suspicious)} persistence-related items",
                severity=3, mitre_id="T1543",
                evidence={"items": suspicious},
            ))
        
        return self.findings
    
    def run_all(self) -> List[Finding]:
        os_type = get_os_type()
        if os_type == "windows":
            self.check_windows_persistence()
        elif os_type == "linux":
            self.check_linux_persistence()
        elif os_type == "macos":
            self.check_macos_persistence()
        return self.findings


# ============================================================================
# MODULE 3: LATERAL MOVEMENT DETECTOR
# ============================================================================

class LateralMovementDetector:
    """Detect signs of lateral movement across the network."""
    
    MODULE = "LATERAL_MOVEMENT"
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.findings: List[Finding] = []
    
    def check_windows_lateral(self) -> List[Finding]:
        self.logger.info("[LATERAL] Checking Windows lateral movement artifacts...")
        self.logger.info("  SEARCHING: RDP sessions (inbound/outbound), SMB/admin share connections,")
        self.logger.info("             WMI remote execution, PsExec service/binary, logon events (Type 3/10)")
        self.logger.info("  WHY: Nova affiliates move laterally via RDP, PsExec, and WMI to reach domain")
        self.logger.info("       controllers and file servers before deploying the ransomware payload.")
        
        # --- RDP Connections (Inbound) ---
        out, _, rc = run_cmd(
            'wevtutil qe "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" '
            '/q:"*[System[(EventID=21 or EventID=25)]]" /f:text /c:50 2>nul',
            timeout=30
        )
        if rc == 0 and out and "Event" in out:
            # Parse individual RDP sessions from text output
            rdp_sessions = []
            current_event: Dict[str, str] = {}
            for line in out.split("\n"):
                line = line.strip()
                if line.startswith("Event["):
                    if current_event:
                        rdp_sessions.append(current_event)
                    current_event = {}
                elif ":" in line:
                    key, _, val = line.partition(":")
                    key = key.strip().lower()
                    val = val.strip()
                    if "date" in key or "time" in key:
                        current_event["timestamp"] = val
                    elif "user" in key:
                        current_event["user"] = val
                    elif "source" in key or "address" in key:
                        current_event["source_ip"] = val
                    elif "session" in key:
                        current_event["session_id"] = val
                    elif "event id" in key or "eventid" in key:
                        current_event["event_id"] = val
            if current_event:
                rdp_sessions.append(current_event)
            self.findings.append(Finding(
                self.MODULE,
                "RDP INBOUND CONNECTIONS DETECTED",
                f"Found {len(rdp_sessions)} RDP logon/reconnection sessions — review for unauthorized access",
                severity=3, mitre_id="T1021",
                evidence={"rdp_sessions": rdp_sessions[:50]},
            ))

        # --- RDP Outbound (bitmap cache) ---
        bmc_path = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache")
        if os.path.exists(bmc_path):
            cache_files = os.listdir(bmc_path)
            if cache_files:
                # Also check MRU for destination servers
                mru_servers = []
                mru_out, _, mru_rc = run_cmd(
                    r'reg query "HKCU\SOFTWARE\Microsoft\Terminal Server Client\Default" 2>nul'
                )
                if mru_rc == 0 and mru_out:
                    for line in mru_out.split("\n"):
                        if "MRU" in line and "REG_SZ" in line:
                            parts = re.split(r'\s{4,}', line.strip(), maxsplit=2)
                            if len(parts) >= 3:
                                mru_servers.append(parts[2].strip())
                self.findings.append(Finding(
                    self.MODULE,
                    "RDP OUTBOUND CACHE FOUND",
                    f"RDP bitmap cache with {len(cache_files)} files — indicates outbound RDP to {len(mru_servers)} host(s)",
                    severity=3, mitre_id="T1021",
                    evidence={
                        "cache_dir": bmc_path,
                        "file_count": len(cache_files),
                        "cache_files": cache_files[:30],
                        "destination_servers_mru": mru_servers,
                    },
                ))

        # --- SMB/Admin shares ---
        out, _, rc = run_cmd("net use 2>nul")
        if rc == 0 and out:
            connections = []
            for l in out.split("\n"):
                if "\\\\" in l:
                    parts = l.split()
                    conn_entry = {"raw": l.strip()}
                    # Try to extract UNC path and status
                    for p in parts:
                        if p.startswith("\\\\"):
                            conn_entry["unc_path"] = p
                            # Extract hostname/IP from UNC
                            unc_parts = p.replace("\\\\", "").split("\\")
                            if unc_parts:
                                conn_entry["destination_host"] = unc_parts[0]
                                conn_entry["share_name"] = unc_parts[1] if len(unc_parts) > 1 else ""
                    if parts and parts[0] in ("OK", "Disconnected", "Unavailable"):
                        conn_entry["status"] = parts[0]
                    connections.append(conn_entry)
            if connections:
                self.findings.append(Finding(
                    self.MODULE, "ACTIVE SMB/NETWORK CONNECTIONS",
                    f"Found {len(connections)} active network share connections",
                    severity=3, mitre_id="T1021",
                    evidence={"connections": connections},
                ))
        
        # --- WMI activity ---
        out, _, rc = run_cmd(
            'wevtutil qe "Microsoft-Windows-WMI-Activity/Operational" /f:text /c:30 2>nul',
            timeout=30
        )
        if rc == 0 and out and "Event" in out:
            self.findings.append(Finding(
                self.MODULE, "WMI ACTIVITY DETECTED",
                "WMI operational events found - could indicate lateral WMI execution",
                severity=2, mitre_id="T1021",
                evidence={"wmi_events_preview": out[:3000]},
            ))
        
        # --- PsExec artifacts ---
        psexec_indicators = []
        psexec_svc = os.path.expandvars(r"%SYSTEMROOT%\PSEXESVC.exe")
        if os.path.exists(psexec_svc):
            svc_stat = safe_stat(psexec_svc)
            svc_hash = hash_file(psexec_svc, "sha256")
            psexec_indicators.append({
                "type": "psexesvc_binary", "path": psexec_svc,
                "sha256": svc_hash or "",
                "created": svc_stat.get("created", "") if svc_stat else "",
                "modified": svc_stat.get("modified", "") if svc_stat else "",
                "size_bytes": svc_stat.get("size_bytes", 0) if svc_stat else 0,
            })
        
        out, _, rc = run_cmd('sc query PSEXESVC 2>nul')
        if rc == 0 and "RUNNING" in out.upper():
            psexec_indicators.append({"type": "psexesvc_service", "status": "running"})
        
        if psexec_indicators:
            self.findings.append(Finding(
                self.MODULE, "PSEXEC ARTIFACTS DETECTED",
                "PsExec service/binary found - strong lateral movement indicator",
                severity=4, mitre_id="T1021",
                evidence={"indicators": psexec_indicators},
            ))
        
        # --- Logon events (Type 3 = Network, Type 10 = RemoteInteractive) ---
        out, _, rc = run_cmd(
            'wevtutil qe Security /q:"*[System[Provider[@Name=\'Microsoft-Windows-Security-Auditing\'] '
            'and (EventID=4624)]]" /f:text /c:100 2>nul',
            timeout=30
        )
        if rc == 0 and out:
            type3_count = len(re.findall(r'logon type:\s+3\b', out, re.I))
            type10_count = len(re.findall(r'logon type:\s+10\b', out, re.I))
            if type3_count > 0 or type10_count > 0:
                # Extract source IPs and usernames from logon events
                source_ips = defaultdict(int)
                usernames = defaultdict(int)
                for ip_match in re.finditer(r'source network address:\s*(\S+)', out, re.I):
                    ip = ip_match.group(1)
                    if ip and ip != "-":
                        source_ips[ip] += 1
                for user_match in re.finditer(r'account name:\s*(\S+)', out, re.I):
                    user = user_match.group(1)
                    if user and user != "-" and user.upper() not in ("SYSTEM", "LOCAL SERVICE",
                                                                      "NETWORK SERVICE", "ANONYMOUS LOGON"):
                        usernames[user] += 1
                self.findings.append(Finding(
                    self.MODULE, "NETWORK/RDP LOGON EVENTS",
                    f"Found {type3_count} network logons (Type 3) and {type10_count} RDP logons (Type 10)",
                    severity=3, mitre_id="T1078",
                    evidence={
                        "type3_count": type3_count,
                        "type10_count": type10_count,
                        "source_ips": dict(source_ips),
                        "logon_usernames": dict(usernames),
                    },
                ))
        
        return self.findings
    
    def check_linux_lateral(self) -> List[Finding]:
        self.logger.info("[LATERAL] Checking Linux lateral movement artifacts...")
        self.logger.info("  SEARCHING: SSH login history, failed login attempts, auth.log entries")
        self.logger.info("  WHY: Tracks SSH-based lateral movement and brute-force attempts.")
        
        # --- SSH login history ---
        out, _, rc = run_cmd("last -i -n 50 2>/dev/null || last -n 50 2>/dev/null")
        if rc == 0 and out:
            remote_logins = []
            for l in out.split("\n"):
                if l.strip() and "pts/" in l:
                    parts = l.split()
                    session = {
                        "username": parts[0] if len(parts) > 0 else "",
                        "terminal": parts[1] if len(parts) > 1 else "",
                        "source_ip": parts[2] if len(parts) > 2 else "",
                    }
                    # Capture date portion (varies by OS)
                    date_part = " ".join(parts[3:7]) if len(parts) > 6 else " ".join(parts[3:])
                    session["login_time"] = date_part
                    remote_logins.append(session)
            if remote_logins:
                # Summarize source IPs
                ip_counts = defaultdict(int)
                for s in remote_logins:
                    if s["source_ip"]:
                        ip_counts[s["source_ip"]] += 1
                self.findings.append(Finding(
                    self.MODULE, "SSH/REMOTE LOGIN HISTORY",
                    f"Found {len(remote_logins)} remote terminal sessions from {len(ip_counts)} unique source(s)",
                    severity=3, mitre_id="T1021",
                    evidence={"sessions": remote_logins[:30], "source_ip_summary": dict(ip_counts)},
                ))

        # --- Failed login attempts ---
        out, _, rc = run_cmd("lastb -n 50 2>/dev/null")
        if rc == 0 and out and len(out.strip()) > 10:
            failed_entries = []
            ip_counts = defaultdict(int)
            user_counts = defaultdict(int)
            for l in out.split("\n"):
                if l.strip() and not l.startswith("btmp"):
                    parts = l.split()
                    entry = {
                        "username": parts[0] if len(parts) > 0 else "",
                        "terminal": parts[1] if len(parts) > 1 else "",
                        "source_ip": parts[2] if len(parts) > 2 else "",
                    }
                    if entry["source_ip"]:
                        ip_counts[entry["source_ip"]] += 1
                    if entry["username"]:
                        user_counts[entry["username"]] += 1
                    failed_entries.append(entry)
            self.findings.append(Finding(
                self.MODULE, "FAILED LOGIN ATTEMPTS",
                f"Found {len(failed_entries)} failed login attempts from {len(ip_counts)} unique IP(s)",
                severity=3, mitre_id="T1078",
                evidence={
                    "failed_logins": failed_entries[:30],
                    "source_ip_failure_counts": dict(ip_counts),
                    "username_failure_counts": dict(user_counts),
                    "total_failures": len(failed_entries),
                },
            ))

        # --- auth.log analysis ---
        auth_logs = ["/var/log/auth.log", "/var/log/secure"]
        for alog in auth_logs:
            if os.path.exists(alog):
                try:
                    out, _, rc = run_cmd(f"grep -i 'accepted\\|failed\\|invalid\\|sudo' {alog} | tail -100")
                    if out:
                        accepted = []
                        failed = []
                        sudo = []
                        for line in out.split("\n"):
                            # Parse: "Jan  5 14:23:01 host sshd[1234]: Accepted publickey for user from 1.2.3.4 port 22"
                            entry = {"log_line": line.strip()}
                            ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                            if ip_match:
                                entry["source_ip"] = ip_match.group(1)
                            user_match = re.search(r'for\s+(\S+)', line)
                            if user_match:
                                entry["username"] = user_match.group(1)
                            port_match = re.search(r'port\s+(\d+)', line)
                            if port_match:
                                entry["source_port"] = port_match.group(1)
                            # Timestamp is typically the first 15 chars
                            if len(line) > 15:
                                entry["timestamp"] = line[:15].strip()

                            if "accepted" in line.lower():
                                accepted.append(entry)
                            elif "failed" in line.lower():
                                failed.append(entry)
                            if "sudo" in line.lower():
                                sudo.append(entry)
                        self.findings.append(Finding(
                            self.MODULE, "AUTH LOG ANALYSIS",
                            f"From {alog}: {len(accepted)} accepted, {len(failed)} failed, {len(sudo)} sudo",
                            severity=3, mitre_id="T1078",
                            evidence={
                                "log_file": alog,
                                "accepted_logins": accepted[:20],
                                "failed_logins": failed[:20],
                                "sudo_commands": sudo[:20],
                            },
                        ))
                except (PermissionError, OSError):
                    pass
        
        return self.findings
    
    def check_macos_lateral(self) -> List[Finding]:
        self.logger.info("[LATERAL] Checking macOS lateral movement artifacts...")
        self.logger.info("  SEARCHING: Login history, Apple Screen Sharing / ARD activity")
        self.logger.info("  WHY: Screen sharing logs reveal unauthorized remote access to macOS endpoints.")
        
        # SSH logins
        out, _, rc = run_cmd("last -20 2>/dev/null")
        if rc == 0 and out:
            self.findings.append(Finding(
                self.MODULE, "LOGIN HISTORY",
                "Recent login sessions on macOS",
                severity=2, mitre_id="T1021",
                evidence={"sessions": out[:3000]},
            ))
        
        # Screen sharing / ARD
        out, _, rc = run_cmd("log show --predicate 'subsystem == \"com.apple.screensharing\"' --last 7d --style syslog 2>/dev/null | head -50")
        if rc == 0 and out and len(out.strip()) > 10:
            self.findings.append(Finding(
                self.MODULE, "SCREEN SHARING ACTIVITY",
                "Apple Screen Sharing events detected",
                severity=3, mitre_id="T1021",
                evidence={"events": out[:3000]},
            ))
        
        return self.findings
    
    def run_all(self) -> List[Finding]:
        os_type = get_os_type()
        if os_type == "windows":
            self.check_windows_lateral()
        elif os_type == "linux":
            self.check_linux_lateral()
        elif os_type == "macos":
            self.check_macos_lateral()
        return self.findings


# ============================================================================
# MODULE 4: EXFILTRATION DETECTOR
# ============================================================================

class ExfiltrationDetector:
    """Detect data exfiltration indicators."""
    
    MODULE = "EXFILTRATION"
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.findings: List[Finding] = []
    
    def check_exfil_tools(self) -> List[Finding]:
        """Check for exfiltration tools in running processes."""
        self.logger.info("[EXFIL] Checking running processes for exfiltration tools...")
        self.logger.info("  SEARCHING: rclone, MegaSync, WinSCP, FileZilla, curl, wget, scp, rsync,")
        self.logger.info("             7z, rar (archiving tools used for data staging)")
        self.logger.info("  WHY: Nova uses double extortion - they exfiltrate data BEFORE encrypting.")
        self.logger.info("       rclone to MEGA is their most common exfil method.")

        exfil_tools = ["rclone", "megasync", "winscp", "filezilla", "cyberduck",
                        "7z", "7za", "rar", "tar", "zip",  # archiving for staging
                        "curl", "wget", "scp", "rsync", "ftp"]

        out = get_system_cache().get_process_list()
        
        found = []
        if out:
            for tool in exfil_tools:
                if tool.lower() in out.lower():
                    found.append(tool)
        
        if found:
            self.findings.append(Finding(
                self.MODULE,
                "EXFILTRATION TOOLS IN RUNNING PROCESSES",
                f"Found {len(found)} potential exfil tools: {', '.join(found)}",
                severity=4, mitre_id="T1048",
                evidence={"tools_running": found},
            ))
        
        return self.findings
    
    def check_staging_dirs(self) -> List[Finding]:
        """Look for data staging directories (large archives, temp dirs with bulk data)."""
        self.logger.info("[EXFIL] Checking for large archives in staging directories (>50MB)...")
        self.logger.info("  SEARCHING: .7z, .zip, .rar, .tar archives in TEMP, ProgramData, PerfLogs, /tmp, /dev/shm")
        self.logger.info("  WHY: Attackers stage stolen data as compressed archives before exfiltration.")
        os_type = get_os_type()
        
        staging_patterns = ["*.7z", "*.zip", "*.rar", "*.tar", "*.tar.gz",
                            "*.tar.bz2", "*.tar.xz", "*.cab"]
        
        if os_type == "windows":
            search_dirs = [os.path.expandvars(r"%TEMP%"), os.path.expandvars(r"%PROGRAMDATA%"),
                           r"C:\PerfLogs", r"C:\Windows\Temp"]
        elif os_type == "macos":
            search_dirs = ["/tmp", "/var/tmp", "/private/tmp"]
        else:
            search_dirs = ["/tmp", "/var/tmp", "/dev/shm", "/opt"]
        
        large_archives = []
        for sdir in search_dirs:
            if not os.path.exists(sdir):
                continue
            for pattern in staging_patterns:
                for fpath in glob.glob(os.path.join(sdir, "**", pattern), recursive=True):
                    try:
                        fsize = os.path.getsize(fpath)
                        if fsize > 50_000_000:  # > 50MB
                            stat = safe_stat(fpath)
                            if stat:
                                stat["size_mb"] = round(fsize / 1_000_000, 2)
                                large_archives.append(stat)
                    except OSError:
                        continue
        
        if large_archives:
            self.findings.append(Finding(
                self.MODULE,
                "LARGE ARCHIVES IN STAGING LOCATIONS",
                f"Found {len(large_archives)} large archive files in temp/staging directories",
                severity=4, mitre_id="T1074",
                evidence={"archives": large_archives},
            ))
        
        return self.findings
    
    def check_rclone_config(self) -> List[Finding]:
        """Look for rclone configuration files (key exfil tool for ransomware groups)."""
        self.logger.info("[EXFIL] Searching for rclone configuration files...")
        self.logger.info("  SEARCHING: rclone.conf in AppData, .config/rclone, all user profiles")
        self.logger.info("  WHY: rclone configs contain the attacker's cloud storage destination (usually MEGA).")
        self.logger.info("       This is the #1 exfiltration method for Nova and most RaaS groups.")
        os_type = get_os_type()
        
        rclone_paths = []
        if os_type == "windows":
            rclone_paths = [
                os.path.expandvars(r"%APPDATA%\rclone\rclone.conf"),
                os.path.expandvars(r"%USERPROFILE%\.config\rclone\rclone.conf"),
            ]
        else:
            rclone_paths = [
                os.path.expanduser("~/.config/rclone/rclone.conf"),
                "/root/.config/rclone/rclone.conf",
            ]
            rclone_paths += glob.glob("/home/*/.config/rclone/rclone.conf")
        
        found_configs = []
        for rpath in rclone_paths:
            if os.path.exists(rpath):
                stat = safe_stat(rpath)
                try:
                    with open(rpath, "r", errors="ignore") as f:
                        content = f.read()
                        # Extract remote names (leak destination)
                        remotes = re.findall(r'\[(.+?)\]', content)
                        found_configs.append({
                            "path": rpath,
                            "file_info": stat,
                            "configured_remotes": remotes,
                        })
                except (PermissionError, OSError):
                    found_configs.append({"path": rpath, "file_info": stat})
        
        if found_configs:
            self.findings.append(Finding(
                self.MODULE,
                "RCLONE CONFIGURATION FOUND (KEY EXFIL TOOL)",
                f"Found {len(found_configs)} rclone config files - strong exfiltration indicator",
                severity=5, mitre_id="T1048",
                evidence={"configs": found_configs},
            ))
        
        return self.findings
    
    def check_outbound_connections(self) -> List[Finding]:
        """Analyze current outbound connections for suspicious destinations."""
        self.logger.info("[EXFIL] Checking outbound connections for suspicious ports and C2 IPs...")
        self.logger.info("  SEARCHING: Established connections on ports 4444, 5555, 6666, 8888, 9999, 1234,")
        self.logger.info("             31337, 4443, 8443, 9050/9150 (Tor), and known Nova C2 IPs")
        self.logger.info("  WHY: Active C2 connections mean the attacker may still have real-time access.")

        out = get_system_cache().get_netstat_output()
        
        if out:
            # Look for connections on unusual ports
            unusual_ports = {"4444", "5555", "6666", "8888", "9999", "1234", "31337",
                             "4443", "8443", "9443",  # alt HTTPS
                             "9050", "9150",  # Tor
                             }
            suspicious_conns = []
            c2_conns = []
            c2_ips = set(NOVA_IOCS.get("c2_ips", []))
            for line in out.split("\n"):
                # Check for known Nova C2 IPs
                for c2_ip in c2_ips:
                    if c2_ip in line:
                        c2_conns.append(line.strip())
                        break
                # Check for suspicious ports
                for port in unusual_ports:
                    if f":{port}" in line and "ESTABLISHED" in line.upper():
                        suspicious_conns.append(line.strip())
                        break

            if c2_conns:
                self.findings.append(Finding(
                    self.MODULE,
                    "ACTIVE CONNECTION TO KNOWN NOVA C2 IP",
                    f"Found {len(c2_conns)} connections to known Nova command-and-control infrastructure!",
                    severity=5, mitre_id="T1071",
                    evidence={"c2_connections": c2_conns, "known_c2_ips": list(c2_ips)},
                ))

            if suspicious_conns:
                self.findings.append(Finding(
                    self.MODULE,
                    "SUSPICIOUS OUTBOUND CONNECTIONS",
                    f"Found {len(suspicious_conns)} connections on unusual ports",
                    severity=4, mitre_id="T1048",
                    evidence={"connections": suspicious_conns[:20]},
                ))

        return self.findings
    
    def run_all(self) -> List[Finding]:
        self.check_exfil_tools()
        self.check_staging_dirs()
        self.check_rclone_config()
        self.check_outbound_connections()
        return self.findings


# ============================================================================
# MODULE 5: DEFENSE EVASION DETECTOR
# ============================================================================

class DefenseEvasionDetector:
    """Detect defense evasion and anti-forensics by Nova affiliates."""
    
    MODULE = "DEFENSE_EVASION"
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.findings: List[Finding] = []
    
    def check_windows_defense_evasion(self) -> List[Finding]:
        self.logger.info("[EVASION] Checking Windows defense evasion indicators...")
        self.logger.info("  SEARCHING: Defender status, tamper protection, shadow copies, event log clearing,")
        self.logger.info("             empty event logs, safe boot config, Defender exclusions")
        self.logger.info("  WHY: Nova ALWAYS disables Defender and deletes shadow copies before encrypting.")
        self.logger.info("       Log clearing is done to hamper forensic investigation.")
        
        # --- Windows Defender status ---
        out, _, rc = run_cmd(
            'powershell -Command "Get-MpPreference | Select-Object DisableRealtimeMonitoring,'
            'DisableBehaviorMonitoring,DisableIOAVProtection,ExclusionPath,ExclusionExtension '
            '| ConvertTo-Json" 2>nul',
            timeout=15
        )
        if rc == 0 and out:
            try:
                defender = json.loads(out)
                issues = []
                if defender.get("DisableRealtimeMonitoring"):
                    issues.append("Real-time monitoring DISABLED")
                if defender.get("DisableBehaviorMonitoring"):
                    issues.append("Behavior monitoring DISABLED")
                if defender.get("DisableIOAVProtection"):
                    issues.append("IOAV protection DISABLED")
                if defender.get("ExclusionPath"):
                    issues.append(f"Exclusion paths set: {defender['ExclusionPath']}")
                if defender.get("ExclusionExtension"):
                    issues.append(f"Exclusion extensions set: {defender['ExclusionExtension']}")
                
                if issues:
                    self.findings.append(Finding(
                        self.MODULE,
                        "WINDOWS DEFENDER TAMPERED",
                        f"Defender configuration issues: {'; '.join(issues)}",
                        severity=5, mitre_id="T1562",
                        evidence={"defender_config": defender, "issues": issues},
                    ))
            except json.JSONDecodeError:
                pass
        
        # --- Shadow copies deleted? ---
        out, err, rc = run_cmd("vssadmin list shadows 2>nul")
        if rc == 0:
            if "no items" in out.lower() or "no shadow" in out.lower():
                self.findings.append(Finding(
                    self.MODULE,
                    "NO VOLUME SHADOW COPIES (BACKUP DESTRUCTION)",
                    "All VSS shadow copies appear deleted - typical ransomware behavior",
                    severity=5, mitre_id="T1490",
                    evidence={"vss_output": out},
                ))
            elif not out.strip():
                # Empty output with rc=0 is ambiguous — could be permission or parsing issue
                self.findings.append(Finding(
                    self.MODULE,
                    "VSS CHECK INCONCLUSIVE",
                    "vssadmin returned empty output - verify manually (may require elevation)",
                    severity=3, mitre_id="T1490",
                    evidence={"vss_output": out, "stderr": err},
                ))
        
        # --- Windows event log clearing ---
        out, _, rc = run_cmd(
            'wevtutil qe Security /q:"*[System[(EventID=1102)]]" /f:text /c:10 2>nul',
            timeout=15
        )
        if rc == 0 and out and "1102" in out:
            # Parse clearing events for timestamps and accounts
            clear_events = []
            current_event: Dict[str, str] = {}
            for line in out.split("\n"):
                line = line.strip()
                if line.startswith("Event["):
                    if current_event:
                        clear_events.append(current_event)
                    current_event = {"event_id": "1102"}
                elif ":" in line:
                    key, _, val = line.partition(":")
                    key_lower = key.strip().lower()
                    val = val.strip()
                    if "date" in key_lower or "time" in key_lower:
                        current_event["timestamp"] = val
                    elif "account" in key_lower or "subject" in key_lower:
                        current_event["cleared_by_account"] = val
                    elif "domain" in key_lower:
                        current_event["domain"] = val
                    elif "logon id" in key_lower:
                        current_event["logon_id"] = val
            if current_event:
                clear_events.append(current_event)
            self.findings.append(Finding(
                self.MODULE,
                "SECURITY LOG CLEARED (ANTI-FORENSICS)",
                f"Found {len(clear_events)} security log clearing event(s) (Event ID 1102)",
                severity=5, mitre_id="T1070",
                evidence={"log_clear_events": clear_events},
            ))
        
        # --- Check if key event logs are empty/tiny ---
        log_channels = ["Security", "System", "Application",
                         "Microsoft-Windows-PowerShell/Operational"]
        empty_logs = []
        for lc in log_channels:
            out, _, rc = run_cmd(f'wevtutil gli "{lc}" 2>nul')
            if rc == 0 and out:
                record_match = re.search(r'numberOfLogRecords:\s*(\d+)', out, re.I)
                size_match = re.search(r'fileSize:\s*(\d+)', out, re.I)
                records = int(record_match.group(1)) if record_match else -1
                if records >= 0 and records < 50:
                    log_entry: Dict[str, Any] = {
                        "log_channel": lc,
                        "record_count": records,
                    }
                    if size_match:
                        log_entry["file_size_bytes"] = int(size_match.group(1))
                    empty_logs.append(log_entry)
        
        if empty_logs:
            self.findings.append(Finding(
                self.MODULE,
                "EVENT LOGS SUSPICIOUSLY EMPTY",
                f"{len(empty_logs)} event log(s) have very few records",
                severity=4, mitre_id="T1070",
                evidence={"empty_logs": empty_logs},
            ))
        
        # --- Safe boot / boot config tampered ---
        out, _, rc = run_cmd("bcdedit /enum 2>nul")
        if rc == 0 and out:
            if "safeboot" in out.lower():
                self.findings.append(Finding(
                    self.MODULE,
                    "SAFE BOOT CONFIGURATION DETECTED",
                    "Boot configuration altered - some ransomware boot into safe mode to bypass AV",
                    severity=4, mitre_id="T1562",
                    evidence={"bcdedit_output": out[:2000]},
                ))
        
        # --- Tamper protection registry ---
        out, _, rc = run_cmd(
            r'reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection 2>nul'
        )
        if rc == 0 and "0x0" in out:
            self.findings.append(Finding(
                self.MODULE,
                "TAMPER PROTECTION DISABLED",
                "Windows Defender Tamper Protection is OFF",
                severity=5, mitre_id="T1562",
                evidence={"registry_value": out.strip()},
            ))

        # --- Windows Firewall Audit ---
        self.logger.info("  SEARCHING: Suspicious Windows Firewall inbound allow rules")
        out, _, rc = run_cmd(
            'powershell -Command "Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True '
            '| Select-Object DisplayName,DisplayGroup,@{N=\'Program\';E={(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $_).Program}} '
            '| ConvertTo-Json -Depth 3" 2>nul',
            timeout=30
        )
        if rc == 0 and out:
            try:
                rules = json.loads(out)
                if isinstance(rules, dict):
                    rules = [rules]
                suspicious_rules = []
                suspect_programs = ["\\temp\\", "\\tmp\\", "\\appdata\\", "\\downloads\\",
                                    "ngrok", "chisel", "ligolo", "frp", "socat",
                                    "\\programdata\\", "\\perflogs\\", "\\users\\public\\"]
                for rule in rules:
                    program = str(rule.get("Program", "")).lower()
                    group = rule.get("DisplayGroup") or ""
                    if program and program != "any":
                        # Flag rules with no group and suspicious program paths
                        if not group and any(sp in program for sp in suspect_programs):
                            suspicious_rules.append({
                                "rule_name": rule.get("DisplayName", ""),
                                "program": rule.get("Program", ""),
                                "group": group,
                            })
                        # Also flag known tunnel/proxy tools regardless of group
                        elif any(tool in program for tool in ["ngrok", "chisel", "ligolo", "frp", "socat"]):
                            suspicious_rules.append({
                                "rule_name": rule.get("DisplayName", ""),
                                "program": rule.get("Program", ""),
                                "group": group,
                            })
                if suspicious_rules:
                    self.findings.append(Finding(
                        self.MODULE,
                        "SUSPICIOUS FIREWALL INBOUND RULES",
                        f"Found {len(suspicious_rules)} suspicious inbound allow rules - may indicate attacker-created network access",
                        severity=4, mitre_id="T1562",
                        evidence={"suspicious_rules": suspicious_rules[:30]},
                    ))
            except json.JSONDecodeError:
                pass

        # --- NTFS Alternate Data Streams ---
        self.logger.info("  SEARCHING: NTFS Alternate Data Streams in common staging directories")
        ads_dirs = [
            os.environ.get("TEMP", "C:\\Windows\\Temp"),
            "C:\\ProgramData", "C:\\PerfLogs",
            os.path.join(os.environ.get("USERPROFILE", "C:\\Users\\Default"), "Downloads"),
        ]
        suspicious_ads = []
        for ads_dir in ads_dirs:
            if not os.path.exists(ads_dir):
                continue
            out, _, rc = run_cmd(
                f'powershell -Command "Get-ChildItem -Path \'{ads_dir}\' -Recurse -ErrorAction SilentlyContinue '
                f'| ForEach-Object {{ $streams = Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue; '
                f'$streams | Where-Object {{ $_.Stream -ne \':$DATA\' -and $_.Stream -ne \'Zone.Identifier\' }} '
                f'| Select-Object @{{N=\'FilePath\';E={{$_.FileName}}}},Stream,Length }} '
                f'| ConvertTo-Json -Depth 2" 2>nul',
                timeout=20
            )
            if rc == 0 and out and out.strip() not in ["", "null"]:
                try:
                    streams = json.loads(out)
                    if isinstance(streams, dict):
                        streams = [streams]
                    for s in streams:
                        if s.get("Stream") and s.get("Length", 0) > 0:
                            suspicious_ads.append({
                                "file_path": s.get("FilePath", ""),
                                "stream_name": s.get("Stream", ""),
                                "size_bytes": s.get("Length", 0),
                            })
                except json.JSONDecodeError:
                    pass
        if suspicious_ads:
            self.findings.append(Finding(
                self.MODULE,
                "NTFS ALTERNATE DATA STREAMS DETECTED",
                f"Found {len(suspicious_ads)} non-standard ADS entries - data can be hidden in alternate streams",
                severity=4, mitre_id="T1564",
                evidence={"alternate_data_streams": suspicious_ads[:50]},
            ))

        return self.findings

    def check_linux_defense_evasion(self) -> List[Finding]:
        self.logger.info("[EVASION] Checking Linux defense evasion indicators...")
        self.logger.info("  SEARCHING: Security service status (auditd, rsyslog, fail2ban, EDR agents),")
        self.logger.info("             log file integrity, iptables rules, bash history anomalies")
        self.logger.info("  WHY: Attackers stop security services, clear logs, and flush firewall rules")
        self.logger.info("       to operate undetected and destroy forensic evidence.")
        
        # --- Check if common security services are running ---
        security_services = ["auditd", "rsyslog", "syslog-ng", "fail2ban",
                             "ossec", "wazuh-agent", "crowdstrike-falcon-sensor",
                             "cbagentd", "elastic-agent"]
        stopped = []
        for svc in security_services:
            out, _, rc = run_cmd(f"systemctl is-active {svc} 2>/dev/null")
            if rc != 0 or "inactive" in out.lower() or "dead" in out.lower():
                # Check if it was ever installed
                _, _, rc2 = run_cmd(f"systemctl list-unit-files | grep -q {svc}")
                if rc2 == 0:
                    stopped.append(svc)
        
        if stopped:
            self.findings.append(Finding(
                self.MODULE,
                "SECURITY SERVICES STOPPED",
                f"These security services are installed but not running: {', '.join(stopped)}",
                severity=4, mitre_id="T1562",
                evidence={"stopped_services": stopped},
            ))
        
        # --- Log tampering ---
        log_files = ["/var/log/auth.log", "/var/log/syslog", "/var/log/messages",
                     "/var/log/secure", "/var/log/audit/audit.log"]
        suspicious_logs = []
        for lf in log_files:
            if os.path.exists(lf):
                try:
                    fsize = os.path.getsize(lf)
                    if fsize == 0:
                        suspicious_logs.append({"path": lf, "issue": "empty (0 bytes)"})
                    elif fsize < 100:
                        suspicious_logs.append({"path": lf, "issue": f"suspiciously small ({fsize} bytes)"})
                except OSError:
                    pass
            else:
                # Missing critical log
                if lf in ["/var/log/auth.log", "/var/log/secure"]:
                    suspicious_logs.append({"path": lf, "issue": "MISSING"})
        
        if suspicious_logs:
            self.findings.append(Finding(
                self.MODULE,
                "LOG FILES TAMPERED OR MISSING",
                f"{len(suspicious_logs)} log files are empty, tiny, or missing",
                severity=4, mitre_id="T1070",
                evidence={"logs": suspicious_logs},
            ))
        
        # --- iptables/firewall changes ---
        out, _, rc = run_cmd("iptables -L -n 2>/dev/null")
        if rc == 0 and out:
            if "DROP" not in out and "REJECT" not in out:
                self.findings.append(Finding(
                    self.MODULE,
                    "FIREWALL RULES POSSIBLY FLUSHED",
                    "iptables has no DROP/REJECT rules - may have been flushed by attacker",
                    severity=3, mitre_id="T1562",
                    evidence={"iptables_output": out[:2000]},
                ))
        
        # --- History files ---
        hist_files = glob.glob("/home/*/.bash_history") + ["/root/.bash_history"]
        for hf in hist_files:
            if os.path.exists(hf):
                try:
                    fsize = os.path.getsize(hf)
                    if fsize == 0:
                        self.findings.append(Finding(
                            self.MODULE, "BASH HISTORY CLEARED",
                            f"History file is empty: {hf}",
                            severity=3, mitre_id="T1070",
                            evidence={"path": hf},
                        ))
                    else:
                        # Check for suspicious commands in history
                        with open(hf, "r", errors="ignore") as f:
                            lines = f.readlines()[-200:]
                            suspicious_cmds = []
                            patterns = ["curl.*|.*sh", "wget.*|.*sh", "chmod 777", "base64",
                                        "nc -", "ncat", "/dev/shm", "history -c",
                                        "rm -rf /var/log", "iptables -F",
                                        "systemctl stop", "service.*stop",
                                        "kill -9", "pkill", "nohup",
                                        "rclone", "scp.*@", "rsync.*@"]
                            for line in lines:
                                for pat in patterns:
                                    if re.search(pat, line, re.I):
                                        suspicious_cmds.append(line.strip())
                                        break
                            if suspicious_cmds:
                                self.findings.append(Finding(
                                    self.MODULE,
                                    "SUSPICIOUS COMMANDS IN BASH HISTORY",
                                    f"Found {len(suspicious_cmds)} suspicious commands in {hf}",
                                    severity=4, mitre_id="T1059",
                                    evidence={"history_file": hf, "commands": suspicious_cmds[:50]},
                                ))
                except (PermissionError, OSError):
                    pass
        
        return self.findings
    
    def check_macos_defense_evasion(self) -> List[Finding]:
        self.logger.info("[EVASION] Checking macOS defense evasion indicators...")
        self.logger.info("  SEARCHING: Gatekeeper status, System Integrity Protection (SIP)")
        self.logger.info("  WHY: Disabled Gatekeeper/SIP allows unsigned malware to run freely.")
        
        # --- Check Gatekeeper status ---
        out, _, rc = run_cmd("spctl --status 2>/dev/null")
        if rc == 0 and "disabled" in out.lower():
            self.findings.append(Finding(
                self.MODULE, "GATEKEEPER DISABLED",
                "macOS Gatekeeper is disabled - unsigned apps can run freely",
                severity=4, mitre_id="T1562",
                evidence={"gatekeeper_status": out},
            ))
        
        # --- SIP status ---
        out, _, rc = run_cmd("csrutil status 2>/dev/null")
        if rc == 0 and "disabled" in out.lower():
            self.findings.append(Finding(
                self.MODULE, "SIP DISABLED",
                "System Integrity Protection is disabled",
                severity=5, mitre_id="T1562",
                evidence={"sip_status": out},
            ))

        # --- XProtect Definitions Freshness ---
        self.logger.info("  SEARCHING: XProtect definition freshness")
        xprotect_plist = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/version.plist"
        if not os.path.exists(xprotect_plist):
            xprotect_plist = "/System/Library/CoreServices/XProtect.bundle/Contents/version.plist"
        if os.path.exists(xprotect_plist):
            try:
                mtime = os.path.getmtime(xprotect_plist)
                age_days = (datetime.now(timezone.utc).timestamp() - mtime) / 86400
                if age_days > 30:
                    self.findings.append(Finding(
                        self.MODULE,
                        "XPROTECT DEFINITIONS STALE",
                        f"XProtect definitions are {int(age_days)} days old - should update within 30 days",
                        severity=3, mitre_id="T1562",
                        evidence={"xprotect_plist": xprotect_plist, "age_days": round(age_days, 1)},
                    ))
            except OSError:
                pass
        else:
            self.findings.append(Finding(
                self.MODULE,
                "XPROTECT DEFINITIONS MISSING",
                "XProtect version.plist not found - macOS malware protection may be compromised",
                severity=4, mitre_id="T1562",
                evidence={"checked_paths": [
                    "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/version.plist",
                    "/System/Library/CoreServices/XProtect.bundle/Contents/version.plist",
                ]},
            ))

        # --- TCC Permissions Audit ---
        self.logger.info("  SEARCHING: TCC database for suspicious Full Disk Access / Accessibility permissions")
        tcc_dbs = [
            "/Library/Application Support/com.apple.TCC/TCC.db",
            os.path.expanduser("~/Library/Application Support/com.apple.TCC/TCC.db"),
        ]
        suspicious_tcc = []
        for tcc_db in tcc_dbs:
            if not os.path.exists(tcc_db):
                continue
            for service in ["kTCCServiceAccessibility", "kTCCServiceSystemPolicyAllFiles"]:
                out, _, rc = run_cmd(
                    f'sqlite3 "{tcc_db}" "SELECT client,auth_value FROM access WHERE service=\'{service}\' AND auth_value=2;" 2>/dev/null'
                )
                if rc == 0 and out:
                    for line in out.split("\n"):
                        if line.strip():
                            parts = line.split("|")
                            client = parts[0] if parts else line
                            if not client.startswith("com.apple."):
                                suspicious_tcc.append({
                                    "database": tcc_db,
                                    "service": service.replace("kTCCService", ""),
                                    "client": client,
                                })
        if suspicious_tcc:
            self.findings.append(Finding(
                self.MODULE,
                "SUSPICIOUS TCC PERMISSIONS GRANTED",
                f"Found {len(suspicious_tcc)} non-Apple apps with Full Disk Access or Accessibility permissions",
                severity=3, mitre_id="T1562",
                evidence={"tcc_entries": suspicious_tcc},
            ))

        return self.findings

    def run_all(self) -> List[Finding]:
        os_type = get_os_type()
        if os_type == "windows":
            self.check_windows_defense_evasion()
        elif os_type == "linux":
            self.check_linux_defense_evasion()
        elif os_type == "macos":
            self.check_macos_defense_evasion()
        return self.findings


# ============================================================================
# MODULE 5c: ROOTKIT DETECTOR
# ============================================================================

class RootkitDetector:
    """Detect rootkits, hidden processes, unsigned drivers, and suspicious kernel modules."""

    MODULE = "ROOTKIT_DETECTION"

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.findings: List[Finding] = []

    def check_windows_rootkit(self) -> List[Finding]:
        """Check for unsigned running drivers, test signing mode, and known rootkit driver names."""
        self.logger.info("[ROOTKIT] Checking Windows for unsigned drivers and rootkit indicators...")
        self.logger.info("  SEARCHING: Unsigned running drivers, test signing mode, known rootkit driver names")
        self.logger.info("  WHY: Rootkits install kernel drivers to hide processes, files, and network connections.")

        # --- Unsigned running drivers ---
        out, _, rc = run_cmd(
            'powershell -Command "Get-WmiObject Win32_SystemDriver | Where-Object {$_.State -eq \'Running\'} '
            '| ForEach-Object { $sig = Get-AuthenticodeSignature $_.PathName -ErrorAction SilentlyContinue; '
            'if ($sig.Status -ne \'Valid\') { [PSCustomObject]@{Name=$_.Name;Path=$_.PathName;Status=$sig.Status} } } '
            '| ConvertTo-Json -Depth 2" 2>nul',
            timeout=60
        )
        if rc == 0 and out and out.strip() not in ["", "null"]:
            try:
                unsigned = json.loads(out)
                if isinstance(unsigned, dict):
                    unsigned = [unsigned]
                # Filter out known benign unsigned drivers
                known_unsigned = ["", "null"]
                real_unsigned = [d for d in unsigned if d.get("Name") and d["Name"].lower() not in known_unsigned]
                if real_unsigned:
                    self.findings.append(Finding(
                        self.MODULE,
                        "UNSIGNED KERNEL DRIVERS RUNNING",
                        f"Found {len(real_unsigned)} running drivers without valid digital signatures - may indicate rootkit",
                        severity=5, mitre_id="T1014",
                        evidence={"unsigned_drivers": real_unsigned[:20]},
                    ))
            except json.JSONDecodeError:
                pass

        # --- Test signing mode ---
        out, _, rc = run_cmd("bcdedit /enum 2>nul")
        if rc == 0 and out:
            if "testsigning" in out.lower() and "yes" in out.lower():
                self.findings.append(Finding(
                    self.MODULE,
                    "WINDOWS TEST SIGNING MODE ENABLED",
                    "Boot configuration has test signing enabled - allows loading unsigned kernel drivers",
                    severity=5, mitre_id="T1014",
                    evidence={"bcdedit_excerpt": out[:2000]},
                ))

        # --- Known rootkit driver names ---
        known_rootkit_names = [
            "fgexec", "odinaff", "pandora", "sauron", "wnbd", "winring0",
            "capcom", "cpuz", "dbutil", "gdrv", "iqvw64e", "rtcore64",
            "winpmem", "processhacker", "kprocesshacker", "mimikatz",
        ]
        out, _, rc = run_cmd(
            'powershell -Command "Get-WmiObject Win32_SystemDriver | Where-Object {$_.State -eq \'Running\'} '
            '| Select-Object Name,DisplayName,PathName | ConvertTo-Json -Depth 2" 2>nul',
            timeout=30
        )
        if rc == 0 and out:
            try:
                drivers = json.loads(out)
                if isinstance(drivers, dict):
                    drivers = [drivers]
                flagged = []
                for drv in drivers:
                    name = (drv.get("Name") or "").lower()
                    if any(rk in name for rk in known_rootkit_names):
                        flagged.append({
                            "name": drv.get("Name", ""),
                            "display_name": drv.get("DisplayName", ""),
                            "path": drv.get("PathName", ""),
                        })
                if flagged:
                    self.findings.append(Finding(
                        self.MODULE,
                        "KNOWN ROOTKIT/VULNERABLE DRIVER NAMES DETECTED",
                        f"Found {len(flagged)} running drivers matching known rootkit/BYOVD names",
                        severity=5, mitre_id="T1014",
                        evidence={"flagged_drivers": flagged},
                    ))
            except json.JSONDecodeError:
                pass

        return self.findings

    def check_linux_rootkit(self) -> List[Finding]:
        """Check for hidden processes and kernel module discrepancies."""
        self.logger.info("[ROOTKIT] Checking Linux for hidden processes and kernel anomalies...")
        self.logger.info("  SEARCHING: Hidden processes (ps vs /proc), deleted binaries in /proc")
        self.logger.info("  WHY: Rootkits hide malicious processes from ps and other userspace tools.")

        # --- Hidden processes: compare ps PIDs vs /proc PIDs ---
        ps_out, _, rc = run_cmd("ps -eo pid --no-headers 2>/dev/null")
        if rc == 0 and ps_out:
            ps_pids = set()
            for line in ps_out.split("\n"):
                line = line.strip()
                if line.isdigit():
                    ps_pids.add(int(line))

            proc_pids = set()
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    proc_pids.add(int(entry))

            # PIDs in /proc but not in ps = hidden from ps
            hidden = proc_pids - ps_pids
            # Filter out kernel threads (they may not show in ps depending on flags)
            real_hidden = []
            for pid in hidden:
                try:
                    cmdline_path = f"/proc/{pid}/cmdline"
                    if os.path.exists(cmdline_path):
                        with open(cmdline_path, "r") as f:
                            cmdline = f.read().strip()
                            if cmdline:  # Has a cmdline = real process, not kthread
                                exe_path = os.readlink(f"/proc/{pid}/exe") if os.path.exists(f"/proc/{pid}/exe") else ""
                                real_hidden.append({
                                    "pid": pid,
                                    "cmdline": cmdline[:200],
                                    "exe": exe_path,
                                })
                except (PermissionError, OSError):
                    pass

            if real_hidden:
                self.findings.append(Finding(
                    self.MODULE,
                    "HIDDEN PROCESSES DETECTED",
                    f"Found {len(real_hidden)} processes visible in /proc but hidden from ps - strong rootkit indicator",
                    severity=5, mitre_id="T1014",
                    evidence={"hidden_processes": real_hidden[:20]},
                ))

        # --- Check for deleted binaries still running ---
        deleted_procs = []
        for pid_dir in glob.glob("/proc/[0-9]*/exe"):
            try:
                exe_link = os.readlink(pid_dir)
                if "(deleted)" in exe_link:
                    pid = pid_dir.split("/")[2]
                    deleted_procs.append({
                        "pid": pid,
                        "exe": exe_link,
                    })
            except (PermissionError, OSError):
                pass
        if deleted_procs:
            self.findings.append(Finding(
                self.MODULE,
                "PROCESSES RUNNING FROM DELETED BINARIES",
                f"Found {len(deleted_procs)} processes whose binary has been deleted from disk - potential malware",
                severity=4, mitre_id="T1014",
                evidence={"deleted_binary_processes": deleted_procs[:20]},
            ))

        return self.findings

    def check_macos_rootkit(self) -> List[Finding]:
        """Check for non-Apple kexts, suspicious system extensions, and tampered system binaries."""
        self.logger.info("[ROOTKIT] Checking macOS for non-Apple kexts and tampered system binaries...")
        self.logger.info("  SEARCHING: Third-party kexts, system extensions, code signing of key binaries")
        self.logger.info("  WHY: Rootkits may install kernel extensions or replace system binaries.")

        # --- Non-Apple kernel extensions ---
        out, _, rc = run_cmd("kextstat 2>/dev/null")
        if rc == 0 and out:
            non_apple_kexts = []
            for line in out.split("\n"):
                line = line.strip()
                if not line or line.startswith("Index") or line.startswith("---"):
                    continue
                # kextstat lines have bundle IDs; Apple ones start with com.apple.
                parts = line.split()
                for part in parts:
                    if "." in part and not part.startswith("com.apple.") and not part[0].isdigit():
                        non_apple_kexts.append({"kext_id": part, "raw_line": line[:200]})
                        break
            if non_apple_kexts:
                self.findings.append(Finding(
                    self.MODULE,
                    "NON-APPLE KERNEL EXTENSIONS LOADED",
                    f"Found {len(non_apple_kexts)} non-Apple kexts loaded - review for legitimacy",
                    severity=3, mitre_id="T1014",
                    evidence={"kexts": non_apple_kexts},
                ))

        # --- System extensions ---
        out, _, rc = run_cmd("systemextensionsctl list 2>/dev/null")
        if rc == 0 and out:
            non_apple_ext = []
            for line in out.split("\n"):
                if line.strip() and "com.apple." not in line and "---" not in line and "enabled" in line.lower():
                    non_apple_ext.append(line.strip())
            if non_apple_ext:
                self.findings.append(Finding(
                    self.MODULE,
                    "NON-APPLE SYSTEM EXTENSIONS",
                    f"Found {len(non_apple_ext)} non-Apple system extensions",
                    severity=3, mitre_id="T1014",
                    evidence={"extensions": non_apple_ext},
                ))

        # --- Code signing verification of key binaries ---
        critical_binaries = ["/usr/bin/login", "/usr/sbin/sshd", "/usr/bin/sudo", "/usr/bin/su",
                             "/usr/bin/ssh", "/usr/libexec/security_authtrampoline"]
        tampered = []
        for binary in critical_binaries:
            if os.path.exists(binary):
                out, err, rc = run_cmd(f'codesign -v "{binary}" 2>&1')
                combined = f"{out} {err}".lower()
                if rc != 0 and "valid on disk" not in combined:
                    tampered.append({
                        "binary": binary,
                        "codesign_output": f"{out} {err}"[:300],
                    })
        if tampered:
            self.findings.append(Finding(
                self.MODULE,
                "TAMPERED SYSTEM BINARIES DETECTED",
                f"Found {len(tampered)} critical system binaries with invalid code signatures",
                severity=5, mitre_id="T1014",
                evidence={"tampered_binaries": tampered},
            ))

        return self.findings

    def run_all(self) -> List[Finding]:
        os_type = get_os_type()
        if os_type == "windows":
            self.check_windows_rootkit()
        elif os_type == "linux":
            self.check_linux_rootkit()
        elif os_type == "macos":
            self.check_macos_rootkit()
        return self.findings


# ============================================================================
# MODULE 5d: WEB SHELL DETECTOR
# ============================================================================

class WebShellDetector:
    """Detect web shells in common web server directories."""

    MODULE = "WEB_SHELL_DETECTION"

    WEB_SHELL_PATTERNS = [
        re.compile(rb"eval\s*\(", re.I),
        re.compile(rb"exec\s*\(", re.I),
        re.compile(rb"system\s*\(", re.I),
        re.compile(rb"passthru\s*\(", re.I),
        re.compile(rb"shell_exec\s*\(", re.I),
        re.compile(rb"base64_decode\s*\(", re.I),
        re.compile(rb"gzinflate\s*\(", re.I),
        re.compile(rb"Runtime\.getRuntime\(\)\.exec", re.I),
        re.compile(rb"WScript\.Shell", re.I),
        re.compile(rb"cmd\.exe|/bin/sh|/bin/bash", re.I),
        re.compile(rb"ProcessStartInfo|Process\.Start", re.I),
        re.compile(rb"<%.*?%>.*?Request\[", re.I | re.S),
    ]

    WEB_EXTENSIONS = {".php", ".aspx", ".asp", ".jsp", ".py", ".cgi", ".cfm", ".jspx"}

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.findings: List[Finding] = []

    def _get_web_roots(self) -> List[str]:
        """Auto-discover web server document roots."""
        os_type = get_os_type()
        roots = []
        if os_type == "windows":
            candidates = [
                "C:\\inetpub\\wwwroot", "C:\\xampp\\htdocs",
                "C:\\wamp\\www", "C:\\wamp64\\www",
                "D:\\inetpub\\wwwroot", "D:\\wwwroot",
            ]
        elif os_type == "macos":
            candidates = [
                "/Library/WebServer/Documents",
                "/usr/local/var/www",
                os.path.expanduser("~/Sites"),
            ]
        else:
            candidates = [
                "/var/www/html", "/var/www",
                "/usr/share/nginx/html",
                "/srv/www", "/srv/http",
                "/opt/lampp/htdocs",
            ]
        for c in candidates:
            if os.path.isdir(c):
                roots.append(c)
        return roots

    def scan_web_roots(self) -> List[Finding]:
        """Scan web roots for files matching web shell patterns."""
        self.logger.info("[WEBSHELL] Scanning web roots for potential web shells...")
        roots = self._get_web_roots()
        if not roots:
            self.logger.info("  No web server document roots found. Skipping.")
            return self.findings

        self.logger.info(f"  SEARCHING: {', '.join(roots)}")
        self.logger.info("  WHY: Web shells provide persistent backdoor access via web-accessible files.")

        suspicious_files = []
        files_scanned = 0
        max_files = 5000

        for root in roots:
            for dirpath, _, filenames in os.walk(root):
                for fname in filenames:
                    if files_scanned >= max_files:
                        break
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in self.WEB_EXTENSIONS:
                        continue
                    fpath = os.path.join(dirpath, fname)
                    files_scanned += 1
                    try:
                        with open(fpath, "rb") as f:
                            content = f.read(65536)  # Read first 64KB
                        match_count = sum(1 for pat in self.WEB_SHELL_PATTERNS if pat.search(content))
                        if match_count >= 2:
                            suspicious_files.append({
                                "path": fpath,
                                "pattern_matches": match_count,
                                "size_bytes": os.path.getsize(fpath),
                                "modified": datetime.fromtimestamp(
                                    os.path.getmtime(fpath), tz=timezone.utc
                                ).isoformat(),
                            })
                    except (PermissionError, OSError):
                        pass
                if files_scanned >= max_files:
                    break

        if suspicious_files:
            self.findings.append(Finding(
                self.MODULE,
                "POTENTIAL WEB SHELLS DETECTED",
                f"Found {len(suspicious_files)} files matching 2+ web shell patterns across {len(roots)} web root(s)",
                severity=5, mitre_id="T1505.003",
                evidence={"web_shells": suspicious_files[:30], "files_scanned": files_scanned},
            ))
        else:
            self.logger.info(f"  Scanned {files_scanned} web files - no web shells detected.")

        return self.findings

    def run_all(self) -> List[Finding]:
        self.scan_web_roots()
        return self.findings


# ============================================================================
# MODULE 5e: CERTIFICATE TRUST STORE AUDITOR
# ============================================================================

class CertificateAuditor:
    """Audit certificate trust stores for unauthorized or recently added certificates."""

    MODULE = "CERTIFICATE_AUDIT"

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.findings: List[Finding] = []

    def check_windows_certs(self) -> List[Finding]:
        """Audit Windows certificate store for suspicious root CAs."""
        self.logger.info("[CERTS] Auditing Windows root certificate store...")
        self.logger.info("  SEARCHING: Self-signed or recently added root CAs in LocalMachine\\Root")
        self.logger.info("  WHY: Attackers add rogue root CAs to intercept TLS traffic or sign malware.")

        out, _, rc = run_cmd(
            'powershell -Command "Get-ChildItem Cert:\\LocalMachine\\Root '
            '| Select-Object Subject,Issuer,NotBefore,NotAfter,Thumbprint '
            '| ConvertTo-Json -Depth 2" 2>nul',
            timeout=20
        )
        if rc == 0 and out:
            try:
                certs = json.loads(out)
                if isinstance(certs, dict):
                    certs = [certs]
                known_issuers = [
                    "microsoft", "digicert", "verisign", "globalsign", "comodo",
                    "entrust", "godaddy", "usertrust", "sectigo", "thawte",
                    "geotrust", "starfield", "baltimore", "amazon", "isrg",
                    "certum", "actalis", "buypass", "quovadis", "trustcor",
                ]
                suspicious_certs = []
                thirty_days_ago = datetime.now(timezone.utc).timestamp() - (30 * 86400)
                for cert in certs:
                    subject = str(cert.get("Subject", "")).lower()
                    issuer = str(cert.get("Issuer", "")).lower()
                    # Self-signed: subject == issuer
                    is_self_signed = subject == issuer
                    is_known = any(ki in issuer for ki in known_issuers)
                    # Check if recently added (NotBefore within 30 days)
                    not_before_str = str(cert.get("NotBefore", ""))
                    is_recent = False
                    try:
                        # PowerShell dates come in various formats
                        if not_before_str:
                            nb_ts = datetime.fromisoformat(not_before_str.replace("/Date(", "").replace(")/", "")).timestamp()
                            is_recent = nb_ts > thirty_days_ago
                    except (ValueError, TypeError, OSError):
                        pass
                    if (is_self_signed and not is_known) or (is_recent and not is_known):
                        suspicious_certs.append({
                            "subject": cert.get("Subject", ""),
                            "issuer": cert.get("Issuer", ""),
                            "thumbprint": cert.get("Thumbprint", ""),
                            "not_before": not_before_str,
                            "self_signed": is_self_signed,
                            "recently_added": is_recent,
                        })
                if suspicious_certs:
                    self.findings.append(Finding(
                        self.MODULE,
                        "SUSPICIOUS ROOT CERTIFICATES DETECTED",
                        f"Found {len(suspicious_certs)} suspicious certificates in the root store",
                        severity=4, mitre_id="T1553",
                        evidence={"certificates": suspicious_certs[:20]},
                    ))
            except json.JSONDecodeError:
                pass

        return self.findings

    def check_linux_certs(self) -> List[Finding]:
        """Audit Linux certificate trust store for recently modified certs."""
        self.logger.info("[CERTS] Auditing Linux certificate trust store...")
        self.logger.info("  SEARCHING: Recently modified certificates in system CA directories")
        self.logger.info("  WHY: Rogue CA certificates enable MITM attacks on TLS connections.")

        cert_dirs = [
            "/etc/ssl/certs",
            "/usr/local/share/ca-certificates",
            "/etc/pki/tls/certs",
            "/etc/pki/ca-trust/source/anchors",
        ]
        thirty_days_ago = datetime.now(timezone.utc).timestamp() - (30 * 86400)
        recent_certs = []

        for cert_dir in cert_dirs:
            if not os.path.isdir(cert_dir):
                continue
            try:
                for fname in os.listdir(cert_dir):
                    fpath = os.path.join(cert_dir, fname)
                    if not os.path.isfile(fpath):
                        continue
                    try:
                        mtime = os.path.getmtime(fpath)
                        if mtime > thirty_days_ago:
                            recent_certs.append({
                                "path": fpath,
                                "modified": datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat(),
                                "size_bytes": os.path.getsize(fpath),
                            })
                    except OSError:
                        pass
            except (PermissionError, OSError):
                pass

        if recent_certs:
            self.findings.append(Finding(
                self.MODULE,
                "RECENTLY MODIFIED CA CERTIFICATES",
                f"Found {len(recent_certs)} certificates modified within the last 30 days",
                severity=3, mitre_id="T1553",
                evidence={"recent_certificates": recent_certs[:30]},
            ))

        return self.findings

    def check_macos_certs(self) -> List[Finding]:
        """Audit macOS System keychain for non-Apple trusted root certificates."""
        self.logger.info("[CERTS] Auditing macOS System keychain for non-Apple root certificates...")
        self.logger.info("  SEARCHING: Non-Apple trusted root certificates in System.keychain")
        self.logger.info("  WHY: Rogue root CAs in the System keychain allow TLS interception.")

        out, _, rc = run_cmd(
            'security find-certificate -a -p /Library/Keychains/System.keychain 2>/dev/null',
            timeout=20
        )
        if rc == 0 and out:
            # Parse PEM certificates and check subjects
            non_apple_certs = []
            cert_blocks = out.split("-----END CERTIFICATE-----")
            for block in cert_blocks:
                block = block.strip()
                if "-----BEGIN CERTIFICATE-----" not in block:
                    continue
                pem = block + "\n-----END CERTIFICATE-----"
                # Use openssl to get subject
                import tempfile
                try:
                    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as tmp:
                        tmp.write(pem)
                        tmp_path = tmp.name
                    subj_out, _, rc2 = run_cmd(
                        f'openssl x509 -in "{tmp_path}" -noout -subject -issuer 2>/dev/null'
                    )
                    os.unlink(tmp_path)
                    if rc2 == 0 and subj_out:
                        subj_lower = subj_out.lower()
                        if "apple" not in subj_lower and "o = apple" not in subj_lower:
                            non_apple_certs.append(subj_out.strip())
                except OSError:
                    pass

            if non_apple_certs:
                self.findings.append(Finding(
                    self.MODULE,
                    "NON-APPLE ROOT CERTIFICATES IN SYSTEM KEYCHAIN",
                    f"Found {len(non_apple_certs)} non-Apple certificates in System.keychain",
                    severity=3, mitre_id="T1553",
                    evidence={"certificates": non_apple_certs[:30]},
                ))

        return self.findings

    def run_all(self) -> List[Finding]:
        os_type = get_os_type()
        if os_type == "windows":
            self.check_windows_certs()
        elif os_type == "linux":
            self.check_linux_certs()
        elif os_type == "macos":
            self.check_macos_certs()
        return self.findings


# ============================================================================
# MODULE 5b: CREDENTIAL & ARTIFACT HUNTER
# ============================================================================

class CredentialArtifactHunter:
    """Detect credential dumping artifacts and attacker command history."""

    MODULE = "CREDENTIAL_ARTIFACTS"

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.findings: List[Finding] = []

    def check_credential_dumps(self) -> List[Finding]:
        """Detect LSASS dumps, SAM/SYSTEM hive copies, and other credential artifacts."""
        self.logger.info("[CRED] Checking for credential dumping artifacts...")
        self.logger.info("  SEARCHING: LSASS memory dumps, SAM/SYSTEM/SECURITY hive copies, NTDS.dit,")
        self.logger.info("             procdump binaries, /etc/shadow copies in temp dirs")
        self.logger.info("  WHY: Nova affiliates dump credentials to move laterally and escalate privileges.")
        self.logger.info("       LSASS dumps contain plaintext passwords; NTDS.dit has all domain hashes.")
        os_type = get_os_type()

        if os_type == "windows":
            cred_artifacts = []

            # LSASS memory dump files
            lsass_patterns = ["lsass*.dmp", "lsass*.zip", "lsass*.rar"]
            dump_dirs = [
                os.path.expandvars(r"%TEMP%"),
                os.path.expandvars(r"%PROGRAMDATA%"),
                r"C:\PerfLogs",
                r"C:\Windows\Temp",
                os.path.expandvars(r"%USERPROFILE%\Desktop"),
                os.path.expandvars(r"%USERPROFILE%\Documents"),
            ]
            for ddir in dump_dirs:
                if not os.path.exists(ddir):
                    continue
                for pattern in lsass_patterns:
                    for fpath in glob.glob(os.path.join(ddir, pattern)):
                        stat = safe_stat(fpath)
                        if stat:
                            cred_artifacts.append({"type": "lsass_dump", **stat})

            # SAM / SYSTEM / SECURITY hive copies
            hive_names = ["sam", "system", "security", "ntds.dit"]
            for ddir in dump_dirs:
                if not os.path.exists(ddir):
                    continue
                try:
                    for fname in os.listdir(ddir):
                        if fname.lower() in hive_names:
                            fpath = os.path.join(ddir, fname)
                            stat = safe_stat(fpath)
                            if stat:
                                cred_artifacts.append({"type": "hive_copy", "hive": fname, **stat})
                except (PermissionError, OSError):
                    continue

            # Procdump artifacts
            for ddir in dump_dirs:
                if not os.path.exists(ddir):
                    continue
                for fpath in glob.glob(os.path.join(ddir, "procdump*.exe")):
                    stat = safe_stat(fpath)
                    if stat:
                        cred_artifacts.append({"type": "procdump_binary", **stat})

            # comsvcs.dll minidump via rundll32 (check recent PowerShell history for this)
            # This is handled in check_powershell_history below

            if cred_artifacts:
                self.findings.append(Finding(
                    self.MODULE,
                    "CREDENTIAL DUMP ARTIFACTS DETECTED",
                    f"Found {len(cred_artifacts)} credential dumping artifacts (LSASS dumps, hive copies)",
                    severity=5, mitre_id="T1003",
                    evidence={"artifacts": cred_artifacts},
                ))

        elif os_type == "linux":
            cred_artifacts = []
            # /etc/shadow copies in unusual locations
            shadow_locs = ["/tmp", "/var/tmp", "/dev/shm", "/opt"]
            for loc in shadow_locs:
                shadow_path = os.path.join(loc, "shadow")
                if os.path.exists(shadow_path):
                    stat = safe_stat(shadow_path)
                    if stat:
                        cred_artifacts.append({"type": "shadow_copy", **stat})
                # Also check for common dump tool outputs
                for pattern in ["*.dmp", "hashdump*", "mimipenguin*"]:
                    for fpath in glob.glob(os.path.join(loc, pattern)):
                        stat = safe_stat(fpath)
                        if stat:
                            cred_artifacts.append({"type": "dump_file", **stat})

            if cred_artifacts:
                self.findings.append(Finding(
                    self.MODULE,
                    "CREDENTIAL DUMP ARTIFACTS DETECTED",
                    f"Found {len(cred_artifacts)} credential-related artifacts in temp locations",
                    severity=5, mitre_id="T1003",
                    evidence={"artifacts": cred_artifacts},
                ))

        return self.findings

    def check_powershell_history(self) -> List[Finding]:
        """Check PowerShell ConsoleHost_history.txt for attacker commands."""
        self.logger.info("[CRED] Checking PowerShell ConsoleHost_history.txt for all users...")
        self.logger.info("  SEARCHING: invoke-mimikatz, invoke-expression, downloadstring, vssadmin delete,")
        self.logger.info("             comsvcs.dll, sekurlsa, reg save sam/system, rclone, net user /add")
        self.logger.info("  WHY: PowerShell history persists by default and captures attacker commands.")
        self.logger.info("       This is often the best forensic evidence of what the attacker did.")
        os_type = get_os_type()

        if os_type != "windows":
            return self.findings

        # ConsoleHost_history.txt for all users
        ps_history_base = os.path.expandvars(
            r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        )
        history_files = [ps_history_base]
        # Also check other user profiles
        users_dir = os.path.expandvars(r"%SYSTEMDRIVE%\Users")
        if os.path.exists(users_dir):
            try:
                for user_dir in os.listdir(users_dir):
                    hist = os.path.join(
                        users_dir, user_dir,
                        r"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
                    )
                    if os.path.exists(hist) and hist not in history_files:
                        history_files.append(hist)
            except (PermissionError, OSError):
                pass

        suspicious_patterns = [
            r"invoke-mimikatz", r"invoke-expression", r"downloadstring",
            r"encodedcommand", r"set-mppreference", r"-disablerealtimemonitoring",
            r"vssadmin\s+delete", r"wmic\s+shadowcopy", r"comsvcs\.dll",
            r"sekurlsa", r"lsadump", r"procdump.*lsass",
            r"reg\s+save.*\\sam", r"reg\s+save.*\\system", r"reg\s+save.*\\security",
            r"ntdsutil", r"rclone", r"megasync",
            r"net\s+user\s+.*\/add", r"net\s+localgroup\s+admin",
        ]

        for hist_file in history_files:
            if not os.path.exists(hist_file):
                continue
            try:
                with open(hist_file, "r", errors="ignore") as f:
                    lines = f.readlines()
                    suspicious_cmds = []
                    for line in lines[-500:]:
                        for pat in suspicious_patterns:
                            if re.search(pat, line, re.I):
                                suspicious_cmds.append(line.strip())
                                break
                    if suspicious_cmds:
                        self.findings.append(Finding(
                            self.MODULE,
                            "SUSPICIOUS POWERSHELL HISTORY",
                            f"Found {len(suspicious_cmds)} suspicious commands in {hist_file}",
                            severity=5, mitre_id="T1059",
                            evidence={"history_file": hist_file, "commands": suspicious_cmds[:100]},
                        ))
            except (PermissionError, OSError):
                continue

        return self.findings

    def check_proc_analysis(self) -> List[Finding]:
        """Linux: check /proc for hidden/deleted binaries and process injection."""
        self.logger.info("[CRED] Checking /proc for processes with deleted binaries or running from temp dirs...")
        self.logger.info("  SEARCHING: /proc/*/exe symlinks pointing to (deleted) or /tmp, /dev/shm, /var/tmp")
        self.logger.info("  WHY: Ransomware often deletes its own binary after execution to avoid detection,")
        self.logger.info("       but the process stays in memory. This catches fileless/in-memory malware.")
        os_type = get_os_type()

        if os_type != "linux":
            return self.findings

        suspicious_procs = []
        try:
            for pid_dir in os.listdir("/proc"):
                if not pid_dir.isdigit():
                    continue
                exe_link = f"/proc/{pid_dir}/exe"
                try:
                    exe_path = os.readlink(exe_link)
                    is_deleted = "(deleted)" in exe_path
                    is_temp = any(loc in exe_path for loc in ["/tmp/", "/dev/shm/", "/var/tmp/"])
                    if is_deleted or is_temp:
                        proc_entry: Dict[str, Any] = {
                            "pid": pid_dir,
                            "exe": exe_path,
                            "issue": "Binary deleted from disk but still running" if is_deleted
                                     else "Running from suspicious temp location",
                        }
                        # Command line
                        try:
                            with open(f"/proc/{pid_dir}/cmdline", "r") as f:
                                proc_entry["cmdline"] = f.read().replace("\x00", " ").strip()
                        except (PermissionError, OSError):
                            proc_entry["cmdline"] = ""
                        # Parent PID
                        try:
                            with open(f"/proc/{pid_dir}/status", "r") as f:
                                for sline in f:
                                    if sline.startswith("PPid:"):
                                        proc_entry["ppid"] = sline.split(":")[1].strip()
                                    elif sline.startswith("Uid:"):
                                        proc_entry["uid"] = sline.split(":")[1].strip().split()[0]
                                    elif sline.startswith("Name:"):
                                        proc_entry["process_name"] = sline.split(":")[1].strip()
                        except (PermissionError, OSError):
                            pass
                        # Open file descriptor count
                        try:
                            fd_dir = f"/proc/{pid_dir}/fd"
                            proc_entry["open_fds"] = len(os.listdir(fd_dir))
                        except (PermissionError, OSError):
                            pass
                        # Network connections from /proc/net (via cmdline)
                        net_out, _, net_rc = run_cmd(f"ss -tnp | grep 'pid={pid_dir},' 2>/dev/null", timeout=5)
                        if net_rc == 0 and net_out:
                            proc_entry["network_connections"] = [l.strip() for l in net_out.split("\n") if l.strip()][:5]
                        suspicious_procs.append(proc_entry)
                except (PermissionError, OSError, FileNotFoundError):
                    continue
        except (PermissionError, OSError):
            pass

        if suspicious_procs:
            self.findings.append(Finding(
                self.MODULE,
                "SUSPICIOUS PROCESSES IN /proc",
                f"Found {len(suspicious_procs)} processes with deleted binaries or running from temp dirs",
                severity=5, mitre_id="T1055",
                evidence={"processes": suspicious_procs},
            ))

        return self.findings

    def check_user_accounts(self) -> List[Finding]:
        """Cross-platform check for recently created or suspicious user accounts."""
        self.logger.info("[CRED] Checking for suspicious or recently created user accounts...")
        self.logger.info("  SEARCHING: Root-equivalent accounts (UID 0), recently created users (<30 days),")
        self.logger.info("             accounts with login shells in unusual states")
        self.logger.info("  WHY: Attackers create backdoor accounts (e.g., 'support', 'admin2') for re-entry.")
        self.logger.info("       UID 0 accounts other than root indicate a rootkit or backdoor.")
        os_type = get_os_type()
        suspicious_users = []

        if os_type == "windows":
            out, _, rc = run_cmd(
                'wmic useraccount get Name,SID,Status,Disabled,LocalAccount /format:csv 2>nul',
                timeout=15
            )
            if rc == 0 and out:
                # Also check for recently created accounts via net user
                out2, _, rc2 = run_cmd('net user 2>nul')
                if rc2 == 0 and out2:
                    suspicious_users.append({"type": "user_list", "output": out2[:3000]})

        elif os_type == "linux":
            # Check for users with UID >= 1000 or UID 0 (root equivalents)
            try:
                with open("/etc/passwd", "r") as f:
                    for line in f:
                        parts = line.strip().split(":")
                        if len(parts) >= 7:
                            username, uid, shell = parts[0], int(parts[2]), parts[6]
                            # Root-equivalent accounts (UID 0 that aren't root)
                            if uid == 0 and username != "root":
                                suspicious_users.append({
                                    "type": "root_equivalent",
                                    "username": username,
                                    "uid": uid,
                                    "shell": shell,
                                })
                            # Users with login shells added recently
                            if uid >= 1000 and shell in ["/bin/bash", "/bin/sh", "/bin/zsh"]:
                                home = parts[5]
                                if os.path.exists(home):
                                    try:
                                        mtime = os.path.getmtime(home)
                                        if (datetime.now(timezone.utc).timestamp() - mtime) < 30 * 86400:
                                            suspicious_users.append({
                                                "type": "recent_user",
                                                "username": username,
                                                "uid": uid,
                                                "home": home,
                                                "shell": shell,
                                                "home_modified": datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat(),
                                            })
                                    except OSError:
                                        pass
            except (PermissionError, OSError):
                pass

        elif os_type == "macos":
            out, _, rc = run_cmd("dscl . list /Users UniqueID 2>/dev/null")
            if rc == 0 and out:
                for line in out.split("\n"):
                    parts = line.split()
                    if len(parts) == 2:
                        username, uid = parts[0], int(parts[1])
                        if uid >= 500 and not username.startswith("_"):
                            suspicious_users.append({
                                "type": "local_user",
                                "username": username,
                                "uid": uid,
                            })

        if suspicious_users:
            sev = 5 if any(u.get("type") == "root_equivalent" for u in suspicious_users) else 3
            self.findings.append(Finding(
                self.MODULE,
                "USER ACCOUNT ANOMALIES",
                f"Found {len(suspicious_users)} user account entries to investigate",
                severity=sev, mitre_id="T1136",
                evidence={"users": suspicious_users},
            ))

        return self.findings

    def check_network_recon(self) -> List[Finding]:
        """Capture ARP table and routing table for lateral movement path analysis."""
        self.logger.info("[CRED] Capturing network reconnaissance data (ARP, routes, interfaces)...")
        self.logger.info("  SEARCHING: ARP table, routing table, network interface configuration")
        self.logger.info("  WHY: Shows what other hosts this machine communicated with, revealing")
        self.logger.info("       the attacker's lateral movement path across your network.")
        os_type = get_os_type()
        recon_data = {}

        if os_type == "windows":
            out, _, rc = run_cmd("arp -a 2>nul")
            if rc == 0 and out:
                recon_data["arp_table"] = out[:5000]
            out, _, rc = run_cmd("route print 2>nul")
            if rc == 0 and out:
                recon_data["routing_table"] = out[:5000]
            out, _, rc = run_cmd("ipconfig /all 2>nul")
            if rc == 0 and out:
                recon_data["network_config"] = out[:5000]
        else:
            out, _, rc = run_cmd("arp -a 2>/dev/null || ip neigh 2>/dev/null")
            if rc == 0 and out:
                recon_data["arp_table"] = out[:5000]
            out, _, rc = run_cmd("ip route 2>/dev/null || route -n 2>/dev/null || netstat -rn 2>/dev/null")
            if rc == 0 and out:
                recon_data["routing_table"] = out[:5000]
            out, _, rc = run_cmd("ip addr 2>/dev/null || ifconfig -a 2>/dev/null")
            if rc == 0 and out:
                recon_data["network_config"] = out[:5000]

        if recon_data:
            self.findings.append(Finding(
                self.MODULE,
                "NETWORK RECONNAISSANCE DATA",
                "Captured ARP, routing, and network config for lateral movement analysis",
                severity=1, mitre_id="T1018",
                evidence=recon_data,
            ))

        return self.findings

    def run_all(self) -> List[Finding]:
        self.check_credential_dumps()
        self.check_powershell_history()
        self.check_proc_analysis()
        self.check_user_accounts()
        self.check_network_recon()
        return self.findings


# ============================================================================
# MODULE 6: LIVE TRIAGE
# ============================================================================

class LiveTriage:
    """Current system state: processes, connections, users, open handles."""
    
    MODULE = "LIVE_TRIAGE"
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.findings: List[Finding] = []
    
    def triage(self) -> List[Finding]:
        self.logger.info("[TRIAGE] Running live system triage...")
        self.logger.info("  SEARCHING: Current logged-in users, running processes, network connections,")
        self.logger.info("             listening ports, DNS cache entries")
        self.logger.info("  WHY: Captures volatile evidence that is lost on reboot. Shows if the attacker")
        self.logger.info("       is CURRENTLY active on this system right now.")
        os_type = get_os_type()
        triage_data = {"os": os_type, "hostname": socket.gethostname(),
                       "timestamp": datetime.now(timezone.utc).isoformat()}
        
        # --- Current Users ---
        if os_type == "windows":
            out, _, _ = run_cmd("query user 2>nul")
        else:
            out, _, _ = run_cmd("who 2>/dev/null")
        triage_data["current_users"] = out
        
        # --- Suspicious Processes ---
        out = get_system_cache().get_process_list()

        suspicious_procs = []
        if out:
            for proc_name in NOVA_IOCS["suspicious_processes"]:
                if proc_name.lower() in out.lower():
                    matches = [l for l in out.split("\n") if proc_name.lower() in l.lower()]
                    for match_line in matches[:5]:
                        proc_entry: Dict[str, Any] = {
                            "matched_tool": proc_name,
                            "raw_line": match_line.strip(),
                        }
                        # Try to parse PID and other fields from ps/tasklist output
                        parts = match_line.split()
                        if os_type == "windows":
                            # tasklist CSV: "Image Name","PID","Session Name","Session#","Mem Usage",...
                            csv_parts = [p.strip('"') for p in match_line.split('","')]
                            if len(csv_parts) >= 2:
                                proc_entry["process_name"] = csv_parts[0]
                                proc_entry["pid"] = csv_parts[1]
                                if len(csv_parts) >= 5:
                                    proc_entry["memory_usage"] = csv_parts[4]
                        else:
                            # ps aux: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
                            if len(parts) >= 11:
                                proc_entry["user"] = parts[0]
                                proc_entry["pid"] = parts[1]
                                proc_entry["cpu_percent"] = parts[2]
                                proc_entry["memory_percent"] = parts[3]
                                proc_entry["start_time"] = parts[8]
                                proc_entry["command"] = " ".join(parts[10:])
                        suspicious_procs.append(proc_entry)

        if suspicious_procs:
            tool_names = list(set(p["matched_tool"] for p in suspicious_procs))
            self.findings.append(Finding(
                self.MODULE,
                "SUSPICIOUS PROCESSES RUNNING",
                f"Found {len(suspicious_procs)} suspicious processes: {', '.join(tool_names)}",
                severity=4, mitre_id="T1059",
                evidence={"processes": suspicious_procs},
            ))
        
        triage_data["process_list_preview"] = out[:5000] if out else ""
        
        # --- Network Connections ---
        out = get_system_cache().get_netstat_output()
        triage_data["network_connections"] = out[:5000] if out else ""
        
        # --- Listening Ports ---
        if os_type == "windows":
            out, _, _ = run_cmd('netstat -nao | findstr "LISTENING" 2>nul')
        else:
            out, _, _ = run_cmd("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        triage_data["listening_ports"] = out[:3000] if out else ""
        
        # Flag unusual listeners
        if out:
            unusual = []
            suspicious_ports = {"4444", "5555", "6666", "8888", "9999", "1234", "31337", "9050"}
            for line in out.split("\n"):
                for port in suspicious_ports:
                    if f":{port}" in line:
                        listener = {"port": port, "raw_line": line.strip()}
                        # Try to extract bind address and PID
                        addr_match = re.search(r'(\S+):' + port, line)
                        if addr_match:
                            listener["bind_address"] = addr_match.group(1)
                        pid_match = re.search(r'(?:pid[=,])(\d+)|(\d+)\s*$', line)
                        if pid_match:
                            listener["pid"] = pid_match.group(1) or pid_match.group(2)
                        unusual.append(listener)
                        break
            if unusual:
                ports_found = list(set(u["port"] for u in unusual))
                self.findings.append(Finding(
                    self.MODULE,
                    "UNUSUAL LISTENING PORTS",
                    f"Found {len(unusual)} processes listening on suspicious ports: {', '.join(ports_found)}",
                    severity=4, mitre_id="T1059",
                    evidence={"listeners": unusual},
                ))
        
        # --- DNS Cache (Windows) ---
        if os_type == "windows":
            out, _, rc = run_cmd("ipconfig /displaydns 2>nul", timeout=15)
            if rc == 0 and out:
                # Parse DNS cache into records: Record Name, Record Type, A (Host) Record
                suspicious_dns = []
                suspicious_domains = [".onion", "mega.nz", "mega.co", "anonfiles",
                                       "transfer.sh", "gofile.io", "dropmefiles"]
                current_record: Dict[str, str] = {}
                for line in out.split("\n"):
                    line = line.strip()
                    if "Record Name" in line:
                        current_record = {"domain": line.split(":", 1)[1].strip() if ":" in line else ""}
                    elif "Record Type" in line:
                        current_record["record_type"] = line.split(":", 1)[1].strip() if ":" in line else ""
                    elif "A (Host) Record" in line or "AAAA" in line:
                        current_record["resolved_ip"] = line.split(":", 1)[1].strip() if ":" in line else ""
                    elif "Time To Live" in line:
                        current_record["ttl"] = line.split(":", 1)[1].strip() if ":" in line else ""
                    elif line == "" and current_record.get("domain"):
                        domain = current_record.get("domain", "").lower()
                        if any(d in domain for d in suspicious_domains):
                            suspicious_dns.append(current_record)
                        current_record = {}
                # Check the last record
                if current_record.get("domain"):
                    domain = current_record.get("domain", "").lower()
                    if any(d in domain for d in suspicious_domains):
                        suspicious_dns.append(current_record)
                if suspicious_dns:
                    domains_found = list(set(d.get("domain", "") for d in suspicious_dns))
                    self.findings.append(Finding(
                        self.MODULE,
                        "SUSPICIOUS DNS CACHE ENTRIES",
                        f"Found {len(suspicious_dns)} suspicious domain(s) in DNS cache: {', '.join(domains_found[:5])}",
                        severity=4, mitre_id="T1048",
                        evidence={"dns_entries": suspicious_dns},
                    ))
        
        # Store full triage data
        self.findings.append(Finding(
            self.MODULE, "SYSTEM TRIAGE SNAPSHOT",
            f"Live triage of {triage_data['hostname']}",
            severity=1, evidence=triage_data,
        ))
        
        return self.findings
    
    def run_all(self) -> List[Finding]:
        return self.triage()


# ============================================================================
# MODULE 8: EVTX ANALYZER (Offline Event Log Parsing)
# ============================================================================

class EVTXAnalyzer:
    """Parse offline .evtx files and generate Nova-specific findings."""

    MODULE = "EVTX_ANALYSIS"

    # Nova-specific command patterns to detect in event logs
    NOVA_CMD_PATTERNS = [
        re.compile(r"rclone", re.I),
        re.compile(r"mimikatz", re.I),
        re.compile(r"psexec", re.I),
        re.compile(r"sharphound", re.I),
        re.compile(r"bloodhound", re.I),
        re.compile(r"lazagne", re.I),
        re.compile(r"chisel", re.I),
        re.compile(r"ngrok", re.I),
        re.compile(r"anydesk", re.I),
        re.compile(r"megasync", re.I),
        re.compile(r"netscan", re.I),
        re.compile(r"advanced_ip_scanner", re.I),
    ]

    POWERSHELL_SUSPICIOUS = [
        re.compile(r"invoke-expression", re.I),
        re.compile(r"downloadstring", re.I),
        re.compile(r"encodedcommand", re.I),
        re.compile(r"set-mppreference", re.I),
        re.compile(r"-disablerealtimemonitoring", re.I),
        re.compile(r"vssadmin\s+(delete|resize)\s+shadows", re.I),
        re.compile(r"wmic\s+shadowcopy\s+delete", re.I),
        re.compile(r"bcdedit.*recoveryenabled.*no", re.I),
        re.compile(r"rclone", re.I),
        re.compile(r"invoke-mimikatz", re.I),
        re.compile(r"sekurlsa", re.I),
        re.compile(r"comsvcs\.dll", re.I),
        re.compile(r"net\s+user\s+.*\/add", re.I),
        re.compile(r"net\s+localgroup\s+admin", re.I),
    ]

    SUSPICIOUS_SERVICES = [
        re.compile(r"temp", re.I),
        re.compile(r"appdata", re.I),
        re.compile(r"perflog", re.I),
        re.compile(r"powershell", re.I),
        re.compile(r"cmd\.exe", re.I),
        re.compile(r"psexe", re.I),
        re.compile(r"anydesk", re.I),
        re.compile(r"splashtop", re.I),
        re.compile(r"atera", re.I),
    ]

    EXFIL_DOMAINS = [
        "mega.nz", "mega.co.nz", "anonfiles.com", "transfer.sh",
        "gofile.io", "dropmefiles.com", "send.exploit.in",
    ]

    def __init__(self, evtx_paths: List[str], logger: logging.Logger):
        self.logger = logger
        self.findings: List[Finding] = []
        self.evtx_files: List[str] = []

        for p in evtx_paths:
            if os.path.isdir(p):
                for root, _, files in os.walk(p):
                    for f in files:
                        if f.lower().endswith(".evtx"):
                            self.evtx_files.append(os.path.join(root, f))
            elif os.path.isfile(p) and p.lower().endswith(".evtx"):
                self.evtx_files.append(p)

        if not self.evtx_files:
            self.logger.warning("[EVTX] No .evtx files found in provided paths")

    def _parse_evtx_file(self, path: str) -> List[Dict]:
        """Parse a single .evtx file into a list of event dicts."""
        events = []
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        xml_str = record.xml()
                        evt = self._parse_event_xml(xml_str)
                        if evt:
                            evt["_source_file"] = path
                            events.append(evt)
                    except Exception:
                        continue
        except Exception as e:
            self.logger.error(f"[EVTX] Failed to parse {path}: {e}")
        return events

    def _parse_event_xml(self, xml_str: str) -> Optional[Dict]:
        """Extract fields from event XML into a flat dict."""
        try:
            root = ET.fromstring(xml_str)
            ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

            system = root.find("ns:System", ns)
            if system is None:
                return None

            evt: Dict[str, Any] = {}
            eid_el = system.find("ns:EventID", ns)
            evt["EventID"] = int(eid_el.text) if eid_el is not None and eid_el.text else 0

            tc_el = system.find("ns:TimeCreated", ns)
            evt["TimeCreated"] = tc_el.get("SystemTime", "") if tc_el is not None else ""

            provider_el = system.find("ns:Provider", ns)
            evt["Provider"] = provider_el.get("Name", "") if provider_el is not None else ""

            channel_el = system.find("ns:Channel", ns)
            evt["Channel"] = channel_el.text if channel_el is not None and channel_el.text else ""

            computer_el = system.find("ns:Computer", ns)
            evt["Computer"] = computer_el.text if computer_el is not None and computer_el.text else ""

            # Parse EventData
            event_data = root.find("ns:EventData", ns)
            if event_data is not None:
                for data_el in event_data:
                    name = data_el.get("Name", "")
                    value = data_el.text or ""
                    if name:
                        evt[name] = value
                    elif value:
                        evt.setdefault("_data_values", []).append(value)

            # Parse UserData if present
            user_data = root.find("ns:UserData", ns)
            if user_data is not None:
                for child in user_data:
                    for el in child:
                        tag = el.tag.split("}")[-1] if "}" in el.tag else el.tag
                        if el.text:
                            evt[tag] = el.text

            return evt
        except ET.ParseError:
            return None

    def _classify_log(self, path: str, events: List[Dict]) -> str:
        """Auto-detect log type from filename or content."""
        basename = os.path.basename(path).lower()
        if "security" in basename:
            return "security"
        if "system" in basename:
            return "system"
        if "powershell" in basename or "operational" in basename:
            # Check if PowerShell by provider
            if events:
                provider = events[0].get("Provider", "")
                if "powershell" in provider.lower():
                    return "powershell"
        if "sysmon" in basename:
            return "sysmon"
        if "terminalsession" in basename or "terminalservices" in basename or "rdp" in basename:
            return "rdp"

        # Classify by channel/provider from first event
        if events:
            channel = events[0].get("Channel", "").lower()
            provider = events[0].get("Provider", "").lower()
            if "security" in channel:
                return "security"
            if channel == "system":
                return "system"
            if "powershell" in channel or "powershell" in provider:
                return "powershell"
            if "sysmon" in provider or "sysmon" in channel:
                return "sysmon"
            if "terminalservices" in channel or "terminalservices" in provider:
                return "rdp"

        return "unknown"

    def analyze_security_log(self, events: List[Dict]) -> List[Finding]:
        """Analyze Windows Security event log events."""
        findings = []

        # EventID 1102: Audit log cleared
        cleared = [e for e in events if e.get("EventID") == 1102]
        if cleared:
            findings.append(Finding(
                self.MODULE, "SECURITY LOG CLEARED (EVTX)",
                f"Found {len(cleared)} log-clearing events (EventID 1102) in offline EVTX",
                severity=5, mitre_id="T1070",
                evidence={"events": [{
                    "time": e.get("TimeCreated"), "computer": e.get("Computer"),
                    "cleared_by": e.get("SubjectUserName", "") or e.get("AccountName", ""),
                    "domain": e.get("SubjectDomainName", ""),
                } for e in cleared[:20]]},
            ))

        # EventID 4624: Successful logon
        logons_4624 = [e for e in events if e.get("EventID") == 4624]
        rdp_logons = [e for e in logons_4624 if e.get("LogonType") == "10"]
        net_logons = [e for e in logons_4624 if e.get("LogonType") == "3"]

        if rdp_logons:
            evidence_list = []
            for e in rdp_logons[:30]:
                evidence_list.append({
                    "time": e.get("TimeCreated"), "user": e.get("TargetUserName", ""),
                    "source_ip": e.get("IpAddress", ""), "computer": e.get("Computer", ""),
                })
            findings.append(Finding(
                self.MODULE, "RDP LOGONS DETECTED (EVTX)",
                f"Found {len(rdp_logons)} RDP logon events (Type 10) in Security log",
                severity=4, mitre_id="T1021",
                evidence={"rdp_logons": evidence_list, "total": len(rdp_logons)},
            ))

        if net_logons:
            evidence_list = []
            for e in net_logons[:30]:
                evidence_list.append({
                    "time": e.get("TimeCreated"), "user": e.get("TargetUserName", ""),
                    "source_ip": e.get("IpAddress", ""), "computer": e.get("Computer", ""),
                })
            findings.append(Finding(
                self.MODULE, "NETWORK LOGONS DETECTED (EVTX)",
                f"Found {len(net_logons)} network logon events (Type 3) in Security log",
                severity=3, mitre_id="T1021",
                evidence={"net_logons": evidence_list, "total": len(net_logons)},
            ))

        # EventID 4625: Failed logons (brute force)
        failed = [e for e in events if e.get("EventID") == 4625]
        if len(failed) >= 10:
            src_ips = defaultdict(int)
            targeted_users = defaultdict(int)
            timestamps = []
            for e in failed:
                ip = e.get("IpAddress", "unknown")
                src_ips[ip] += 1
                user = e.get("TargetUserName", "unknown")
                targeted_users[user] += 1
                ts = e.get("TimeCreated", "")
                if ts:
                    timestamps.append(ts)
            timestamps.sort()
            findings.append(Finding(
                self.MODULE, "BRUTE FORCE ATTEMPT DETECTED (EVTX)",
                f"Found {len(failed)} failed logon events (EventID 4625) from {len(src_ips)} source IP(s) "
                f"targeting {len(targeted_users)} account(s)",
                severity=4, mitre_id="T1110",
                evidence={
                    "total_failures": len(failed),
                    "source_ips": dict(src_ips),
                    "targeted_usernames": dict(targeted_users),
                    "first_attempt": timestamps[0] if timestamps else "",
                    "last_attempt": timestamps[-1] if timestamps else "",
                },
            ))

        # EventID 4688: Process creation
        procs = [e for e in events if e.get("EventID") == 4688]
        nova_procs = []
        for e in procs:
            cmdline = e.get("CommandLine", "") or e.get("NewProcessName", "")
            for pat in self.NOVA_CMD_PATTERNS:
                if pat.search(cmdline):
                    nova_procs.append({
                        "time": e.get("TimeCreated"), "command": cmdline,
                        "user": e.get("SubjectUserName", ""), "matched": pat.pattern,
                    })
                    break
        if nova_procs:
            findings.append(Finding(
                self.MODULE, "NOVA TOOL EXECUTION DETECTED (EVTX)",
                f"Found {len(nova_procs)} process creation events matching Nova affiliate tools",
                severity=5, mitre_id="T1059",
                evidence={"processes": nova_procs[:50]},
            ))

        # EventID 4697: Service installed
        svc_installs = [e for e in events if e.get("EventID") == 4697]
        if svc_installs:
            svc_list = []
            for e in svc_installs:
                svc_list.append({
                    "time": e.get("TimeCreated"), "service": e.get("ServiceName", ""),
                    "path": e.get("ServiceFileName", ""), "account": e.get("ServiceAccount", ""),
                })
            findings.append(Finding(
                self.MODULE, "SERVICE INSTALLED (EVTX)",
                f"Found {len(svc_installs)} service installation events (EventID 4697)",
                severity=4, mitre_id="T1543",
                evidence={"services": svc_list[:30]},
            ))

        # EventID 4698: Scheduled task created
        schtasks = [e for e in events if e.get("EventID") == 4698]
        if schtasks:
            task_list = []
            for e in schtasks:
                task_list.append({
                    "time": e.get("TimeCreated"), "task_name": e.get("TaskName", ""),
                    "content": e.get("TaskContent", "")[:500],
                })
            findings.append(Finding(
                self.MODULE, "SCHEDULED TASK CREATED (EVTX)",
                f"Found {len(schtasks)} scheduled task creation events (EventID 4698)",
                severity=4, mitre_id="T1053",
                evidence={"tasks": task_list[:30]},
            ))

        # EventID 4720: Account created
        new_accounts = [e for e in events if e.get("EventID") == 4720]
        if new_accounts:
            acct_list = []
            for e in new_accounts:
                acct_list.append({
                    "time": e.get("TimeCreated"), "new_user": e.get("TargetUserName", ""),
                    "created_by": e.get("SubjectUserName", ""),
                })
            findings.append(Finding(
                self.MODULE, "USER ACCOUNT CREATED (EVTX)",
                f"Found {len(new_accounts)} account creation events (EventID 4720)",
                severity=4, mitre_id="T1136",
                evidence={"accounts": acct_list[:30]},
            ))

        # EventID 4732: User added to admin group
        group_adds = [e for e in events if e.get("EventID") == 4732]
        if group_adds:
            adds_list = []
            for e in group_adds:
                adds_list.append({
                    "time": e.get("TimeCreated"),
                    "member": e.get("MemberName", "") or e.get("MemberSid", ""),
                    "group": e.get("TargetUserName", ""),
                    "added_by": e.get("SubjectUserName", ""),
                })
            findings.append(Finding(
                self.MODULE, "USER ADDED TO GROUP (EVTX)",
                f"Found {len(group_adds)} group membership change events (EventID 4732)",
                severity=4, mitre_id="T1098",
                evidence={"group_changes": adds_list[:30]},
            ))

        return findings

    def analyze_system_log(self, events: List[Dict]) -> List[Finding]:
        """Analyze Windows System event log events."""
        findings = []

        # EventID 7045: New service installed
        new_svcs = [e for e in events if e.get("EventID") == 7045]
        suspicious_svcs = []
        for e in new_svcs:
            svc_name = e.get("ServiceName", "")
            svc_path = e.get("ImagePath", "")
            combined = f"{svc_name} {svc_path}"
            for pat in self.SUSPICIOUS_SERVICES:
                if pat.search(combined):
                    suspicious_svcs.append({
                        "time": e.get("TimeCreated"), "service": svc_name,
                        "path": svc_path, "account": e.get("AccountName", ""),
                    })
                    break

        if suspicious_svcs:
            findings.append(Finding(
                self.MODULE, "SUSPICIOUS SERVICE INSTALLED (EVTX)",
                f"Found {len(suspicious_svcs)} suspicious new services (EventID 7045)",
                severity=4, mitre_id="T1543",
                evidence={"services": suspicious_svcs[:30]},
            ))
        elif new_svcs:
            svc_list = []
            for e in new_svcs[:20]:
                svc_list.append({
                    "time": e.get("TimeCreated"), "service": e.get("ServiceName", ""),
                    "path": e.get("ImagePath", ""),
                })
            findings.append(Finding(
                self.MODULE, "NEW SERVICES INSTALLED (EVTX)",
                f"Found {len(new_svcs)} new service installations (EventID 7045)",
                severity=2, mitre_id="T1543",
                evidence={"services": svc_list},
            ))

        # EventID 7036: Service state change — look for security services stopped
        state_changes = [e for e in events if e.get("EventID") == 7036]
        security_stopped = []
        security_svc_names = ["windows defender", "mpssvc", "windefend", "sense",
                              "wscsvc", "securityhealthservice", "wuauserv"]
        for e in state_changes:
            param1 = (e.get("param1", "") or "").lower()
            param2 = (e.get("param2", "") or "").lower()
            if any(s in param1 for s in security_svc_names) and "stopped" in param2:
                security_stopped.append({
                    "time": e.get("TimeCreated"), "service": e.get("param1", ""),
                    "state": e.get("param2", ""),
                })

        if security_stopped:
            findings.append(Finding(
                self.MODULE, "SECURITY SERVICE STOPPED (EVTX)",
                f"Found {len(security_stopped)} security service stop events",
                severity=5, mitre_id="T1562",
                evidence={"stopped": security_stopped[:30]},
            ))

        return findings

    def analyze_powershell_log(self, events: List[Dict]) -> List[Finding]:
        """Analyze PowerShell Operational event log events."""
        findings = []

        # EventID 4104: Script block logging
        script_blocks = [e for e in events if e.get("EventID") == 4104]
        suspicious_blocks = []
        for e in script_blocks:
            script_text = e.get("ScriptBlockText", "") or e.get("_data_values", [""])[0] if e.get("_data_values") else ""
            if not script_text:
                continue
            for pat in self.POWERSHELL_SUSPICIOUS:
                if pat.search(script_text):
                    suspicious_blocks.append({
                        "time": e.get("TimeCreated"),
                        "matched_pattern": pat.pattern,
                        "matched_content_snippet": script_text[:200],
                    })
                    break

        if suspicious_blocks:
            findings.append(Finding(
                self.MODULE, "SUSPICIOUS POWERSHELL SCRIPTS (EVTX)",
                f"Found {len(suspicious_blocks)} suspicious PowerShell script blocks (EventID 4104)",
                severity=5, mitre_id="T1059",
                evidence={"script_blocks": suspicious_blocks[:50]},
            ))

        return findings

    def analyze_sysmon_log(self, events: List[Dict]) -> List[Finding]:
        """Analyze Sysmon event log events."""
        findings = []

        # EventID 1: Process creation
        proc_creates = [e for e in events if e.get("EventID") == 1]
        nova_procs = []
        for e in proc_creates:
            cmdline = e.get("CommandLine", "") or e.get("Image", "")
            for pat in self.NOVA_CMD_PATTERNS:
                if pat.search(cmdline):
                    nova_procs.append({
                        "time": e.get("TimeCreated"), "image": e.get("Image", ""),
                        "commandline": (e.get("CommandLine", "") or "")[:300],
                        "user": e.get("User", ""), "parent": e.get("ParentImage", ""),
                        "hashes": e.get("Hashes", ""),
                    })
                    break

        # Check hashes against known Nova hashes
        known_hashes = set()
        for h in NOVA_IOCS["sha256_hashes"]:
            known_hashes.add(h.lower())
        for h in NOVA_IOCS["md5_hashes"]:
            known_hashes.add(h.lower())

        hash_matches = []
        for e in proc_creates:
            hashes_str = e.get("Hashes", "")
            if hashes_str:
                for h_part in hashes_str.split(","):
                    h_val = h_part.split("=")[-1].strip().lower() if "=" in h_part else h_part.strip().lower()
                    if h_val in known_hashes:
                        hash_matches.append({
                            "time": e.get("TimeCreated"), "image": e.get("Image", ""),
                            "hash_match": h_val, "full_hashes": hashes_str,
                        })
                        break

        if hash_matches:
            findings.append(Finding(
                self.MODULE, "NOVA MALWARE HASH MATCH IN SYSMON (EVTX)",
                f"Found {len(hash_matches)} process(es) matching known Nova hashes",
                severity=5, mitre_id="T1486",
                evidence={"hash_matches": hash_matches[:20]},
            ))

        if nova_procs:
            findings.append(Finding(
                self.MODULE, "NOVA TOOL EXECUTION IN SYSMON (EVTX)",
                f"Found {len(nova_procs)} processes matching Nova affiliate tools in Sysmon",
                severity=5, mitre_id="T1059",
                evidence={"processes": nova_procs[:50]},
            ))

        # EventID 3: Network connection — match C2 IPs
        net_conns = [e for e in events if e.get("EventID") == 3]
        c2_ips = set(NOVA_IOCS.get("c2_ips", []))
        c2_hits = []
        for e in net_conns:
            dest_ip = e.get("DestinationIp", "")
            if dest_ip in c2_ips:
                c2_hits.append({
                    "time": e.get("TimeCreated"), "image": e.get("Image", ""),
                    "dest_ip": dest_ip, "dest_port": e.get("DestinationPort", ""),
                    "user": e.get("User", ""),
                })

        if c2_hits:
            findings.append(Finding(
                self.MODULE, "CONNECTION TO NOVA C2 IP IN SYSMON (EVTX)",
                f"Found {len(c2_hits)} connections to known Nova C2 IPs in Sysmon logs",
                severity=5, mitre_id="T1071",
                evidence={"c2_connections": c2_hits[:30]},
            ))

        # EventID 11: File creation — .ralord, .nova, ransom notes
        file_creates = [e for e in events if e.get("EventID") == 11]
        nova_files = []
        ext_set = set(e.lower() for e in NOVA_IOCS["file_extensions"])
        note_names = set(n.lower() for n in NOVA_IOCS["ransom_note_names"])
        note_pattern = re.compile(NOVA_IOCS.get("ransom_note_pattern", ""), re.I) if NOVA_IOCS.get("ransom_note_pattern") else None

        for e in file_creates:
            target = e.get("TargetFilename", "")
            if not target:
                continue
            fname = os.path.basename(target).lower()
            _, ext = os.path.splitext(fname)
            if ext in ext_set or fname in note_names or (note_pattern and note_pattern.match(os.path.basename(target))):
                nova_files.append({
                    "time": e.get("TimeCreated"), "file": target,
                    "image": e.get("Image", ""),
                })

        if nova_files:
            findings.append(Finding(
                self.MODULE, "NOVA ENCRYPTED FILES / RANSOM NOTES IN SYSMON (EVTX)",
                f"Found {len(nova_files)} Nova-related file creation events in Sysmon",
                severity=5, mitre_id="T1486",
                evidence={"files": nova_files[:50]},
            ))

        # EventID 13: Registry value set (persistence keys)
        reg_sets = [e for e in events if e.get("EventID") == 13]
        persistence_keys = []
        persist_patterns = [
            re.compile(r"currentversion\\run", re.I),
            re.compile(r"currentversion\\runonce", re.I),
            re.compile(r"winlogon\\shell", re.I),
            re.compile(r"winlogon\\userinit", re.I),
            re.compile(r"policies\\explorer\\run", re.I),
        ]
        for e in reg_sets:
            target_obj = e.get("TargetObject", "")
            for pat in persist_patterns:
                if pat.search(target_obj):
                    persistence_keys.append({
                        "time": e.get("TimeCreated"), "key": target_obj,
                        "details": e.get("Details", ""), "image": e.get("Image", ""),
                    })
                    break

        if persistence_keys:
            findings.append(Finding(
                self.MODULE, "REGISTRY PERSISTENCE MODIFIED IN SYSMON (EVTX)",
                f"Found {len(persistence_keys)} registry persistence modifications",
                severity=4, mitre_id="T1547",
                evidence={"registry_keys": persistence_keys[:30]},
            ))

        # EventID 22: DNS query — onion, mega.nz, exfil domains
        dns_queries = [e for e in events if e.get("EventID") == 22]
        suspicious_dns = []
        onion_domains = set(d.lower() for d in NOVA_IOCS.get("onion_domains", []))
        for e in dns_queries:
            query_name = (e.get("QueryName", "") or "").lower()
            is_suspicious = False
            if ".onion" in query_name:
                is_suspicious = True
            elif query_name in onion_domains:
                is_suspicious = True
            elif any(d in query_name for d in self.EXFIL_DOMAINS):
                is_suspicious = True
            if is_suspicious:
                suspicious_dns.append({
                    "time": e.get("TimeCreated"), "query": e.get("QueryName", ""),
                    "image": e.get("Image", ""),
                })

        if suspicious_dns:
            findings.append(Finding(
                self.MODULE, "SUSPICIOUS DNS QUERIES IN SYSMON (EVTX)",
                f"Found {len(suspicious_dns)} suspicious DNS queries (onion/exfil domains)",
                severity=4, mitre_id="T1048",
                evidence={"dns_queries": suspicious_dns[:30]},
            ))

        return findings

    def analyze_rdp_log(self, events: List[Dict]) -> List[Finding]:
        """Analyze RDP/Terminal Services event log events."""
        findings = []

        # EventID 21: RDP session logon
        rdp_logons = [e for e in events if e.get("EventID") == 21]
        if rdp_logons:
            logon_list = []
            for e in rdp_logons:
                logon_list.append({
                    "time": e.get("TimeCreated"), "user": e.get("User", ""),
                    "source": e.get("Address", "") or e.get("Source", ""),
                    "session_id": e.get("SessionID", ""),
                })
            findings.append(Finding(
                self.MODULE, "RDP SESSION LOGONS (EVTX)",
                f"Found {len(rdp_logons)} RDP session logon events (EventID 21)",
                severity=3, mitre_id="T1021",
                evidence={"rdp_logons": logon_list[:30]},
            ))

        # EventID 25: RDP reconnection
        rdp_reconnects = [e for e in events if e.get("EventID") == 25]
        if rdp_reconnects:
            recon_list = []
            for e in rdp_reconnects:
                recon_list.append({
                    "time": e.get("TimeCreated"), "user": e.get("User", ""),
                    "source": e.get("Address", "") or e.get("Source", ""),
                    "session_id": e.get("SessionID", ""),
                })
            findings.append(Finding(
                self.MODULE, "RDP SESSION RECONNECTIONS (EVTX)",
                f"Found {len(rdp_reconnects)} RDP reconnection events (EventID 25)",
                severity=3, mitre_id="T1021",
                evidence={"rdp_reconnections": recon_list[:30]},
            ))

        return findings

    def run_all(self) -> List[Finding]:
        """Parse all EVTX files and route to appropriate analyzers."""
        if not HAS_EVTX:
            self.logger.error("[EVTX] python-evtx is not installed. Install with: pip install python-evtx")
            self.findings.append(Finding(
                self.MODULE, "EVTX PARSER NOT AVAILABLE",
                "python-evtx library is not installed — cannot parse .evtx files. "
                "Install with: pip install python-evtx",
                severity=1,
            ))
            return self.findings

        self.logger.info(f"[EVTX] Analyzing {len(self.evtx_files)} .evtx file(s)...")

        for evtx_path in self.evtx_files:
            self.logger.info(f"[EVTX] Parsing: {evtx_path}")
            events = self._parse_evtx_file(evtx_path)
            if not events:
                self.logger.warning(f"[EVTX] No events parsed from {evtx_path}")
                continue

            self.logger.info(f"[EVTX]   -> {len(events)} events parsed")
            log_type = self._classify_log(evtx_path, events)
            self.logger.info(f"[EVTX]   -> Classified as: {log_type}")

            if log_type == "security":
                self.findings.extend(self.analyze_security_log(events))
            elif log_type == "system":
                self.findings.extend(self.analyze_system_log(events))
            elif log_type == "powershell":
                self.findings.extend(self.analyze_powershell_log(events))
            elif log_type == "sysmon":
                self.findings.extend(self.analyze_sysmon_log(events))
            elif log_type == "rdp":
                self.findings.extend(self.analyze_rdp_log(events))
            else:
                # Try all analyzers for unknown logs
                self.logger.info(f"[EVTX]   -> Unknown log type, running all analyzers")
                self.findings.extend(self.analyze_security_log(events))
                self.findings.extend(self.analyze_system_log(events))
                self.findings.extend(self.analyze_powershell_log(events))
                self.findings.extend(self.analyze_sysmon_log(events))
                self.findings.extend(self.analyze_rdp_log(events))

        self.logger.info(f"[EVTX] Analysis complete: {len(self.findings)} findings from EVTX files")
        return self.findings


# ============================================================================
# NOVA CONFIDENCE SCORER
# ============================================================================

class NovaConfidenceScorer:
    """Cross-correlate ALL findings to produce a definitive Nova attribution score."""

    MODULE = "NOVA_ATTRIBUTION"

    WEIGHTS = {
        "hash_match": 40,
        "encryption_extension": 15,
        "ransom_note_content": 15,
        "c2_connection": 20,
        "tool_signature": 5,
        "shadow_deletion": 5,
        "defender_disabled": 5,
        "rust_payload": 10,
        "exfil_rclone_mega": 5,
        "lateral_rdp_psexec": 5,
        "evtx_nova_commands": 10,
        "rootkit_detected": 15,
        "web_shell_detected": 10,
        "certificate_tampering": 5,
        "persistence_advanced": 5,
    }
    # Max possible: 170
    # Thresholds:
    #   >= 70: CONFIRMED Nova
    #   50-69: HIGHLY LIKELY Nova
    #   25-49: POSSIBLE Nova (needs investigation)
    #   < 25:  INSUFFICIENT EVIDENCE

    TITLE_PATTERNS = {
        "hash_match": [
            re.compile(r"KNOWN NOVA MALWARE", re.I),
            re.compile(r"NOVA.*HASH MATCH", re.I),
        ],
        "encryption_extension": [
            re.compile(r"ENCRYPTED FILES DETECTED", re.I),
            re.compile(r"NOVA ENCRYPTED FILES", re.I),
        ],
        "ransom_note_content": [
            re.compile(r"RANSOM NOTE.*CONFIRMED NOVA", re.I),
            re.compile(r"RANSOM NOTE", re.I),
        ],
        "c2_connection": [
            re.compile(r"NOVA C2", re.I),
            re.compile(r"C2 IP", re.I),
        ],
        "tool_signature": [
            re.compile(r"SUSPICIOUS.*TOOLS", re.I),
            re.compile(r"NOVA TOOL EXECUTION", re.I),
        ],
        "shadow_deletion": [
            re.compile(r"SHADOW COP", re.I),
            re.compile(r"BACKUP DESTRUCTION", re.I),
            re.compile(r"INHIBIT.*RECOVERY", re.I),
        ],
        "defender_disabled": [
            re.compile(r"DEFENDER TAMPERED", re.I),
            re.compile(r"TAMPER PROTECTION DISABLED", re.I),
            re.compile(r"SECURITY SERVICE STOPPED", re.I),
            re.compile(r"GATEKEEPER DISABLED", re.I),
            re.compile(r"SIP DISABLED", re.I),
        ],
        "exfil_rclone_mega": [
            re.compile(r"RCLONE", re.I),
            re.compile(r"EXFILTRATION TOOL", re.I),
        ],
        "lateral_rdp_psexec": [
            re.compile(r"PSEXEC", re.I),
            re.compile(r"RDP.*LOGON", re.I),
            re.compile(r"RDP.*CONNECTION", re.I),
            re.compile(r"LATERAL", re.I),
        ],
        "evtx_nova_commands": [
            re.compile(r"SUSPICIOUS POWERSHELL", re.I),
            re.compile(r"NOVA.*SYSMON", re.I),
            re.compile(r"EVTX.*NOVA", re.I),
            re.compile(r"NOVA.*EVTX", re.I),
        ],
        "rootkit_detected": [
            re.compile(r"ROOTKIT", re.I),
            re.compile(r"HIDDEN PROCESS", re.I),
            re.compile(r"UNSIGNED.*DRIVER", re.I),
            re.compile(r"KERNEL MODULE DISCREPANC", re.I),
            re.compile(r"TEST SIGNING MODE", re.I),
        ],
        "web_shell_detected": [
            re.compile(r"WEB SHELL", re.I),
        ],
        "certificate_tampering": [
            re.compile(r"SUSPICIOUS ROOT CERT", re.I),
            re.compile(r"RECENTLY MODIFIED CA", re.I),
            re.compile(r"NON-APPLE ROOT CERT", re.I),
        ],
        "persistence_advanced": [
            re.compile(r"IFEO.*HIJACK", re.I),
            re.compile(r"COM OBJECT HIJACK", re.I),
            re.compile(r"APPINIT_DLLS", re.I),
            re.compile(r"ACCESSIBILITY.*BACKDOOR", re.I),
            re.compile(r"LD_PRELOAD", re.I),
            re.compile(r"PRINT MONITOR", re.I),
            re.compile(r"LSA PACKAGE", re.I),
        ],
    }

    def __init__(self):
        self.result: Optional[Dict] = None

    def score(self, findings: List[Finding]) -> Dict:
        """Iterate findings, match to weight categories, compute attribution score."""
        matched_categories: Dict[str, List[str]] = defaultdict(list)

        for f in findings:
            title = f.title
            desc = f.description
            combined = f"{title} {desc}"

            for category, patterns in self.TITLE_PATTERNS.items():
                for pat in patterns:
                    if pat.search(combined):
                        matched_categories[category].append(title)
                        break

            # Special: check for Rust-based payload indicators
            evidence = f.evidence if isinstance(f.evidence, dict) else {}
            for mf in evidence.get("matched_files", []):
                if isinstance(mf, dict):
                    path = mf.get("path", "").lower()
                    if any(ext in path for ext in [".exe", ""]):
                        # Hash match already covers this, but check for Rust indicators
                        pass

        # Compute score
        score = 0
        max_possible = sum(self.WEIGHTS.values())
        evidence_breakdown = {}

        for category, weight in self.WEIGHTS.items():
            if category in matched_categories:
                score += weight
                evidence_breakdown[category] = {
                    "weight": weight,
                    "matched": True,
                    "evidence_count": len(matched_categories[category]),
                    "samples": matched_categories[category][:3],
                }
            else:
                evidence_breakdown[category] = {
                    "weight": weight,
                    "matched": False,
                    "evidence_count": 0,
                    "samples": [],
                }

        # Determine confidence level
        if score >= 70:
            confidence_level = "CONFIRMED NOVA"
        elif score >= 50:
            confidence_level = "HIGHLY LIKELY NOVA"
        elif score >= 25:
            confidence_level = "POSSIBLE NOVA"
        else:
            confidence_level = "INSUFFICIENT EVIDENCE"

        self.result = {
            "score": score,
            "max_possible": max_possible,
            "percentage": round((score / max_possible) * 100, 1) if max_possible > 0 else 0,
            "confidence_level": confidence_level,
            "categories_matched": len(matched_categories),
            "categories_total": len(self.WEIGHTS),
            "evidence_breakdown": evidence_breakdown,
        }
        return self.result

    def generate_attribution_finding(self) -> Finding:
        """Create a summary Finding with the confidence assessment."""
        if self.result is None:
            return Finding(
                self.MODULE, "NOVA ATTRIBUTION NOT SCORED",
                "Confidence scorer was not run", severity=1,
            )

        r = self.result
        sev = 5 if r["score"] >= 70 else 4 if r["score"] >= 50 else 3 if r["score"] >= 25 else 1
        return Finding(
            self.MODULE,
            f"NOVA ATTRIBUTION: {r['confidence_level']}",
            f"Score: {r['score']}/{r['max_possible']} ({r['percentage']}%) — "
            f"{r['categories_matched']}/{r['categories_total']} evidence categories matched",
            severity=sev,
            evidence=r,
        )


# ============================================================================
# MODULE 7: TIMELINE BUILDER
# ============================================================================

class TimelineBuilder:
    """Build a chronological timeline from all findings."""
    
    MODULE = "TIMELINE"
    
    def __init__(self, findings: List[Finding], logger: logging.Logger):
        self.findings = findings
        self.logger = logger
    
    def build(self) -> List[Dict]:
        """Extract timestamped events from all findings and sort chronologically."""
        self.logger.info("[TIMELINE] Building incident timeline...")
        events = []
        
        for f in self.findings:
            # Primary finding timestamp
            events.append({
                "timestamp": f.timestamp,
                "module": f.module,
                "title": f.title,
                "severity": f.severity,
                "severity_label": severity_label(f.severity),
                "mitre_id": f.mitre_id,
                "description": f.description,
            })
            
            # Extract timestamps from evidence
            evidence = f.evidence
            if isinstance(evidence, dict):
                # Encrypted files
                for ef in evidence.get("encrypted_files", []):
                    if isinstance(ef, dict) and ef.get("modified"):
                        events.append({
                            "timestamp": ef["modified"],
                            "module": f.module,
                            "title": f"File encrypted: {ef.get('path', 'unknown')}",
                            "severity": 5,
                            "severity_label": "CRITICAL",
                            "mitre_id": "T1486",
                            "description": f"File encrypted ({ef.get('size_bytes', '?')} bytes)",
                        })
                
                # Tools found on disk
                for tool in evidence.get("tools", []):
                    if isinstance(tool, dict) and tool.get("modified"):
                        events.append({
                            "timestamp": tool["modified"],
                            "module": f.module,
                            "title": f"Tool dropped: {tool.get('tool_name', tool.get('path', 'unknown'))}",
                            "severity": 4,
                            "severity_label": "HIGH",
                            "mitre_id": "T1570",
                            "description": f"Suspicious tool found at {tool.get('path', 'unknown')}",
                        })
        
        # Sort by timestamp
        events.sort(key=lambda x: x.get("timestamp", ""))
        
        return events


# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generate human-readable and machine-readable reports."""

    def __init__(self, findings: List[Finding], timeline: List[Dict],
                 output_dir: str, logger: logging.Logger,
                 os_info: Optional[Dict[str, str]] = None):
        self.findings = findings
        self.timeline = timeline
        self.output_dir = output_dir
        self.logger = logger
        self.os_info = os_info or get_os_info()
    
    def generate_all(self):
        self.generate_json()
        self.generate_csv()
        self.generate_txt()
    
    def generate_json(self):
        path = os.path.join(self.output_dir, "nova_ir_findings.json")
        data = {
            "metadata": {
                "tool": "Nova/RALord IR Toolkit",
                "version": "2.1",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "hostname": self.os_info.get("hostname", socket.gethostname()),
                "os_type": self.os_info.get("os_type", ""),
                "os_distribution": self.os_info.get("distribution", ""),
                "os_version": self.os_info.get("version", ""),
                "os_architecture": self.os_info.get("architecture", ""),
                "os_kernel": self.os_info.get("kernel", ""),
                "os_platform": self.os_info.get("platform", platform.platform()),
                "operational_mode": self.os_info.get("operational_mode", "LIVE"),
                "threat_group": "Nova RaaS (formerly RALord)",
            },
            "executive_summary": self._exec_summary(),
            "findings": [f.to_dict() for f in self.findings],
            "timeline": self.timeline,
            "mitre_mapping": MITRE_MAPPING,
            "known_iocs": {
                "sha256": NOVA_IOCS["sha256_hashes"],
                "md5": NOVA_IOCS["md5_hashes"],
                "file_extension": NOVA_IOCS["file_extensions"],
                "tox_ids": NOVA_IOCS["tox_ids"],
                "onion_domains": NOVA_IOCS["onion_domains"],
            },
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        self.logger.info(f"[REPORT] JSON report saved: {path}")
    
    def generate_csv(self):
        path = os.path.join(self.output_dir, "nova_ir_findings.csv")
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Module", "Severity", "MITRE_ID", "Title", "Description"])
            for finding in self.findings:
                writer.writerow([
                    finding.timestamp, finding.module,
                    severity_label(finding.severity),
                    finding.mitre_id, finding.title, finding.description,
                ])
        self.logger.info(f"[REPORT] CSV report saved: {path}")
    
    def generate_txt(self):
        path = os.path.join(self.output_dir, "nova_ir_report.txt")
        with open(path, "w") as f:
            op_mode = self.os_info.get("operational_mode", "LIVE")
            f.write("=" * 80 + "\n")
            f.write(" NOVA (RALord) RANSOMWARE - INCIDENT RESPONSE REPORT\n")
            f.write(f" Generated: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f" Host:      {self.os_info.get('hostname', socket.gethostname())}\n")
            f.write(f" OS:        {self.os_info.get('distribution', platform.platform())}\n")
            f.write(f" Arch:      {self.os_info.get('architecture', '')}\n")
            if self.os_info.get("kernel"):
                f.write(f" Kernel:    {self.os_info['kernel']}\n")
            f.write(f" Mode:      {op_mode} ANALYSIS\n")
            f.write("=" * 80 + "\n")
            if op_mode == "OFFLINE":
                f.write(" NOTE: This report is based on offline EVTX analysis only.\n")
                f.write("       No live system checks were performed.\n")
            f.write("\n")
            
            summary = self._exec_summary()
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"  Impact Assessment:   {summary['impact_level']}\n")
            f.write(f"  Total Findings:      {summary['total_findings']}\n")
            f.write(f"  Critical Findings:   {summary['critical_count']}\n")
            f.write(f"  High Findings:       {summary['high_count']}\n")
            f.write(f"  Encryption Detected: {summary['encryption_detected']}\n")
            f.write(f"  Active Threat:       {summary['active_threat']}\n")
            f.write(f"  Data Exfiltration:   {summary['exfiltration_indicators']}\n\n")
            
            f.write("FINDINGS BY MODULE\n")
            f.write("=" * 80 + "\n\n")
            
            # Group by module
            by_module = defaultdict(list)
            for finding in self.findings:
                by_module[finding.module].append(finding)
            
            for module, findings in sorted(by_module.items()):
                f.write(f"\n--- {module} ---\n\n")
                for finding in sorted(findings, key=lambda x: -x.severity):
                    f.write(f"  [{severity_label(finding.severity)}] {finding.title}\n")
                    f.write(f"    {finding.description}\n")
                    if finding.mitre_id:
                        f.write(f"    MITRE: {finding.mitre_id} - {finding.mitre_name}\n")
                    f.write(f"    Time:  {finding.timestamp}\n\n")
            
            # Timeline
            f.write("\n" + "=" * 80 + "\n")
            f.write("INCIDENT TIMELINE\n")
            f.write("=" * 80 + "\n\n")
            for event in self.timeline:
                f.write(f"  {event['timestamp']}  [{event['severity_label']}] {event['title']}\n")
                if event.get('mitre_id'):
                    f.write(f"    MITRE: {event['mitre_id']}\n")
                f.write(f"    {event['description']}\n\n")
            
            # Recommendations
            f.write("\n" + "=" * 80 + "\n")
            f.write("IMMEDIATE RESPONSE ACTIONS\n")
            f.write("=" * 80 + "\n\n")
            f.write("  1. ISOLATE affected systems from the network immediately\n")
            f.write("  2. PRESERVE forensic evidence (memory dumps, disk images)\n")
            f.write("  3. IDENTIFY the initial access vector (VPN, RDP, phishing)\n")
            f.write("  4. ENUMERATE all compromised accounts and reset credentials\n")
            f.write("  5. CHECK backup integrity - Nova targets backup systems\n")
            f.write("  6. SCAN the entire network for lateral movement\n")
            f.write("  7. BLOCK Nova C2 infrastructure at firewall/proxy\n")
            f.write("  8. ENGAGE your IR retainer / law enforcement (FBI IC3)\n")
            f.write("  9. DO NOT contact attackers via Tox without legal counsel\n")
            f.write(" 10. DOCUMENT everything for potential legal proceedings\n\n")
            
            # Nova-specific intel
            f.write("=" * 80 + "\n")
            f.write("NOVA/RALORD THREAT INTELLIGENCE\n")
            f.write("=" * 80 + "\n\n")
            f.write("  Group:        Nova RaaS (formerly RALord, rebranded April 2025)\n")
            f.write("  Payload:      Rust-based ransomware (RC4 PRGA encryption)\n")
            f.write("  Extensions:   .ralord, .nova, .LORD, .RNOVA\n")
            f.write("  Model:        RaaS (85/15 affiliate split)\n")
            f.write("  Double Extort: Yes (encrypt + data leak threat)\n")
            f.write("  Communication: qTox, Session Messenger, Jabber, Nova Chat\n")
            f.write(f"  Known Tox IDs: {len(NOVA_IOCS['tox_ids'])} tracked\n")
            f.write(f"  Onion Domains: {len(NOVA_IOCS['onion_domains'])} tracked (leak sites + negotiation)\n")
            f.write(f"  C2 IPs:       {', '.join(NOVA_IOCS.get('c2_ips', []))}\n")
            f.write("  Initial Access: Exposed RDP/VPN, phishing, compromised creds\n")
            f.write("  Key TTPs:     Backup deletion, AV disabling, rclone exfil,\n")
            f.write("                LOLBins, lateral via PsExec/RDP/SMB\n")
            f.write("  WARNING:      Nova has been known to DOUBLE ransom demands\n")
            f.write("                after initial payment. Engage legal counsel.\n\n")
        
        self.logger.info(f"[REPORT] Text report saved: {path}")
    
    def _exec_summary(self) -> Dict:
        critical = sum(1 for f in self.findings if f.severity == 5)
        high = sum(1 for f in self.findings if f.severity == 4)
        encryption = any("ENCRYPT" in f.title.upper() for f in self.findings)
        active = any(f.module == "LIVE_TRIAGE" and f.severity >= 4 for f in self.findings)
        exfil = any(f.module == "EXFILTRATION" and f.severity >= 4 for f in self.findings)
        
        if critical >= 3:
            impact = "SEVERE - Active ransomware incident confirmed"
        elif critical >= 1:
            impact = "HIGH - Strong indicators of compromise"
        elif high >= 2:
            impact = "MODERATE - Investigation required"
        else:
            impact = "LOW - No critical indicators found"
        
        return {
            "impact_level": impact,
            "total_findings": len(self.findings),
            "critical_count": critical,
            "high_count": high,
            "encryption_detected": encryption,
            "active_threat": active,
            "exfiltration_indicators": exfil,
        }


# ============================================================================
# MITRE ATT&CK REPORT GENERATOR
# ============================================================================

MITRE_TACTICS = {
    "TA0001": {"name": "Initial Access", "techniques": ["T1078", "T1133", "T1566", "T1204"]},
    "TA0002": {"name": "Execution", "techniques": ["T1059", "T1106"]},
    "TA0003": {"name": "Persistence", "techniques": ["T1053", "T1543", "T1546", "T1547", "T1574", "T1197", "T1505.003", "T1546.008", "T1546.012", "T1546.015", "T1547.002", "T1547.010", "T1574.001"]},
    "TA0004": {"name": "Privilege Escalation", "techniques": ["T1068", "T1055"]},
    "TA0005": {"name": "Defense Evasion", "techniques": ["T1027", "T1070", "T1112", "T1497", "T1562", "T1014", "T1553", "T1564"]},
    "TA0006": {"name": "Credential Access", "techniques": ["T1003", "T1110", "T1550"]},
    "TA0007": {"name": "Discovery", "techniques": ["T1012", "T1018", "T1082", "T1083"]},
    "TA0008": {"name": "Lateral Movement", "techniques": ["T1021", "T1570"]},
    "TA0009": {"name": "Collection", "techniques": ["T1005", "T1074"]},
    "TA0010": {"name": "Exfiltration", "techniques": ["T1048"]},
    "TA0011": {"name": "Command and Control", "techniques": ["T1071"]},
    "TA0040": {"name": "Impact", "techniques": ["T1486", "T1490", "T1491"]},
}

# Technique name lookup
TECHNIQUE_NAMES = {
    "T1078": "Valid Accounts", "T1133": "External Remote Services",
    "T1566": "Phishing", "T1204": "User Execution",
    "T1059": "Command and Scripting Interpreter", "T1106": "Native API",
    "T1053": "Scheduled Task/Job", "T1543": "Create or Modify System Process",
    "T1546": "Event Triggered Execution", "T1547": "Boot or Logon Autostart Execution",
    "T1574": "Hijack Execution Flow", "T1197": "BITS Jobs",
    "T1068": "Exploitation for Privilege Escalation", "T1055": "Process Injection",
    "T1027": "Obfuscated Files or Information", "T1070": "Indicator Removal",
    "T1112": "Modify Registry", "T1497": "Virtualization/Sandbox Evasion",
    "T1562": "Impair Defenses",
    "T1003": "OS Credential Dumping", "T1110": "Brute Force",
    "T1550": "Use Alternate Authentication Material",
    "T1012": "Query Registry", "T1018": "Remote System Discovery",
    "T1082": "System Information Discovery", "T1083": "File and Directory Discovery",
    "T1021": "Remote Services", "T1570": "Lateral Tool Transfer",
    "T1005": "Data from Local System", "T1074": "Data Staged",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1071": "Application Layer Protocol",
    "T1486": "Data Encrypted for Impact", "T1490": "Inhibit System Recovery",
    "T1491": "Defacement",
    "T1098": "Account Manipulation", "T1136": "Create Account",
    "T1014": "Rootkit", "T1505.003": "Web Shell",
    "T1553": "Subvert Trust Controls", "T1564": "Hide Artifacts",
    "T1546.008": "Accessibility Features", "T1546.012": "Image File Execution Options Injection",
    "T1546.015": "Component Object Model Hijacking", "T1547.010": "Port Monitors",
    "T1547.002": "Authentication Package", "T1574.001": "DLL Search Order Hijacking",
}


class MITREReportGenerator:
    """Generate a dedicated MITRE ATT&CK mapped report."""

    def __init__(self, findings: List[Finding], confidence_result: Optional[Dict],
                 output_dir: str, logger: logging.Logger,
                 os_info: Optional[Dict[str, str]] = None):
        self.findings = findings
        self.confidence_result = confidence_result or {}
        self.output_dir = output_dir
        self.logger = logger
        self.os_info = os_info or get_os_info()

        # Build technique → findings map
        self.technique_findings: Dict[str, List[Finding]] = defaultdict(list)
        for f in self.findings:
            if f.mitre_id:
                self.technique_findings[f.mitre_id].append(f)

    def generate(self):
        self._generate_mitre_json()
        self._generate_mitre_txt()

    def _build_tactic_data(self) -> List[Dict]:
        """Build structured tactic/technique data for reports."""
        tactics_data = []
        for tactic_id, tactic_info in MITRE_TACTICS.items():
            techniques = []
            for tech_id in tactic_info["techniques"]:
                findings_for_tech = self.technique_findings.get(tech_id, [])
                if findings_for_tech:
                    status = "CONFIRMED"
                    max_sev = max(f.severity for f in findings_for_tech)
                else:
                    status = "NOT OBSERVED"
                    max_sev = 0

                techniques.append({
                    "id": tech_id,
                    "name": TECHNIQUE_NAMES.get(tech_id, MITRE_MAPPING.get(tech_id, "Unknown")),
                    "status": status,
                    "evidence_count": len(findings_for_tech),
                    "max_severity": max_sev,
                    "findings": [f.to_dict() for f in findings_for_tech],
                })

            observed = sum(1 for t in techniques if t["status"] == "CONFIRMED")
            tactics_data.append({
                "tactic_id": tactic_id,
                "name": tactic_info["name"],
                "techniques": techniques,
                "techniques_observed": observed,
                "techniques_total": len(techniques),
            })
        return tactics_data

    def _generate_mitre_json(self):
        """Generate machine-readable MITRE ATT&CK report."""
        path = os.path.join(self.output_dir, "nova_mitre_report.json")
        tactics_data = self._build_tactic_data()

        total_techniques = sum(t["techniques_total"] for t in tactics_data)
        observed_techniques = sum(t["techniques_observed"] for t in tactics_data)

        data = {
            "metadata": {
                "tool": "Nova/RALord IR Toolkit - MITRE ATT&CK Report",
                "version": "2.1",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "hostname": self.os_info.get("hostname", socket.gethostname()),
                "os_type": self.os_info.get("os_type", ""),
                "os_distribution": self.os_info.get("distribution", ""),
                "os_architecture": self.os_info.get("architecture", ""),
                "os_platform": self.os_info.get("platform", platform.platform()),
                "operational_mode": self.os_info.get("operational_mode", "LIVE"),
            },
            "attribution": self.confidence_result,
            "coverage_summary": {
                "total_techniques_mapped": total_techniques,
                "techniques_observed": observed_techniques,
                "techniques_not_observed": total_techniques - observed_techniques,
                "coverage_percentage": round((observed_techniques / total_techniques) * 100, 1) if total_techniques > 0 else 0,
            },
            "tactics": tactics_data,
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        self.logger.info(f"[MITRE] JSON MITRE report saved: {path}")

    def _generate_mitre_txt(self):
        """Generate human-readable MITRE ATT&CK report."""
        path = os.path.join(self.output_dir, "nova_mitre_report.txt")
        tactics_data = self._build_tactic_data()

        total_techniques = sum(t["techniques_total"] for t in tactics_data)
        observed_techniques = sum(t["techniques_observed"] for t in tactics_data)

        with open(path, "w") as f:
            mitre_op_mode = self.os_info.get("operational_mode", "LIVE")
            f.write("=" * 80 + "\n")
            f.write(" NOVA/RALord RANSOMWARE - MITRE ATT&CK ANALYSIS REPORT\n")
            f.write(f" Generated: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f" Host:      {self.os_info.get('hostname', socket.gethostname())}\n")
            f.write(f" OS:        {self.os_info.get('distribution', platform.platform())}\n")
            f.write(f" Arch:      {self.os_info.get('architecture', '')}\n")
            if self.os_info.get("kernel"):
                f.write(f" Kernel:    {self.os_info['kernel']}\n")
            f.write(f" Mode:      {mitre_op_mode} ANALYSIS\n")
            f.write("=" * 80 + "\n")
            if mitre_op_mode == "OFFLINE":
                f.write(" NOTE: This report is based on offline EVTX analysis only.\n")
            f.write("\n")

            # Section 1: Nova Attribution Assessment
            f.write("=" * 80 + "\n")
            f.write(" 1. NOVA ATTRIBUTION ASSESSMENT\n")
            f.write("=" * 80 + "\n\n")

            cr = self.confidence_result
            if cr:
                f.write(f"  Confidence Level:  {cr.get('confidence_level', 'N/A')}\n")
                f.write(f"  Attribution Score: {cr.get('score', 0)}/{cr.get('max_possible', 0)} "
                        f"({cr.get('percentage', 0)}%)\n")
                f.write(f"  Categories Matched: {cr.get('categories_matched', 0)}/{cr.get('categories_total', 0)}\n\n")

                f.write("  Evidence Breakdown:\n")
                f.write("  " + "-" * 60 + "\n")
                for cat, info in cr.get("evidence_breakdown", {}).items():
                    status = "[+]" if info.get("matched") else "[ ]"
                    f.write(f"    {status} {cat:<30} (weight: {info.get('weight', 0):>3})")
                    if info.get("matched"):
                        f.write(f"  [{info.get('evidence_count', 0)} evidence item(s)]")
                    f.write("\n")
                f.write("\n")
            else:
                f.write("  Attribution scoring was not performed.\n\n")

            # Section 2: Attack Chain Narrative
            f.write("=" * 80 + "\n")
            f.write(" 2. ATTACK CHAIN NARRATIVE\n")
            f.write("=" * 80 + "\n\n")

            narrative_tactics = [
                ("TA0001", "INITIAL ACCESS", "The attacker gained entry to the environment"),
                ("TA0002", "EXECUTION", "Malicious code was executed on compromised systems"),
                ("TA0003", "PERSISTENCE", "Mechanisms were established to maintain access"),
                ("TA0004", "PRIVILEGE ESCALATION", "Higher privileges were obtained"),
                ("TA0005", "DEFENSE EVASION", "Security controls were disabled or bypassed"),
                ("TA0006", "CREDENTIAL ACCESS", "Credentials were harvested for lateral movement"),
                ("TA0007", "DISCOVERY", "The environment was enumerated and mapped"),
                ("TA0008", "LATERAL MOVEMENT", "The attacker spread across the network"),
                ("TA0009", "COLLECTION", "Data was gathered for exfiltration"),
                ("TA0010", "EXFILTRATION", "Stolen data was sent to attacker infrastructure"),
                ("TA0011", "COMMAND AND CONTROL", "C2 channels were established"),
                ("TA0040", "IMPACT", "Ransomware was deployed and data encrypted"),
            ]

            for tactic_id, label, description in narrative_tactics:
                tactic_data = next((t for t in tactics_data if t["tactic_id"] == tactic_id), None)
                if tactic_data and tactic_data["techniques_observed"] > 0:
                    observed = [t for t in tactic_data["techniques"] if t["status"] == "CONFIRMED"]
                    tech_names = ", ".join(f'{t["id"]}' for t in observed)
                    f.write(f"  >> {label}: {description}\n")
                    f.write(f"     Observed techniques: {tech_names}\n")
                    # Show top evidence
                    for tech in observed:
                        for finding in tech["findings"][:1]:
                            f.write(f"     - {finding.get('title', '')}\n")
                    f.write("\n")

            # Section 3: MITRE ATT&CK Matrix
            f.write("=" * 80 + "\n")
            f.write(" 3. MITRE ATT&CK TECHNIQUE MATRIX\n")
            f.write("=" * 80 + "\n\n")

            for tactic in tactics_data:
                f.write(f"  {tactic['tactic_id']} - {tactic['name']} "
                        f"({tactic['techniques_observed']}/{tactic['techniques_total']} observed)\n")
                f.write("  " + "-" * 70 + "\n")

                for tech in tactic["techniques"]:
                    status_tag = "CONFIRMED" if tech["status"] == "CONFIRMED" else "NOT OBSERVED"
                    f.write(f"    [{status_tag:^14}] {tech['id']} - {tech['name']}")
                    if tech["evidence_count"] > 0:
                        f.write(f" ({tech['evidence_count']} finding(s))")
                    f.write("\n")

                    if tech["status"] == "CONFIRMED":
                        for finding in tech["findings"][:3]:
                            desc = finding.get("description", "")
                            if len(desc) > 80:
                                desc = desc[:77] + "..."
                            f.write(f"      - Evidence: {desc}\n")

                f.write("\n")

            # Section 4: Coverage Summary
            f.write("=" * 80 + "\n")
            f.write(" 4. TECHNIQUE COVERAGE SUMMARY\n")
            f.write("=" * 80 + "\n\n")

            coverage_pct = round((observed_techniques / total_techniques) * 100, 1) if total_techniques > 0 else 0
            f.write(f"  Total Techniques Mapped:    {total_techniques}\n")
            f.write(f"  Techniques Observed:        {observed_techniques}\n")
            f.write(f"  Techniques Not Observed:    {total_techniques - observed_techniques}\n")
            f.write(f"  Coverage:                   {coverage_pct}%\n\n")

            f.write("  Per-Tactic Summary:\n")
            f.write(f"  {'Tactic':<8} {'Name':<28} {'Observed':>10} {'Total':>8} {'Coverage':>10}\n")
            f.write("  " + "-" * 66 + "\n")
            for tactic in tactics_data:
                pct = round((tactic["techniques_observed"] / tactic["techniques_total"]) * 100) if tactic["techniques_total"] > 0 else 0
                f.write(f"  {tactic['tactic_id']:<8} {tactic['name']:<28} "
                        f"{tactic['techniques_observed']:>10} {tactic['techniques_total']:>8} "
                        f"{pct:>9}%\n")
            f.write("\n")

            # Section 5: Recommendations Per Tactic
            f.write("=" * 80 + "\n")
            f.write(" 5. RECOMMENDATIONS PER TACTIC\n")
            f.write("=" * 80 + "\n\n")

            recommendations = {
                "TA0001": [
                    "Enforce MFA on all remote access (VPN, RDP, Citrix, cloud portals)",
                    "Audit and restrict exposed services with network segmentation",
                    "Monitor for credential stuffing and brute force attempts",
                ],
                "TA0002": [
                    "Enable PowerShell Constrained Language Mode",
                    "Deploy application whitelisting (AppLocker/WDAC)",
                    "Enable command-line and script block logging",
                ],
                "TA0003": [
                    "Audit scheduled tasks, services, and registry run keys regularly",
                    "Monitor WMI event subscriptions and BITS jobs",
                    "Implement change detection on critical system configs",
                ],
                "TA0004": [
                    "Patch systems promptly, especially known privilege escalation CVEs",
                    "Use Credential Guard to protect LSASS",
                    "Restrict local admin rights using LAPS",
                ],
                "TA0005": [
                    "Enable tamper protection on all EDR/AV agents",
                    "Centralize log collection to prevent local log clearing",
                    "Monitor for Defender exclusion changes and service stops",
                ],
                "TA0006": [
                    "Enable Credential Guard and disable WDigest",
                    "Monitor for LSASS access and credential dumping tools",
                    "Implement tiered administration to limit credential exposure",
                ],
                "TA0007": [
                    "Detect and alert on network scanning tools",
                    "Limit unnecessary admin tool availability",
                    "Segment networks to limit discovery scope",
                ],
                "TA0008": [
                    "Restrict RDP access with jump servers and MFA",
                    "Disable PsExec where not needed, monitor for PSEXESVC",
                    "Enable Windows Firewall rules to restrict SMB laterally",
                ],
                "TA0009": [
                    "Monitor for bulk file access and archive creation",
                    "Detect large staging operations in temp directories",
                ],
                "TA0010": [
                    "Block rclone and unauthorized cloud sync tools at proxy/firewall",
                    "Monitor for large outbound transfers to cloud storage",
                    "Implement DLP policies for sensitive data",
                ],
                "TA0011": [
                    "Block known C2 IPs and domains at perimeter",
                    "Monitor DNS for Tor/onion and suspicious domain queries",
                    "Deploy SSL/TLS inspection for outbound encrypted traffic",
                ],
                "TA0040": [
                    "Maintain offline, immutable backups tested regularly",
                    "Enable Volume Shadow Copy protection and monitor deletions",
                    "Have a tested IR playbook ready for ransomware incidents",
                ],
            }

            for tactic in tactics_data:
                tid = tactic["tactic_id"]
                f.write(f"  {tid} - {tactic['name']}\n")
                if tactic["techniques_observed"] > 0:
                    f.write(f"    STATUS: ACTIVITY DETECTED ({tactic['techniques_observed']} technique(s))\n")
                else:
                    f.write(f"    STATUS: No activity observed\n")

                for rec in recommendations.get(tid, []):
                    f.write(f"    -> {rec}\n")
                f.write("\n")

        self.logger.info(f"[MITRE] Text MITRE report saved: {path}")


# ============================================================================
# MAIN ORCHESTRATOR
# ============================================================================

def main():
    banner = r"""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║       NOVA / RALord RANSOMWARE - IR & THREAT HUNTING TOOLKIT v2.1  ║
    ║                                                                    ║
    ║  Modules: IOC Scanner | Persistence | Lateral Movement             ║
    ║           Exfiltration | Defense Evasion | Credential Artifacts     ║
    ║           Live Triage | EVTX Analyzer | Rootkit Detector            ║
    ║           Web Shell Detector | Certificate Auditor                  ║
    ║           Nova Confidence Scorer | MITRE ATT&CK Report             ║
    ║                                                                    ║
    ║  Modes:  LIVE  = Full system analysis (all modules)                ║
    ║          OFFLINE = EVTX-only analysis (no live system checks)      ║
    ║                                                                    ║
    ║  ⚠  RUN AS ADMINISTRATOR / ROOT FOR FULL VISIBILITY  ⚠            ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

    parser = argparse.ArgumentParser(description="Nova/RALord Ransomware IR Toolkit")
    parser.add_argument("--output-dir", "-o", default=None,
                        help="Output directory for reports")
    parser.add_argument("--modules", "-m", default=None,
                        help="Comma-separated modules: ioc,persistence,lateral,exfil,evasion,creds,triage,evtx,rootkit,webshell,certs (or 'all')")
    parser.add_argument("--quick", "-q", action="store_true",
                        help="Quick triage mode (IOC + Triage only)")
    parser.add_argument("--evtx", nargs="+", default=None,
                        help="Path(s) to .evtx file(s) or directory containing .evtx files for offline analysis")
    parser.add_argument("--offline", action="store_true",
                        help="Explicit offline mode: only analyze provided EVTX files, no live system checks")
    args = parser.parse_args()

    # ---- Determine operational mode ----
    # OFFLINE: --evtx provided without --modules (or with --offline flag)
    # LIVE: --modules specified, or no --evtx at all
    if args.offline:
        operational_mode = "OFFLINE"
    elif args.evtx and args.modules is None and not args.quick:
        # --evtx alone without --modules = auto OFFLINE
        operational_mode = "OFFLINE"
    else:
        operational_mode = "LIVE"

    # Setup output directory
    if args.output_dir:
        output_dir = args.output_dir
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        mode_tag = "offline" if operational_mode == "OFFLINE" else "live"
        output_dir = os.path.join(os.path.expanduser("~"), f"nova_ir_{mode_tag}_{ts}")

    os.makedirs(output_dir, exist_ok=True)
    logger = setup_logging(output_dir)

    # Initialize shared system data cache to avoid duplicate expensive commands
    global _system_cache
    _system_cache = SystemDataCache()

    # ---- OS Detection ----
    os_info = get_os_info()
    os_type = os_info["os_type"]
    os_info["operational_mode"] = operational_mode

    # ---- Mode Banner ----
    if operational_mode == "OFFLINE":
        print("  " + "=" * 60)
        print("  RUNNING IN OFFLINE EVTX ANALYSIS MODE")
        print("  Only EVTX event log analysis will be performed.")
        print("  No live system checks will run.")
        print("  " + "=" * 60)
    else:
        print("  " + "=" * 60)
        print("  RUNNING IN LIVE SYSTEM ANALYSIS MODE")
        print("  Full system forensic analysis will be performed.")
        if args.evtx:
            print("  EVTX offline analysis is also included.")
        print("  " + "=" * 60)
    print()

    print(f"  [*] Detected OS:     {os_info['distribution']}")
    print(f"  [*] Architecture:    {os_info['architecture']}")
    print(f"  [*] Hostname:        {os_info['hostname']}")
    if os_info["kernel"]:
        print(f"  [*] Kernel:          {os_info['kernel']}")
    if os_info["version"]:
        print(f"  [*] Version:         {os_info['version']}")
    print(f"  [*] Mode:            {operational_mode}")
    print()

    logger.info(f"Nova IR Toolkit started on {os_info['hostname']}")
    logger.info(f"Operational mode: {operational_mode}")
    logger.info(f"Detected OS: {os_info['distribution']} ({os_info['architecture']})")
    logger.info(f"Platform: {os_info['platform']}")
    if os_info["kernel"]:
        logger.info(f"Kernel: {os_info['kernel']}")
    logger.info(f"Output directory: {output_dir}")

    # ---- Determine modules to run ----
    if operational_mode == "OFFLINE":
        modules = {"evtx"}
        if not args.evtx:
            logger.error("OFFLINE mode requires --evtx paths. Use: --offline --evtx /path/to/logs/")
            print("  ERROR: OFFLINE mode requires --evtx paths.")
            print("  Usage: python3 nova_ir_toolkit.py --offline --evtx /path/to/logs/")
            return 1
    elif args.quick:
        modules = {"ioc", "triage"}
    elif args.modules and args.modules.lower() == "all":
        modules = {"ioc", "persistence", "lateral", "exfil", "evasion", "creds",
                    "triage", "rootkit", "webshell", "certs"}
        if args.evtx:
            modules.add("evtx")
    elif args.modules:
        modules = set(args.modules.lower().split(","))
    else:
        # Default: all live modules
        modules = {"ioc", "persistence", "lateral", "exfil", "evasion", "creds",
                    "triage", "rootkit", "webshell", "certs"}

    # Auto-enable evtx module if --evtx paths provided in LIVE mode
    if args.evtx and operational_mode == "LIVE":
        modules.add("evtx")

    # ---- Display module applicability for this OS ----
    os_modules = OS_MODULE_MAP.get(os_type, {})
    logger.info(f"Running on {os_type.upper()} — module coverage for this platform:")
    for mod_name in sorted(modules):
        coverage = os_modules.get(mod_name, "Unknown")
        logger.info(f"  {mod_name:<14} -> {coverage}")

    all_findings: List[Finding] = []

    # ---- Run modules ----
    if "ioc" in modules:
        logger.info("=" * 60)
        logger.info(f"MODULE 1: IOC SCANNER [{os_type.upper()}]")
        logger.info("=" * 60)
        scanner = IOCScanner(logger)
        all_findings.extend(scanner.run_all())

    if "persistence" in modules:
        logger.info("=" * 60)
        logger.info(f"MODULE 2: PERSISTENCE HUNTER [{os_type.upper()}]")
        logger.info("=" * 60)
        persist = PersistenceHunter(logger)
        all_findings.extend(persist.run_all())

    if "lateral" in modules:
        logger.info("=" * 60)
        logger.info(f"MODULE 3: LATERAL MOVEMENT DETECTOR [{os_type.upper()}]")
        logger.info("=" * 60)
        lateral = LateralMovementDetector(logger)
        all_findings.extend(lateral.run_all())

    if "exfil" in modules:
        logger.info("=" * 60)
        logger.info(f"MODULE 4: EXFILTRATION DETECTOR [{os_type.upper()}]")
        logger.info("=" * 60)
        exfil = ExfiltrationDetector(logger)
        all_findings.extend(exfil.run_all())

    if "evasion" in modules:
        logger.info("=" * 60)
        logger.info(f"MODULE 5a: DEFENSE EVASION DETECTOR [{os_type.upper()}]")
        logger.info("=" * 60)
        evasion = DefenseEvasionDetector(logger)
        all_findings.extend(evasion.run_all())

    if "creds" in modules:
        logger.info("=" * 60)
        logger.info(f"MODULE 5b: CREDENTIAL & ARTIFACT HUNTER [{os_type.upper()}]")
        logger.info("=" * 60)
        creds = CredentialArtifactHunter(logger)
        all_findings.extend(creds.run_all())

    if "rootkit" in modules:
        logger.info("=" * 60)
        logger.info(f"MODULE 5c: ROOTKIT DETECTOR [{os_type.upper()}]")
        logger.info("=" * 60)
        rootkit = RootkitDetector(logger)
        all_findings.extend(rootkit.run_all())

    if "webshell" in modules:
        logger.info("=" * 60)
        logger.info(f"MODULE 5d: WEB SHELL DETECTOR [{os_type.upper()}]")
        logger.info("=" * 60)
        webshell = WebShellDetector(logger)
        all_findings.extend(webshell.run_all())

    if "certs" in modules:
        logger.info("=" * 60)
        logger.info(f"MODULE 5e: CERTIFICATE AUDITOR [{os_type.upper()}]")
        logger.info("=" * 60)
        certaudit = CertificateAuditor(logger)
        all_findings.extend(certaudit.run_all())

    if "triage" in modules:
        logger.info("=" * 60)
        logger.info(f"MODULE 6: LIVE TRIAGE [{os_type.upper()}]")
        logger.info("=" * 60)
        triage = LiveTriage(logger)
        all_findings.extend(triage.run_all())

    if "evtx" in modules:
        logger.info("=" * 60)
        logger.info("MODULE 8: EVTX ANALYZER (Offline Event Logs)")
        logger.info("=" * 60)
        if args.evtx:
            evtx_analyzer = EVTXAnalyzer(args.evtx, logger)
            all_findings.extend(evtx_analyzer.run_all())
        else:
            logger.warning("[EVTX] Module enabled but no --evtx paths provided. Skipping.")

    # ---- Nova Confidence Scoring ----
    logger.info("=" * 60)
    logger.info("NOVA ATTRIBUTION / CONFIDENCE SCORING")
    logger.info("=" * 60)
    scorer = NovaConfidenceScorer()
    confidence_result = scorer.score(all_findings)
    attribution_finding = scorer.generate_attribution_finding()
    all_findings.append(attribution_finding)
    logger.info(f"[ATTRIBUTION] {confidence_result['confidence_level']} "
                f"(Score: {confidence_result['score']}/{confidence_result['max_possible']})")

    # ---- Timeline ----
    logger.info("=" * 60)
    logger.info("TIMELINE BUILDER")
    logger.info("=" * 60)
    tb = TimelineBuilder(all_findings, logger)
    timeline = tb.build()

    # ---- Reports ----
    logger.info("=" * 60)
    logger.info("GENERATING REPORTS")
    logger.info("=" * 60)
    reporter = ReportGenerator(all_findings, timeline, output_dir, logger, os_info=os_info)
    reporter.generate_all()

    # ---- MITRE ATT&CK Report ----
    logger.info("=" * 60)
    logger.info("GENERATING MITRE ATT&CK REPORT")
    logger.info("=" * 60)
    mitre_reporter = MITREReportGenerator(all_findings, confidence_result, output_dir, logger, os_info=os_info)
    mitre_reporter.generate()

    # ---- Summary ----
    critical = sum(1 for f in all_findings if f.severity == 5)
    high = sum(1 for f in all_findings if f.severity == 4)

    print("\n" + "=" * 60)
    print(f"  MODE: {operational_mode} ANALYSIS")
    print(f"  SCAN COMPLETE - {len(all_findings)} findings")
    print(f"  CRITICAL: {critical} | HIGH: {high}")
    print(f"  NOVA ATTRIBUTION: {confidence_result['confidence_level']}")
    print(f"  Reports saved to: {output_dir}")
    if operational_mode == "OFFLINE":
        print("  NOTE: This report is based on offline EVTX analysis only.")
    print("=" * 60)

    if critical > 0:
        print("\n  CRITICAL FINDINGS DETECTED - IMMEDIATE ACTION REQUIRED")
        print("  Isolate this host and escalate to your IR team NOW\n")

    return 0 if critical == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
