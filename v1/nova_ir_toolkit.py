#!/usr/bin/env python3
"""
================================================================================
 NOVA (formerly RALord) RANSOMWARE - INCIDENT RESPONSE & THREAT HUNTING TOOLKIT
================================================================================
 Author:  SOC/IR Team
 Version: 2.0
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
   1. IOC Scanner         - Known hashes, file extensions, ransom notes, network IOCs
   2. Persistence Hunter  - Registry, services, scheduled tasks, cron, launch agents
   3. Lateral Movement    - RDP, SMB, WMI, PsExec, SSH traces
   4. Exfiltration Detect - Large outbound transfers, cloud upload tools, staging dirs
   5. Defense Evasion     - Disabled AV/EDR, tampered logs, shadow copy deletion
   6. Timeline Builder    - Consolidates all findings into a chronological timeline
   7. Live Triage         - Current connections, processes, users, open files

 USAGE:
   Run as Administrator/root:
     python3 nova_ir_toolkit.py [--output-dir /path/to/output] [--modules all]
     python3 nova_ir_toolkit.py --modules ioc,persistence,timeline
     python3 nova_ir_toolkit.py --quick   (fast triage only)

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

# ============================================================================
# CONFIGURATION & KNOWN IOCs
# ============================================================================

NOVA_IOCS = {
    "sha256_hashes": [
        "456b9adaabae9f3dce2207aa71410987f0a571cd8c11f2e7b41468501a863606",
    ],
    "md5_hashes": [
        "be15f62d14d1cbe2aecce8396f4c6289",
    ],
    "file_extensions": [
        ".ralord",
    ],
    "ransom_note_names": [
        "README.txt",
        "RECOVERY.txt",
        "HOW_TO_RECOVER.txt",
        "RESTORE_FILES.txt",
        "!README!.txt",
    ],
    "ransom_note_keywords": [
        "nova", "ralord", "qtox", "tox id", "your files have been encrypted",
        "data has been stolen", "onion", "novavdivko2zvtrvtllnq45lxhba2rfzp76qigb4nrliklem5au7czqd",
        "pifk3xu3vad6cuxsjll4qjomyaaaoyvnyqppro75pazadzctrrvpdnyd",
        "novadmrkp4vbk2padk5t6pb",
    ],
    "tox_ids": [
        "8E9A6195A769FE7115F087C61D75CF32874C339B3AB0947D07480C9A8A12DA5009151BE6A51F",
    ],
    "session_tokens": [
        "054f55ec93aca9bac362b9d91eff36a7ce451e7caba47c0b2e004ba429f9529c79",
    ],
    "onion_domains": [
        "novavdivko2zvtrvtllnq45lxhba2rfzp76qigb4nrliklem5au7czqd.onion",
        "pifk3xu3vad6cuxsjll4qjomyaaaoyvnyqppro75pazadzctrrvpdnyd.onion",
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

def severity_label(sev: int) -> str:
    return {1: "INFO", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}.get(sev, "UNKNOWN")


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
        """Find files with .ralord extension."""
        self.logger.info("[IOC] Scanning for .ralord encrypted files...")
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
        for root in search_roots:
            try:
                for dirpath, _, filenames in os.walk(root, followlinks=False):
                    for fname in filenames:
                        if fname.endswith(".ralord"):
                            fpath = os.path.join(dirpath, fname)
                            stat_info = safe_stat(fpath)
                            encrypted_files.append(stat_info or {"path": fpath})
                            if len(encrypted_files) >= 500:  # cap for performance
                                break
                    if len(encrypted_files) >= 500:
                        break
            except (PermissionError, OSError):
                continue
        
        if encrypted_files:
            f = Finding(
                self.MODULE,
                "ENCRYPTED FILES DETECTED (.ralord)",
                f"Found {len(encrypted_files)} files encrypted by Nova/RALord ransomware",
                severity=5,
                mitre_id="T1486",
                evidence={"encrypted_files": encrypted_files[:100], "total_count": len(encrypted_files)},
            )
            self.findings.append(f)
            self.logger.critical(f"[IOC] CRITICAL: Found {len(encrypted_files)} .ralord encrypted files!")
        else:
            self.logger.info("[IOC] No .ralord encrypted files found.")
        
        return self.findings
    
    def scan_ransom_notes(self) -> List[Finding]:
        """Find ransom notes by name and keyword content."""
        self.logger.info("[IOC] Scanning for ransom notes...")
        os_type = get_os_type()
        
        if os_type == "windows":
            search_roots = ["C:\\Users", "C:\\"]
        elif os_type == "macos":
            search_roots = ["/Users", "/tmp"]
        else:
            search_roots = ["/home", "/tmp", "/root", "/var"]
        
        found_notes = []
        for root in search_roots:
            try:
                for dirpath, _, filenames in os.walk(root, followlinks=False):
                    for fname in filenames:
                        if fname in NOVA_IOCS["ransom_note_names"]:
                            fpath = os.path.join(dirpath, fname)
                            note_info = {"path": fpath, "matched_by": "filename"}
                            # Check content for Nova-specific keywords
                            try:
                                with open(fpath, "r", errors="ignore") as nf:
                                    content = nf.read(4096).lower()
                                    matched_kw = [kw for kw in NOVA_IOCS["ransom_note_keywords"] if kw in content]
                                    if matched_kw:
                                        note_info["matched_keywords"] = matched_kw
                                        note_info["confirmed_nova"] = True
                                        note_info["matched_by"] = "filename+content"
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
        self.logger.info("[IOC] Scanning for known malware hashes...")
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
                            if fsize > 100_000_000 or fsize < 1000:  # skip very large/tiny
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
        self.logger.info("[IOC] Scanning for suspicious/dual-use tools...")
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
                    # Flag entries in unusual locations
                    suspicious_indicators = [
                        "temp", "appdata", "perflog", "programdata",
                        "powershell", "cmd.exe /c", "mshta", "wscript", "cscript",
                        "rundll32", ".bat", ".vbs", ".ps1", ".hta",
                    ]
                    if any(ind in line_lower for ind in suspicious_indicators):
                        suspicious_entries.append({"registry_path": rpath, "entry": line.strip()})
        
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
            for line in out.split("\n"):
                line_lower = line.lower()
                if any(t in line_lower for t in ["temp", "appdata", "perflog", "powershell -enc",
                                                  "cmd /c", "wscript", "cscript", ".bat", ".ps1"]):
                    suspicious_tasks.append(line.strip())
            
            if suspicious_tasks:
                self.findings.append(Finding(
                    self.MODULE,
                    "SUSPICIOUS SCHEDULED TASKS",
                    f"Found {len(suspicious_tasks)} potentially malicious scheduled tasks",
                    severity=4, mitre_id="T1053",
                    evidence={"tasks": suspicious_tasks[:30]},
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
                    suspicious_svcs.append(line.strip())
            if suspicious_svcs:
                self.findings.append(Finding(
                    self.MODULE,
                    "SUSPICIOUS WINDOWS SERVICES",
                    f"Found {len(suspicious_svcs)} suspicious auto-start services",
                    severity=4, mitre_id="T1543",
                    evidence={"services": suspicious_svcs},
                ))
        
        return self.findings
    
    def check_linux_persistence(self) -> List[Finding]:
        """Check cron, systemd, rc.local, profile scripts, authorized_keys."""
        self.logger.info("[PERSIST] Checking Linux persistence mechanisms...")
        
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
                        if (datetime.now().timestamp() - mtime) < 7 * 86400:  # last 7 days
                            suspicious.append({
                                "type": "recently_modified_profile",
                                "details": stat,
                            })
                    except OSError:
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
        
        # --- RDP Connections (Inbound) ---
        out, _, rc = run_cmd(
            'wevtutil qe "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" '
            '/q:"*[System[(EventID=21 or EventID=25)]]" /f:text /c:50 2>nul',
            timeout=30
        )
        if rc == 0 and out and "Event" in out:
            self.findings.append(Finding(
                self.MODULE,
                "RDP INBOUND CONNECTIONS DETECTED",
                "Recent RDP logon sessions detected - review for unauthorized access",
                severity=3, mitre_id="T1021",
                evidence={"rdp_events": out[:5000]},
            ))
        
        # --- RDP Outbound (bitmap cache) ---
        bmc_path = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache")
        if os.path.exists(bmc_path):
            cache_files = os.listdir(bmc_path)
            if cache_files:
                self.findings.append(Finding(
                    self.MODULE,
                    "RDP OUTBOUND CACHE FOUND",
                    f"RDP bitmap cache with {len(cache_files)} files - indicates outbound RDP",
                    severity=3, mitre_id="T1021",
                    evidence={"cache_dir": bmc_path, "file_count": len(cache_files)},
                ))
        
        # --- SMB/Admin shares ---
        out, _, rc = run_cmd("net use 2>nul")
        if rc == 0 and out:
            connections = [l.strip() for l in out.split("\n") if "\\\\" in l]
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
            psexec_indicators.append({"type": "psexesvc_binary", "path": psexec_svc})
        
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
            type3_count = out.lower().count("logon type:		3")
            type10_count = out.lower().count("logon type:		10")
            if type3_count > 0 or type10_count > 0:
                self.findings.append(Finding(
                    self.MODULE, "NETWORK/RDP LOGON EVENTS",
                    f"Found {type3_count} network logons (Type 3) and {type10_count} RDP logons (Type 10)",
                    severity=3, mitre_id="T1078",
                    evidence={"type3_count": type3_count, "type10_count": type10_count,
                              "raw_preview": out[:3000]},
                ))
        
        return self.findings
    
    def check_linux_lateral(self) -> List[Finding]:
        self.logger.info("[LATERAL] Checking Linux lateral movement artifacts...")
        
        # --- SSH login history ---
        out, _, rc = run_cmd("last -i -n 50 2>/dev/null || last -n 50 2>/dev/null")
        if rc == 0 and out:
            remote_logins = [l for l in out.split("\n") if l.strip() and "pts/" in l]
            if remote_logins:
                self.findings.append(Finding(
                    self.MODULE, "SSH/REMOTE LOGIN HISTORY",
                    f"Found {len(remote_logins)} remote terminal sessions",
                    severity=3, mitre_id="T1021",
                    evidence={"sessions": remote_logins[:30]},
                ))
        
        # --- Failed login attempts ---
        out, _, rc = run_cmd("lastb -n 50 2>/dev/null")
        if rc == 0 and out and len(out.strip()) > 10:
            self.findings.append(Finding(
                self.MODULE, "FAILED LOGIN ATTEMPTS",
                "Failed login attempts detected - possible brute force",
                severity=3, mitre_id="T1078",
                evidence={"failed_logins": out[:3000]},
            ))
        
        # --- auth.log analysis ---
        auth_logs = ["/var/log/auth.log", "/var/log/secure"]
        for alog in auth_logs:
            if os.path.exists(alog):
                try:
                    out, _, rc = run_cmd(f"grep -i 'accepted\\|failed\\|invalid\\|sudo' {alog} | tail -100")
                    if out:
                        accepted = [l for l in out.split("\n") if "accepted" in l.lower()]
                        failed = [l for l in out.split("\n") if "failed" in l.lower()]
                        sudo = [l for l in out.split("\n") if "sudo" in l.lower()]
                        self.findings.append(Finding(
                            self.MODULE, "AUTH LOG ANALYSIS",
                            f"Accepted: {len(accepted)}, Failed: {len(failed)}, Sudo: {len(sudo)}",
                            severity=3, mitre_id="T1078",
                            evidence={"accepted": accepted[:20], "failed": failed[:20], "sudo": sudo[:20]},
                        ))
                except (PermissionError, OSError):
                    pass
        
        return self.findings
    
    def check_macos_lateral(self) -> List[Finding]:
        self.logger.info("[LATERAL] Checking macOS lateral movement artifacts...")
        
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
        self.logger.info("[EXFIL] Checking for data exfiltration indicators...")
        os_type = get_os_type()
        
        exfil_tools = ["rclone", "megasync", "winscp", "filezilla", "cyberduck",
                        "7z", "7za", "rar", "tar", "zip",  # archiving for staging
                        "curl", "wget", "scp", "rsync", "ftp"]
        
        if os_type == "windows":
            out, _, _ = run_cmd("tasklist /fo csv 2>nul")
        else:
            out, _, _ = run_cmd("ps aux 2>/dev/null")
        
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
        self.logger.info("[EXFIL] Checking for data staging directories...")
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
        self.logger.info("[EXFIL] Checking for rclone configuration...")
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
        self.logger.info("[EXFIL] Checking outbound network connections...")
        os_type = get_os_type()
        
        if os_type == "windows":
            out, _, _ = run_cmd("netstat -naob 2>nul", timeout=15)
        else:
            out, _, _ = run_cmd("ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null", timeout=15)
        
        if out:
            # Look for connections on unusual ports
            unusual_ports = {"4444", "5555", "6666", "8888", "9999", "1234", "31337",
                             "4443", "8443", "9443",  # alt HTTPS
                             "9050", "9150",  # Tor
                             }
            suspicious_conns = []
            for line in out.split("\n"):
                for port in unusual_ports:
                    if f":{port}" in line and "ESTABLISHED" in line.upper():
                        suspicious_conns.append(line.strip())
                        break
            
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
        out, _, rc = run_cmd("vssadmin list shadows 2>nul")
        if rc == 0:
            if "no items" in out.lower() or "no shadow" in out.lower() or not out.strip():
                self.findings.append(Finding(
                    self.MODULE,
                    "NO VOLUME SHADOW COPIES (BACKUP DESTRUCTION)",
                    "All VSS shadow copies appear deleted - typical ransomware behavior",
                    severity=5, mitre_id="T1490",
                    evidence={"vss_output": out},
                ))
        
        # --- Windows event log clearing ---
        out, _, rc = run_cmd(
            'wevtutil qe Security /q:"*[System[(EventID=1102)]]" /f:text /c:10 2>nul',
            timeout=15
        )
        if rc == 0 and out and "1102" in out:
            self.findings.append(Finding(
                self.MODULE,
                "SECURITY LOG CLEARED (ANTI-FORENSICS)",
                "Security event log clearing events detected (Event ID 1102)",
                severity=5, mitre_id="T1070",
                evidence={"log_clear_events": out[:3000]},
            ))
        
        # --- Check if key event logs are empty/tiny ---
        log_channels = ["Security", "System", "Application",
                         "Microsoft-Windows-PowerShell/Operational"]
        empty_logs = []
        for lc in log_channels:
            out, _, rc = run_cmd(f'wevtutil gli "{lc}" 2>nul')
            if rc == 0 and out:
                match = re.search(r'numberOfLogRecords:\s*(\d+)', out, re.I)
                if match and int(match.group(1)) < 50:
                    empty_logs.append({"log": lc, "records": int(match.group(1))})
        
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
        
        return self.findings
    
    def check_linux_defense_evasion(self) -> List[Finding]:
        self.logger.info("[EVASION] Checking Linux defense evasion indicators...")
        
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
        if os_type == "windows":
            out, _, _ = run_cmd("tasklist /v /fo csv 2>nul")
        else:
            out, _, _ = run_cmd("ps auxww 2>/dev/null")
        
        suspicious_procs = []
        if out:
            for proc_name in NOVA_IOCS["suspicious_processes"]:
                if proc_name.lower() in out.lower():
                    # Extract the matching lines
                    matches = [l for l in out.split("\n") if proc_name.lower() in l.lower()]
                    suspicious_procs.extend(matches[:5])
        
        if suspicious_procs:
            self.findings.append(Finding(
                self.MODULE,
                "SUSPICIOUS PROCESSES RUNNING",
                f"Found {len(suspicious_procs)} suspicious processes currently running",
                severity=4, mitre_id="T1059",
                evidence={"processes": suspicious_procs},
            ))
        
        triage_data["process_list_preview"] = out[:5000] if out else ""
        
        # --- Network Connections ---
        if os_type == "windows":
            out, _, _ = run_cmd("netstat -naob 2>nul", timeout=15)
        else:
            out, _, _ = run_cmd("ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null", timeout=15)
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
            for line in out.split("\n"):
                # Common attacker reverse shell / C2 ports
                for port in ["4444", "5555", "6666", "8888", "9999", "1234", "31337", "9050"]:
                    if f":{port}" in line:
                        unusual.append(line.strip())
            if unusual:
                self.findings.append(Finding(
                    self.MODULE,
                    "UNUSUAL LISTENING PORTS",
                    f"Found {len(unusual)} processes listening on suspicious ports",
                    severity=4, mitre_id="T1059",
                    evidence={"listeners": unusual},
                ))
        
        # --- DNS Cache (Windows) ---
        if os_type == "windows":
            out, _, rc = run_cmd("ipconfig /displaydns 2>nul", timeout=15)
            if rc == 0 and out:
                # Look for onion or suspicious domains
                suspicious_dns = []
                for line in out.split("\n"):
                    line_lower = line.lower()
                    if any(d in line_lower for d in [".onion", "mega.nz", "mega.co", "anonfiles",
                                                     "transfer.sh", "gofile.io", "dropmefiles"]):
                        suspicious_dns.append(line.strip())
                if suspicious_dns:
                    self.findings.append(Finding(
                        self.MODULE,
                        "SUSPICIOUS DNS CACHE ENTRIES",
                        f"Found {len(suspicious_dns)} suspicious domain resolutions in DNS cache",
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
                 output_dir: str, logger: logging.Logger):
        self.findings = findings
        self.timeline = timeline
        self.output_dir = output_dir
        self.logger = logger
    
    def generate_all(self):
        self.generate_json()
        self.generate_csv()
        self.generate_txt()
    
    def generate_json(self):
        path = os.path.join(self.output_dir, "nova_ir_findings.json")
        data = {
            "metadata": {
                "tool": "Nova/RALord IR Toolkit",
                "version": "2.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "hostname": socket.gethostname(),
                "os": platform.platform(),
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
            f.write("=" * 80 + "\n")
            f.write(" NOVA (RALord) RANSOMWARE - INCIDENT RESPONSE REPORT\n")
            f.write(f" Generated: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f" Host:      {socket.gethostname()}\n")
            f.write(f" OS:        {platform.platform()}\n")
            f.write("=" * 80 + "\n\n")
            
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
            f.write("  Payload:      Rust-based ransomware\n")
            f.write("  Extension:    .ralord\n")
            f.write("  Model:        RaaS (85/15 affiliate split)\n")
            f.write("  Double Extort: Yes (encrypt + data leak threat)\n")
            f.write("  Known Tox ID: 8E9A6195A769FE7115F087C61D75CF32874C339B3AB...\n")
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
# MAIN ORCHESTRATOR
# ============================================================================

def main():
    banner = r"""
    ╔══════════════════════════════════════════════════════════════════╗
    ║       NOVA / RALord RANSOMWARE - IR & THREAT HUNTING TOOLKIT   ║
    ║                                                                ║
    ║  Modules: IOC Scanner | Persistence | Lateral Movement         ║
    ║           Exfiltration | Defense Evasion | Live Triage          ║
    ║           Timeline Builder                                     ║
    ║                                                                ║
    ║  ⚠  RUN AS ADMINISTRATOR / ROOT FOR FULL VISIBILITY  ⚠        ║
    ╚══════════════════════════════════════════════════════════════════╝
    """
    print(banner)
    
    parser = argparse.ArgumentParser(description="Nova/RALord Ransomware IR Toolkit")
    parser.add_argument("--output-dir", "-o", default=None,
                        help="Output directory for reports")
    parser.add_argument("--modules", "-m", default="all",
                        help="Comma-separated modules: ioc,persistence,lateral,exfil,evasion,triage,timeline (or 'all')")
    parser.add_argument("--quick", "-q", action="store_true",
                        help="Quick triage mode (IOC + Triage only)")
    args = parser.parse_args()
    
    # Setup output directory
    if args.output_dir:
        output_dir = args.output_dir
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(os.path.expanduser("~"), f"nova_ir_{ts}")
    
    os.makedirs(output_dir, exist_ok=True)
    logger = setup_logging(output_dir)
    
    logger.info(f"Nova IR Toolkit started on {socket.gethostname()} ({platform.platform()})")
    logger.info(f"Output directory: {output_dir}")
    
    # Determine modules to run
    if args.quick:
        modules = {"ioc", "triage"}
    elif args.modules == "all":
        modules = {"ioc", "persistence", "lateral", "exfil", "evasion", "triage"}
    else:
        modules = set(args.modules.lower().split(","))
    
    all_findings: List[Finding] = []
    
    # ---- Run modules ----
    if "ioc" in modules:
        logger.info("=" * 60)
        logger.info("MODULE 1: IOC SCANNER")
        logger.info("=" * 60)
        scanner = IOCScanner(logger)
        all_findings.extend(scanner.run_all())
    
    if "persistence" in modules:
        logger.info("=" * 60)
        logger.info("MODULE 2: PERSISTENCE HUNTER")
        logger.info("=" * 60)
        persist = PersistenceHunter(logger)
        all_findings.extend(persist.run_all())
    
    if "lateral" in modules:
        logger.info("=" * 60)
        logger.info("MODULE 3: LATERAL MOVEMENT DETECTOR")
        logger.info("=" * 60)
        lateral = LateralMovementDetector(logger)
        all_findings.extend(lateral.run_all())
    
    if "exfil" in modules:
        logger.info("=" * 60)
        logger.info("MODULE 4: EXFILTRATION DETECTOR")
        logger.info("=" * 60)
        exfil = ExfiltrationDetector(logger)
        all_findings.extend(exfil.run_all())
    
    if "evasion" in modules:
        logger.info("=" * 60)
        logger.info("MODULE 5: DEFENSE EVASION DETECTOR")
        logger.info("=" * 60)
        evasion = DefenseEvasionDetector(logger)
        all_findings.extend(evasion.run_all())
    
    if "triage" in modules:
        logger.info("=" * 60)
        logger.info("MODULE 6: LIVE TRIAGE")
        logger.info("=" * 60)
        triage = LiveTriage(logger)
        all_findings.extend(triage.run_all())
    
    # ---- Timeline ----
    logger.info("=" * 60)
    logger.info("MODULE 7: TIMELINE BUILDER")
    logger.info("=" * 60)
    tb = TimelineBuilder(all_findings, logger)
    timeline = tb.build()
    
    # ---- Reports ----
    logger.info("=" * 60)
    logger.info("GENERATING REPORTS")
    logger.info("=" * 60)
    reporter = ReportGenerator(all_findings, timeline, output_dir, logger)
    reporter.generate_all()
    
    # ---- Summary ----
    critical = sum(1 for f in all_findings if f.severity == 5)
    high = sum(1 for f in all_findings if f.severity == 4)
    
    print("\n" + "=" * 60)
    print(f"  SCAN COMPLETE - {len(all_findings)} findings")
    print(f"  CRITICAL: {critical} | HIGH: {high}")
    print(f"  Reports saved to: {output_dir}")
    print("=" * 60)
    
    if critical > 0:
        print("\n  ⚠️  CRITICAL FINDINGS DETECTED - IMMEDIATE ACTION REQUIRED")
        print("  ⚠️  Isolate this host and escalate to your IR team NOW\n")
    
    return 0 if critical == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
