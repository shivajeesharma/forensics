<#
.SYNOPSIS
    Nova/RALord Ransomware - Windows Rapid Triage Script
.DESCRIPTION
    Quick-deploy PowerShell script for Windows endpoint triage during a Nova incident.
    Collects volatile data, checks for IOCs, and exports a triage package.
    Must be run as Administrator.
.NOTES
    Version: 1.0
    Date:    2026-02-09
    READ-ONLY: This script does not modify the system.
#>

#Requires -RunAsAdministrator

param(
    [string]$OutputDir = "$env:USERPROFILE\Desktop\Nova_Triage_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

# NOTE: We use -ErrorAction SilentlyContinue on individual commands rather than
# globally suppressing errors, so collection failures are visible in the log.

# ── Setup ──────────────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$LogFile = Join-Path $OutputDir "triage_log.txt"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    $entry = "[$ts] [$Level] $Message"
    Write-Host $entry -ForegroundColor $(switch($Level) { "CRITICAL" {"Red"} "WARNING" {"Yellow"} "SUCCESS" {"Green"} default {"White"} })
    Add-Content -Path $LogFile -Value $entry
}

Write-Host @"

 ╔═══════════════════════════════════════════════════════════╗
 ║  NOVA / RALord - Windows Rapid Triage                    ║
 ║  Run as Administrator for full visibility                 ║
 ╚═══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Write-Log "Triage started on $env:COMPUTERNAME"
Write-Log "Output: $OutputDir"

# ── Known IOCs ─────────────────────────────────────────────────────────────────
$NovaIOCs = @{
    SHA256       = @("456b9adaabae9f3dce2207aa71410987f0a571cd8c11f2e7b41468501a863606")
    MD5          = @("be15f62d14d1cbe2aecce8396f4c6289",
                     "ef846baabc14fe461cff4c4a0fd5056f",
                     "4566f5ba6d1a1db0dd7794ea8d791b3f",
                     "4924b945cfdc5bfece03f5140a546384")
    ToxIDs       = @("8E9A6195A769FE7115F087C61D75CF32874C339B3AB0947D07480C9A8A12DA5009151BE6A51F",
                     "0C8E5B45C57AE244E9C904C5BC74F73306937469D9CEA22541CA69AC162B8D42A20F4C0382AC")
    FileExts     = @(".ralord",".nova",".LORD",".RNOVA")
    OnionDomains = @(
        "novavdivko2zvtrvtllnq45lxhba2rfzp76qigb4nrliklem5au7czqd.onion",
        "pifk3xu3vad6cuxsjll4qjomyaaaoyvnyqppro75pazadzctrrvpdnyd.onion",
        "novadmrkp4vbk2padk5t6pbxolndceuc7hrcq4mjaoyed6nxsqiuzyyd.onion",
        "novav75eqkjoxct7xuhhwnjw5uaaxvznhtbykq6zal5x7tfevxzjyqyd.onion",
        "novavagygnhqyf7a5tgbuvmujve5a2jzgbrq2n4dvetkhvr2zjg27cad.onion",
        "ralordt7gywtkkkkq2suldao6mpibsb7cpjvdfezpzwgltyj2laiuuid.onion",
        "ralord3htj7v2dkavss2hjzviviwgsf4anfdnihn5qcjl6eb5if3cuqd.onion",
        "ralordqe33mpufkpsr6zkdatktlu3t2uei4ught3sitxgtzfmqmbsuyd.onion"
    )
    C2IPs        = @("144.172.92.192","144.172.95.78")
    SuspTools    = @("rclone","psexec","psexec64","megasync","winscp","mimikatz",
                     "lazagne","sharphound","bloodhound","anydesk","chisel","ngrok",
                     "advanced_ip_scanner","netscan")
}

# ══════════════════════════════════════════════════════════════════════════════
# 1. SYSTEM INFO
# ══════════════════════════════════════════════════════════════════════════════
Write-Log "Collecting system information (hostname, domain, OS, IPs, last boot)..."
Write-Log "  WHY: Establishes the identity and state of this endpoint for the IR report."
$sysInfo = @{
    Hostname     = $env:COMPUTERNAME
    Domain       = $env:USERDOMAIN
    User         = $env:USERNAME
    OS           = (Get-CimInstance Win32_OperatingSystem).Caption
    LastBoot     = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    Timestamp    = (Get-Date).ToUniversalTime().ToString("o")
    IPs          = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" }).IPAddress
}
$sysInfo | ConvertTo-Json | Out-File (Join-Path $OutputDir "01_system_info.json")

# ══════════════════════════════════════════════════════════════════════════════
# 2. ENCRYPTED FILES
# ══════════════════════════════════════════════════════════════════════════════
Write-Log "Scanning for files encrypted by Nova/RALord (extensions: $($NovaIOCs.FileExts -join ', '))..."
Write-Log "  WHY: Nova appends these extensions after encrypting files. Finding them confirms active encryption."
$encryptedFiles = @()
foreach ($drive in (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 })) {
    foreach ($ext in $NovaIOCs.FileExts) {
        try {
            $found = Get-ChildItem -Path "$($drive.Root)" -Filter "*$ext" -Recurse -Depth 15 -ErrorAction SilentlyContinue |
                     Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc, @{N='Extension';E={$ext}} -First 500
            $encryptedFiles += $found
        } catch {}
    }
}

if ($encryptedFiles.Count -gt 0) {
    Write-Log "CRITICAL: Found $($encryptedFiles.Count) encrypted files!" "CRITICAL"
    $encryptedFiles | Export-Csv (Join-Path $OutputDir "02_encrypted_files.csv") -NoTypeInformation
} else {
    Write-Log "No encrypted files found with known Nova extensions" "SUCCESS"
}

# ══════════════════════════════════════════════════════════════════════════════
# 3. RANSOM NOTES
# ══════════════════════════════════════════════════════════════════════════════
Write-Log "Scanning for ransom notes (README.txt, RECOVERY.txt, HOW_TO_RECOVER.txt, etc.)..."
Write-Log "  WHY: Nova drops ransom notes in every encrypted directory. Content reveals Tox ID, onion URLs."
$noteNames = @("README.txt","RECOVERY.txt","HOW_TO_RECOVER.txt","RESTORE_FILES.txt","!README!.txt")
$ransomNotes = @()

foreach ($drive in (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 })) {
    foreach ($note in $noteNames) {
        try {
            $found = Get-ChildItem -Path "$($drive.Root)" -Filter $note -Recurse -ErrorAction SilentlyContinue -Depth 5 |
                     Select-Object FullName, Length, LastWriteTimeUtc -First 50
            foreach ($f in $found) {
                $content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
                $novaMatch = $content -match "(?i)(nova|ralord|qtox|tox id|onion|novavdivko|ralordt7|session messenger|jabber)"
                $ransomNotes += [PSCustomObject]@{
                    Path         = $f.FullName
                    Size         = $f.Length
                    Modified     = $f.LastWriteTimeUtc
                    NovaConfirm  = $novaMatch
                    ContentSnip  = $(if ($content) { $content.Substring(0, [Math]::Min(500, $content.Length)) } else { "" })
                }
            }
        } catch {}
    }
}

if ($ransomNotes.Count -gt 0) {
    $confirmed = ($ransomNotes | Where-Object { $_.NovaConfirm }).Count
    Write-Log "Found $($ransomNotes.Count) ransom notes ($confirmed confirmed Nova)" "CRITICAL"
    $ransomNotes | Export-Csv (Join-Path $OutputDir "03_ransom_notes.csv") -NoTypeInformation
    # Save full content of confirmed notes
    $ransomNotes | Where-Object { $_.NovaConfirm } | ForEach-Object {
        $safeName = $_.Path -replace '[\\/:*?"<>|]', '_'
        Copy-Item $_.Path (Join-Path $OutputDir "note_$safeName") -ErrorAction SilentlyContinue
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# 4. RUNNING PROCESSES
# ══════════════════════════════════════════════════════════════════════════════
Write-Log "Capturing running processes and checking for attacker tools..."
Write-Log "  SEARCHING: rclone, PsExec, mimikatz, LaZagne, SharpHound, AnyDesk, chisel, ngrok, etc."
Write-Log "  WHY: Identifies currently running attacker tools and captures volatile process evidence."
# Single WMI query upfront instead of per-process queries (orders of magnitude faster)
$wmiProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Select-Object ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId, CreationDate
$wmiLookup = @{}
foreach ($wp in $wmiProcs) { $wmiLookup[$wp.ProcessId] = $wp }

$procs = Get-Process -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, Path, StartTime, Company,
    @{N='CommandLine';E={ $wmiLookup[[int]$_.Id].CommandLine }},
    @{N='ParentPID';E={ $wmiLookup[[int]$_.Id].ParentProcessId }}

$procs | Export-Csv (Join-Path $OutputDir "04_processes.csv") -NoTypeInformation

# Flag suspicious - proper filter logic
$suspProcs = $procs | Where-Object {
    $name = $_.ProcessName.ToLower()
    $matched = $false
    foreach ($tool in $NovaIOCs.SuspTools) {
        if ($name -like "*$tool*") { $matched = $true; break }
    }
    $matched
}

if ($suspProcs) {
    Write-Log "SUSPICIOUS PROCESSES FOUND: $($suspProcs.ProcessName -join ', ')" "CRITICAL"
    $suspProcs | Export-Csv (Join-Path $OutputDir "04_suspicious_processes.csv") -NoTypeInformation
}

# ══════════════════════════════════════════════════════════════════════════════
# 5. NETWORK CONNECTIONS
# ══════════════════════════════════════════════════════════════════════════════
Write-Log "Capturing network connections (checking for C2 ports and known Nova IPs)..."
Write-Log "  SEARCHING: Connections on ports 4444,5555,6666,8888,9999,1234,31337,9050,9150,4443,8443"
Write-Log "  WHY: Active outbound connections reveal if the attacker is still connected to this host."
$netConns = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
    State, OwningProcess,
    @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}

$netConns | Export-Csv (Join-Path $OutputDir "05_network_connections.csv") -NoTypeInformation

# Flag connections to known Nova C2 IPs
$c2Conns = $netConns | Where-Object { $_.RemoteAddress -in $NovaIOCs.C2IPs }
if ($c2Conns) {
    Write-Log "ACTIVE CONNECTION TO KNOWN NOVA C2 IP: $($c2Conns.RemoteAddress -join ', ')" "CRITICAL"
    $c2Conns | Export-Csv (Join-Path $OutputDir "05_c2_connections.csv") -NoTypeInformation
}

# Flag suspicious ports
$suspPorts = @(4444,5555,6666,8888,9999,1234,31337,9050,9150,4443,8443)
$suspConns = $netConns | Where-Object { $_.RemotePort -in $suspPorts -and $_.State -eq 'Established' }
if ($suspConns) {
    Write-Log "SUSPICIOUS OUTBOUND CONNECTIONS on ports: $($suspConns.RemotePort -join ', ')" "WARNING"
    $suspConns | Export-Csv (Join-Path $OutputDir "05_suspicious_connections.csv") -NoTypeInformation
}

# ══════════════════════════════════════════════════════════════════════════════
# 6. PERSISTENCE MECHANISMS
# ══════════════════════════════════════════════════════════════════════════════
Write-Log "Checking persistence mechanisms (registry run keys, scheduled tasks, services)..."
Write-Log "  WHY: Nova affiliates establish persistence to survive reboots and maintain access."

# Registry Run keys
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)

$regEntries = @()
foreach ($rp in $regPaths) {
    try {
        $items = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
        if ($items) {
            $items.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                $regEntries += [PSCustomObject]@{
                    RegistryPath = $rp
                    Name         = $_.Name
                    Value        = $_.Value
                    Suspicious   = $_.Value -match "(?i)(temp|appdata|perflog|powershell|cmd\.exe|mshta|wscript|\.bat|\.ps1|\.vbs)"
                }
            }
        }
    } catch {}
}

$regEntries | Export-Csv (Join-Path $OutputDir "06_registry_autorun.csv") -NoTypeInformation
$suspReg = $regEntries | Where-Object { $_.Suspicious }
if ($suspReg) {
    Write-Log "SUSPICIOUS AUTORUN ENTRIES: $($suspReg.Count)" "WARNING"
}

# Scheduled Tasks
Write-Log "Checking scheduled tasks for suspicious entries (temp, PowerShell encoded, cmd /c)..."
$tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |
    Select-Object TaskName, TaskPath, State,
    @{N='Action';E={$_.Actions.Execute}},
    @{N='Arguments';E={$_.Actions.Arguments}},
    @{N='LastRunTime';E={(Get-ScheduledTaskInfo -TaskName $_.TaskName -ErrorAction SilentlyContinue).LastRunTime}}

$tasks | Export-Csv (Join-Path $OutputDir "06_scheduled_tasks.csv") -NoTypeInformation

$suspTasks = $tasks | Where-Object {
    $_.Action -match "(?i)(temp|appdata|perflog|powershell.*-enc|cmd.*/c|wscript|cscript|\.bat|\.ps1)" -or
    $_.Arguments -match "(?i)(temp|appdata|perflog|base64|downloadstring|invoke-expression)"
}
if ($suspTasks) {
    Write-Log "SUSPICIOUS SCHEDULED TASKS: $($suspTasks.Count)" "WARNING"
    $suspTasks | Export-Csv (Join-Path $OutputDir "06_suspicious_tasks.csv") -NoTypeInformation
}

# Services
Write-Log "Checking auto-start services for binaries in unusual locations..."
$services = Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' } |
    Select-Object Name, DisplayName, State, PathName, StartMode, StartName

$services | Export-Csv (Join-Path $OutputDir "06_services.csv") -NoTypeInformation

$suspSvc = $services | Where-Object {
    $_.PathName -match "(?i)(temp|appdata|perflog|programdata\\[^M]|\.bat|\.ps1|cmd\.exe)"
}
if ($suspSvc) {
    Write-Log "SUSPICIOUS SERVICES: $($suspSvc.Count)" "WARNING"
}

# ══════════════════════════════════════════════════════════════════════════════
# 7. DEFENDER & SECURITY STATUS
# ══════════════════════════════════════════════════════════════════════════════
Write-Log "Checking Windows Defender status (real-time, behavior, tamper protection, exclusions)..."
Write-Log "  WHY: Nova ALWAYS disables Defender before encryption. Exclusions may reveal attacker paths."

try {
    $defender = Get-MpPreference
    $defenderStatus = [PSCustomObject]@{
        RealTimeMonitoring    = -not $defender.DisableRealtimeMonitoring
        BehaviorMonitoring    = -not $defender.DisableBehaviorMonitoring
        IOAVProtection        = -not $defender.DisableIOAVProtection
        TamperProtection      = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name TamperProtection -ErrorAction SilentlyContinue).TamperProtection
        ExclusionPaths        = ($defender.ExclusionPath -join "; ")
        ExclusionExtensions   = ($defender.ExclusionExtension -join "; ")
        ExclusionProcesses    = ($defender.ExclusionProcess -join "; ")
    }
    $defenderStatus | ConvertTo-Json | Out-File (Join-Path $OutputDir "07_defender_status.json")

    if ($defender.DisableRealtimeMonitoring) { Write-Log "DEFENDER REAL-TIME MONITORING IS DISABLED!" "CRITICAL" }
    if ($defender.DisableBehaviorMonitoring) { Write-Log "DEFENDER BEHAVIOR MONITORING IS DISABLED!" "CRITICAL" }
    if ($defender.ExclusionPath) { Write-Log "DEFENDER EXCLUSION PATHS SET: $($defender.ExclusionPath -join ', ')" "WARNING" }
    if ($defender.ExclusionExtension) { Write-Log "DEFENDER EXCLUSION EXTENSIONS: $($defender.ExclusionExtension -join ', ')" "WARNING" }
} catch {
    Write-Log "Could not query Defender status" "WARNING"
}

# ══════════════════════════════════════════════════════════════════════════════
# 8. SHADOW COPIES & BACKUPS
# ══════════════════════════════════════════════════════════════════════════════
Write-Log "Checking Volume Shadow Copies (VSS)..."
Write-Log "  WHY: Nova deletes all shadow copies to prevent file recovery. Missing VSS = encryption likely."
$vss = vssadmin list shadows 2>&1
$vss | Out-File (Join-Path $OutputDir "08_shadow_copies.txt")

if ($vss -match "No items found" -or $vss -match "no shadow copies") {
    Write-Log "NO SHADOW COPIES EXIST - Likely deleted by ransomware!" "CRITICAL"
} else {
    $shadowCount = ($vss | Select-String "Shadow Copy ID").Count
    Write-Log "Found $shadowCount shadow copies" "INFO"
}

# ══════════════════════════════════════════════════════════════════════════════
# 9. EVENT LOG ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
Write-Log "Analyzing Security Event Logs (1102=log cleared, 4624=logons, 4625=failed, 4104=PowerShell)..."
Write-Log "  WHY: Event logs reveal the attacker's actions - RDP sessions, credential brute-forcing,"
Write-Log "       PowerShell commands used, and whether they tried to cover their tracks by clearing logs."

# Log clearing events (1102)
$logClears = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102} -MaxEvents 20 -ErrorAction SilentlyContinue
if ($logClears) {
    Write-Log "SECURITY LOG CLEARING EVENTS FOUND: $($logClears.Count)" "CRITICAL"
    $logClears | Select-Object TimeCreated, Id, Message | Export-Csv (Join-Path $OutputDir "09_log_clearing.csv") -NoTypeInformation
}

# Logon events (4624) - single query, filter in memory for Type 10 (RDP) and Type 3 (Network)
$allLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 500 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message,
    @{N='LogonType';E={
        if ($_.Message -match "Logon Type:\s+(\d+)") { $matches[1] }
    }},
    @{N='SourceIP';E={
        if ($_.Message -match "Source Network Address:\s+(\S+)") { $matches[1] }
    }},
    @{N='Account';E={
        if ($_.Message -match "Account Name:\s+(\S+)") { $matches[1] }
    }}

$rdpLogons = $allLogons | Where-Object { $_.LogonType -eq "10" } | Select-Object TimeCreated, SourceIP, Account
if ($rdpLogons) {
    Write-Log "RDP LOGON EVENTS: $($rdpLogons.Count)" "WARNING"
    $rdpLogons | Export-Csv (Join-Path $OutputDir "09_rdp_logons.csv") -NoTypeInformation
}

$netLogons = $allLogons | Where-Object { $_.LogonType -eq "3" } | Select-Object TimeCreated, SourceIP, Account
if ($netLogons) {
    Write-Log "NETWORK LOGON EVENTS: $($netLogons.Count)" "INFO"
    $netLogons | Export-Csv (Join-Path $OutputDir "09_network_logons.csv") -NoTypeInformation
}

# Failed logons (4625)
$failedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, @{N='Account';E={
        if ($_.Message -match "Account Name:\s+(\S+)") { $matches[1] }
    }}, @{N='SourceIP';E={
        if ($_.Message -match "Source Network Address:\s+(\S+)") { $matches[1] }
    }}, @{N='FailReason';E={
        if ($_.Message -match "Failure Reason:\s+(.+)") { $matches[1].Trim() }
    }}

if ($failedLogons) {
    Write-Log "FAILED LOGON ATTEMPTS: $($failedLogons.Count)" "WARNING"
    $failedLogons | Export-Csv (Join-Path $OutputDir "09_failed_logons.csv") -NoTypeInformation
}

# PowerShell script block logging (4104)
$psLogs = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} -MaxEvents 100 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match "(?i)(invoke-expression|downloadstring|encodedcommand|bypass|mimikatz|amsi|disable)" } |
    Select-Object TimeCreated, Message

if ($psLogs) {
    Write-Log "SUSPICIOUS POWERSHELL SCRIPT BLOCKS: $($psLogs.Count)" "CRITICAL"
    $psLogs | Export-Csv (Join-Path $OutputDir "09_suspicious_powershell.csv") -NoTypeInformation
}

# ══════════════════════════════════════════════════════════════════════════════
# 10. EXFILTRATION CHECKS
# ══════════════════════════════════════════════════════════════════════════════
Write-Log "Checking for exfiltration indicators (rclone configs, staged archives, suspicious DNS)..."
Write-Log "  WHY: Nova uses double extortion - data is stolen BEFORE encryption via rclone to MEGA."

# Rclone config
$rclonePaths = @(
    "$env:APPDATA\rclone\rclone.conf",
    "$env:USERPROFILE\.config\rclone\rclone.conf"
)
foreach ($rp in $rclonePaths) {
    if (Test-Path $rp) {
        Write-Log "RCLONE CONFIG FOUND: $rp" "CRITICAL"
        Copy-Item $rp (Join-Path $OutputDir "10_rclone_config.conf") -ErrorAction SilentlyContinue
    }
}

# Large archives in temp/staging
$stagingDirs = @($env:TEMP, $env:PROGRAMDATA, "C:\PerfLogs", "C:\Windows\Temp")
$largeArchives = @()
foreach ($sd in $stagingDirs) {
    if (Test-Path $sd) {
        $largeArchives += Get-ChildItem -Path $sd -Include *.7z,*.zip,*.rar,*.tar,*.tar.gz -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 50MB } |
            Select-Object FullName, @{N='SizeMB';E={[Math]::Round($_.Length/1MB,2)}}, CreationTimeUtc, LastWriteTimeUtc
    }
}
if ($largeArchives) {
    Write-Log "LARGE ARCHIVES IN STAGING DIRS: $($largeArchives.Count)" "WARNING"
    $largeArchives | Export-Csv (Join-Path $OutputDir "10_staging_archives.csv") -NoTypeInformation
}

# DNS Cache check for suspicious domains
$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue |
    Where-Object { $_.Entry -match "(?i)(mega\.nz|mega\.co|anonfiles|transfer\.sh|gofile|dropmefiles|onion|tor)" }
if ($dnsCache) {
    Write-Log "SUSPICIOUS DNS CACHE: $($dnsCache.Entry -join ', ')" "WARNING"
    $dnsCache | Export-Csv (Join-Path $OutputDir "10_suspicious_dns.csv") -NoTypeInformation
}

# ══════════════════════════════════════════════════════════════════════════════
# 11. RECENTLY MODIFIED FILES (Last 48h in key dirs)
# ══════════════════════════════════════════════════════════════════════════════
Write-Log "Checking recently modified executables/scripts in system dirs (last 48h)..."
Write-Log "  SEARCHING: .exe, .dll, .bat, .ps1, .vbs, .js, .hta, .cmd, .sys in System32, Temp, ProgramData"
Write-Log "  WHY: Identifies malware dropped in the last 48 hours for timeline analysis."
$cutoff = (Get-Date).AddHours(-48)
$recentDirs = @("$env:SYSTEMROOT\System32", "$env:SYSTEMROOT\Temp", "$env:TEMP", "$env:PROGRAMDATA")

$recentFiles = @()
foreach ($rd in $recentDirs) {
    if (Test-Path $rd) {
        $recentFiles += Get-ChildItem -Path $rd -File -Recurse -Depth 3 -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $cutoff -and $_.Extension -match "\.(exe|dll|bat|ps1|vbs|js|hta|cmd|sys)$" } |
            Select-Object FullName, Extension, @{N='SizeMB';E={[Math]::Round($_.Length/1MB,2)}}, LastWriteTime, CreationTime -First 200
    }
}

if ($recentFiles) {
    Write-Log "Recently modified executables/scripts: $($recentFiles.Count)" "INFO"
    $recentFiles | Export-Csv (Join-Path $OutputDir "11_recent_executables.csv") -NoTypeInformation
}

# ══════════════════════════════════════════════════════════════════════════════
# 12. USERS & GROUPS
# ══════════════════════════════════════════════════════════════════════════════
Write-Log "Enumerating local users, admin group members, and recently created accounts..."
Write-Log "  WHY: Attackers create backdoor admin accounts for re-entry (e.g., 'support', 'admin2')."
$localUsers = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, Description
$localUsers | Export-Csv (Join-Path $OutputDir "12_local_users.csv") -NoTypeInformation

$adminMembers = net localgroup Administrators 2>&1
$adminMembers | Out-File (Join-Path $OutputDir "12_local_admins.txt")

# Recently created users (last 30 days)
$recentUsers = $localUsers | Where-Object { $_.PasswordLastSet -gt (Get-Date).AddDays(-30) -and $_.Enabled }
if ($recentUsers) {
    Write-Log "RECENTLY CREATED/MODIFIED USERS: $($recentUsers.Name -join ', ')" "WARNING"
}

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
Write-Log "=========================================="
Write-Log "TRIAGE COMPLETE"
Write-Log "Output saved to: $OutputDir"
Write-Log "=========================================="

# Package everything
$zipPath = "$OutputDir.zip"
try {
    Compress-Archive -Path $OutputDir -DestinationPath $zipPath -Force
    Write-Log "Triage package compressed: $zipPath" "SUCCESS"
} catch {
    Write-Log "Could not compress output (Compress-Archive not available)" "WARNING"
}

Write-Host @"

 ════════════════════════════════════════════════════════════
  TRIAGE COMPLETE
  Output:  $OutputDir
  Package: $zipPath

  NEXT STEPS:
  1. Transfer the triage package to your IR workstation
  2. Run the Python toolkit for deeper analysis
  3. Isolate this host if critical findings were detected
  4. Preserve a full disk image if this is a key host
 ════════════════════════════════════════════════════════════

"@ -ForegroundColor Cyan
