/*
    YARA Rules for Nova (RALord) Ransomware Detection
    Author:  IR Team
    Date:    2026-02-09
    Version: 1.0
    
    References:
    - Xcitium ThreatLabs Nova Analysis
    - Cyble RALord Threat Profile
    - CYFIRMA April 2025 Ransomware Tracking
*/

rule Nova_RALord_Ransom_Note
{
    meta:
        description = "Detects Nova/RALord ransomware ransom notes"
        author      = "IR Team"
        severity    = "critical"
        mitre       = "T1486"
    
    strings:
        $tox1 = "8E9A6195A769FE7115F087C61D75CF32874C339B3AB0947D07480C9A8A12DA5009151BE6A51F" ascii wide nocase
        $token1 = "054f55ec93aca9bac362b9d91eff36a7ce451e7caba47c0b2e004ba429f9529c79" ascii wide nocase
        $onion1 = "novavdivko2zvtrvtllnq45lxhba2rfzp76qigb4nrliklem5au7czqd" ascii wide nocase
        $onion2 = "pifk3xu3vad6cuxsjll4qjomyaaaoyvnyqppro75pazadzctrrvpdnyd" ascii wide nocase
        $onion3 = "novadmrkp4vbk2padk5t6pb" ascii wide nocase
        $brand1 = "Nova" ascii wide
        $brand2 = "RALord" ascii wide nocase
        $msg1   = "your files have been encrypted" ascii wide nocase
        $msg2   = "data has been stolen" ascii wide nocase
        $msg3   = "qtox" ascii wide nocase
    
    condition:
        any of ($tox*, $token*, $onion*) or
        (any of ($brand*) and any of ($msg*))
}

rule Nova_RALord_Encrypted_File
{
    meta:
        description = "Detects files encrypted by Nova/RALord (by extension marker)"
        author      = "IR Team"
        severity    = "critical"
        mitre       = "T1486"
    
    strings:
        $marker1 = ".ralord" ascii wide
        $marker2 = "RALORD" ascii wide
        $marker3 = "NOVA_ENCRYPTED" ascii wide
    
    condition:
        any of them at (filesize - 32) or
        any of them at 0
}

rule Nova_RALord_Payload_Windows
{
    meta:
        description = "Detects Nova/RALord Rust-based ransomware payload (Windows PE)"
        author      = "IR Team"
        severity    = "critical"
        mitre       = "T1486"
        hash_sha256 = "456b9adaabae9f3dce2207aa71410987f0a571cd8c11f2e7b41468501a863606"
        hash_md5    = "be15f62d14d1cbe2aecce8396f4c6289"
    
    strings:
        $rust1 = "rust_begin_unwind" ascii
        $rust2 = ".rlib" ascii
        $rust3 = "core::panicking" ascii
        
        $enc1  = "encrypt" ascii nocase
        $enc2  = ".ralord" ascii
        $enc3  = "AES" ascii
        $enc4  = "ChaCha" ascii
        $enc5  = "RSA" ascii
        
        $del1  = "vssadmin delete shadows" ascii wide nocase
        $del2  = "wmic shadowcopy delete" ascii wide nocase
        $del3  = "bcdedit /set" ascii wide nocase
        $del4  = "wbadmin delete" ascii wide nocase
        
        $svc1  = "sc stop" ascii wide nocase
        $svc2  = "net stop" ascii wide nocase
        $svc3  = "taskkill" ascii wide nocase
    
    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        any of ($rust*) and
        (any of ($enc*) and any of ($del*)) or
        (any of ($enc*) and any of ($svc*))
}

rule Nova_RALord_Payload_Linux
{
    meta:
        description = "Detects Nova/RALord Linux/ESXi ransomware payload"
        author      = "IR Team"
        severity    = "critical"
        mitre       = "T1486"
    
    strings:
        $rust1 = "rust_begin_unwind" ascii
        $rust2 = "core::panicking" ascii
        
        $enc1  = ".ralord" ascii
        $enc2  = "encrypt" ascii nocase
        
        $esxi1 = "esxcli" ascii
        $esxi2 = "vim-cmd" ascii
        $esxi3 = ".vmdk" ascii
        $esxi4 = ".vmx" ascii
        
        $lin1  = "/etc/shadow" ascii
        $lin2  = "/proc/" ascii
        $lin3  = "chmod" ascii
    
    condition:
        uint32(0) == 0x464C457F and
        filesize < 20MB and
        any of ($rust*) and
        any of ($enc*) and
        (any of ($esxi*) or any of ($lin*))
}

rule Nova_Shadow_Copy_Deletion
{
    meta:
        description = "Detects shadow copy deletion commands commonly used by Nova"
        author      = "IR Team"
        severity    = "high"
        mitre       = "T1490"
    
    strings:
        $cmd1 = "vssadmin delete shadows /all /quiet" ascii wide nocase
        $cmd2 = "wmic shadowcopy delete" ascii wide nocase
        $cmd3 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $cmd4 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $cmd5 = "wbadmin delete catalog -quiet" ascii wide nocase
        $cmd6 = "wbadmin delete systemstatebackup -keepversions:0" ascii wide nocase
    
    condition:
        2 of them
}

rule Nova_Defense_Evasion_Script
{
    meta:
        description = "Detects scripts used by Nova to disable security products"
        author      = "IR Team"
        severity    = "high"
        mitre       = "T1562"
    
    strings:
        $ps1 = "Set-MpPreference -DisableRealtimeMonitoring" ascii wide nocase
        $ps2 = "Set-MpPreference -DisableBehaviorMonitoring" ascii wide nocase
        $ps3 = "Set-MpPreference -DisableIOAVProtection" ascii wide nocase
        $ps4 = "Set-MpPreference -ExclusionPath" ascii wide nocase
        $ps5 = "Set-MpPreference -ExclusionExtension" ascii wide nocase
        $ps6 = "Disable-WindowsOptionalFeature -Online -FeatureName Windows-Defender" ascii wide nocase
        $ps7 = "Uninstall-WindowsFeature" ascii wide nocase
        
        $reg1 = "DisableAntiSpyware" ascii wide nocase
        $reg2 = "DisableRealtimeMonitoring" ascii wide nocase
        $reg3 = "TamperProtection" ascii wide nocase
        
        $svc1 = "sc config WinDefend start= disabled" ascii wide nocase
        $svc2 = "net stop WinDefend" ascii wide nocase
        $svc3 = "net stop MBAMService" ascii wide nocase
        $svc4 = "net stop SepMasterService" ascii wide nocase
        $svc5 = "net stop McAfeeFramework" ascii wide nocase
    
    condition:
        2 of them
}

rule Nova_Exfiltration_Rclone_Config
{
    meta:
        description = "Detects rclone config files potentially planted by Nova for data exfiltration"
        author      = "IR Team"
        severity    = "high"
        mitre       = "T1048"
    
    strings:
        $header = "[" ascii
        $type1  = "type = mega" ascii nocase
        $type2  = "type = s3" ascii nocase
        $type3  = "type = ftp" ascii nocase
        $type4  = "type = sftp" ascii nocase
        $type5  = "type = dropbox" ascii nocase
        $type6  = "type = onedrive" ascii nocase
        $type7  = "type = drive" ascii nocase
        $type8  = "type = b2" ascii nocase
        $pass   = "pass =" ascii nocase
    
    condition:
        filesize < 10KB and
        $header and $pass and
        any of ($type*)
}

rule Nova_Lateral_Movement_Batch
{
    meta:
        description = "Detects batch scripts used for Nova lateral movement and propagation"
        author      = "IR Team"
        severity    = "high"
        mitre       = "T1021"
    
    strings:
        $psexec = "psexec" ascii wide nocase
        $wmic1  = "wmic /node:" ascii wide nocase
        $wmic2  = "process call create" ascii wide nocase
        $copy1  = "copy " ascii wide nocase
        $admin  = "admin$" ascii wide nocase
        $c_share = "c$" ascii wide nocase
        $ipc    = "ipc$" ascii wide nocase
        $schtask = "schtasks /create" ascii wide nocase
        $net1   = "net use" ascii wide nocase
        
        $loop1  = "for /f" ascii wide nocase
        $loop2  = "for /L" ascii wide nocase
        $ip_pat = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/ ascii
    
    condition:
        filesize < 50KB and
        (any of ($psexec, $wmic1, $wmic2) and any of ($admin, $c_share, $ipc)) or
        ($schtask and $net1 and any of ($loop*)) or
        (any of ($copy*) and any of ($admin, $c_share) and $ip_pat)
}
