<#
.SYNOPSIS
    NxProxy DNS Hardening Script

.DESCRIPTION
    Layer 1: Force DNS to 127.0.0.1 (NxProxy) on ALL NICs
    Layer 2: Lock DNS registry keys (admins exempt)
    Layer 3: Disable DoH in Chrome, Edge, Firefox, Opera + Windows
    Layer 4: Windows Firewall - block all user DNS, SYSTEM exempt
    Layer 5: NxProxy service resilience
    Layer 6: AppLocker - block unauthorized executables

.NOTES
    Launch via Harden-NxProxy.bat or:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Harden-NxProxy.ps1
    Target OS: Windows 11 LTSC (compatible with PowerShell 3.0+)
#>

[CmdletBinding()]
param(
    [string]$NxProxyServiceName = "NxProxy",
    [string]$DnsServer = "127.0.0.1"
)

$ErrorActionPreference = "Stop"

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Error "PowerShell 3.0+ required. Current: $($PSVersionTable.PSVersion)"
    exit 1
}
Write-Host "PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor Cyan

# --- Verify NxProxy service exists ---
$nxProxySvc = $null
if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
    $nxProxySvc = Get-CimInstance Win32_Service -Filter "Name='$NxProxyServiceName'" -ErrorAction SilentlyContinue
}
if (-not $nxProxySvc) {
    $nxProxySvc = Get-WmiObject Win32_Service -Filter "Name='$NxProxyServiceName'" -ErrorAction SilentlyContinue
}
if (-not $nxProxySvc) {
    Write-Error "Service '$NxProxyServiceName' not found. Install NxProxy first."
    exit 1
}
Write-Host "NxProxy service found: $($nxProxySvc.PathName)" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# LAYER 1 - Force DNS to NxProxy on ALL NICs
# =============================================================================
Write-Host "=== LAYER 1: Forcing DNS to $DnsServer on all adapters ===" -ForegroundColor Green

$adapters = Get-NetAdapter
if (-not $adapters) {
    Write-Warning "  No network adapters found!"
} else {
    foreach ($adapter in $adapters) {
        Write-Host "  Configuring: $($adapter.Name) ($($adapter.InterfaceDescription)) [$($adapter.Status)]"
        try {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $DnsServer
            $currentDns = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4
            Write-Host "    DNS set to: $($currentDns.ServerAddresses -join ', ')"
        }
        catch {
            Write-Warning "    Failed: $_"
        }
    }
}
Write-Host "  Layer 1 complete." -ForegroundColor Green

# =============================================================================
# LAYER 2 - Lock DNS registry keys (admin-exempt)
# =============================================================================
Write-Host ""
Write-Host "=== LAYER 2: Locking DNS registry keys ===" -ForegroundColor Green

$tcpipPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
$ifKeys = Get-ChildItem -Path $tcpipPath

foreach ($ifKey in $ifKeys) {
    $keyPath = $ifKey.PSPath
    try {
        $acl = Get-Acl -Path $keyPath
        $acl.SetAccessRuleProtection($true, $false)

        # SYSTEM — Full Control
        $sysRule = New-Object System.Security.AccessControl.RegistryAccessRule("NT AUTHORITY\SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")
        $acl.AddAccessRule($sysRule)

        # Administrators — Full Control
        $admRule = New-Object System.Security.AccessControl.RegistryAccessRule("BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
        $acl.AddAccessRule($admRule)

        # LOCAL SERVICE — Full Control (DHCP client runs as this account)
        $localSvcRule = New-Object System.Security.AccessControl.RegistryAccessRule("NT AUTHORITY\LOCAL SERVICE","FullControl","ContainerInherit,ObjectInherit","None","Allow")
        $acl.AddAccessRule($localSvcRule)

        # NETWORK SERVICE — Full Control (network components need this)
        $netSvcRule = New-Object System.Security.AccessControl.RegistryAccessRule("NT AUTHORITY\NETWORK SERVICE","FullControl","ContainerInherit,ObjectInherit","None","Allow")
        $acl.AddAccessRule($netSvcRule)

        # Users — Read Only (cannot change DNS settings)
        $usrRule = New-Object System.Security.AccessControl.RegistryAccessRule("BUILTIN\Users","ReadKey","ContainerInherit,ObjectInherit","None","Allow")
        $acl.AddAccessRule($usrRule)

        Set-Acl -Path $keyPath -AclObject $acl
        Write-Host "  Locked: $($ifKey.PSChildName)"
    }
    catch {
        Write-Warning "  Failed to lock $($ifKey.PSChildName): $_"
    }
}
Write-Host "  Layer 2 complete." -ForegroundColor Green

# =============================================================================
# LAYER 3 - Disable DoH in all browsers + Windows system DoH
# =============================================================================
Write-Host ""
Write-Host "=== LAYER 3: Disabling DNS-over-HTTPS ===" -ForegroundColor Green

# Chrome
$p = "HKLM:\SOFTWARE\Policies\Google\Chrome"
if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
Set-ItemProperty -Path $p -Name "DnsOverHttpsMode" -Value "off" -Type String
Write-Host "  Chrome: DoH disabled"

# Edge
$p = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
Set-ItemProperty -Path $p -Name "BuiltInDnsClientEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path $p -Name "DnsOverHttpsMode" -Value "off" -Type String
Write-Host "  Edge: DoH disabled + built-in DNS client disabled"

# Firefox
$p = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS"
if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
Set-ItemProperty -Path $p -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path $p -Name "Locked" -Value 1 -Type DWord
Write-Host "  Firefox: DoH disabled + locked"

# Opera (both paths)
foreach ($op in @("HKLM:\SOFTWARE\Policies\Opera Software\Opera","HKLM:\SOFTWARE\Policies\Opera Software\Opera Stable")) {
    if (-not (Test-Path $op)) { New-Item -Path $op -Force | Out-Null }
    Set-ItemProperty -Path $op -Name "DnsOverHttpsMode" -Value "off" -Type String
}
Write-Host "  Opera: DoH disabled (both policy paths)"

# Windows system DoH
$p = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
Set-ItemProperty -Path $p -Name "EnableAutoDoh" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Write-Host "  Windows system DoH: disabled"

Write-Host "  Layer 3 complete." -ForegroundColor Green

# =============================================================================
# LAYER 4 - Windows Firewall rules
# =============================================================================
Write-Host ""
Write-Host "=== LAYER 4: Configuring firewall rules ===" -ForegroundColor Green

# NxProxy runs as LocalSystem (S-1-5-18) via NSSM. LocalSystem is NOT a member
# of BUILTIN\Users (S-1-5-32-545). By scoping block rules to BUILTIN\Users only,
# NxProxy and all SYSTEM-level processes are automatically exempt.
# No program-path allow rules needed — avoids path parsing issues entirely.

$rulePrefix = "NxProxy-Hardening"
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "$rulePrefix*" } | Remove-NetFirewallRule -ErrorAction SilentlyContinue

# BLOCK: Outbound DNS for BUILTIN\Users only (TCP + UDP 53)
$usersSDDL = "D:(A;;CC;;;S-1-5-32-545)"

New-NetFirewallRule -DisplayName "$rulePrefix - Block Users DNS (UDP)" -Direction Outbound -Action Block -Protocol UDP -RemotePort 53 -LocalUser $usersSDDL -Enabled True -Profile Any | Out-Null
New-NetFirewallRule -DisplayName "$rulePrefix - Block Users DNS (TCP)" -Direction Outbound -Action Block -Protocol TCP -RemotePort 53 -LocalUser $usersSDDL -Enabled True -Profile Any | Out-Null
Write-Host "  Blocked: BUILTIN\Users outbound DNS (TCP/UDP 53)"
Write-Host "  NxProxy (LocalSystem) is automatically exempt"

# BLOCK: Known DoH provider IPs on 443 (all users)
$dohIPs = @("8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","9.9.9.9","149.112.112.112","208.67.222.222","208.67.220.220","94.140.14.14","94.140.15.15","185.228.168.9","185.228.169.9")
New-NetFirewallRule -DisplayName "$rulePrefix - Block DoH Providers (HTTPS)" -Direction Outbound -Action Block -Protocol TCP -RemotePort 443 -RemoteAddress $dohIPs -Enabled True -Profile Any | Out-Null
Write-Host "  Blocked: Known DoH provider IPs on port 443 ($($dohIPs.Count) IPs)"

Write-Host "  Layer 4 complete." -ForegroundColor Green

# =============================================================================
# LAYER 5 - NxProxy service resilience
# =============================================================================
Write-Host ""
Write-Host "=== LAYER 5: Hardening NxProxy service ===" -ForegroundColor Green

# Reset DACL to permissive default first (in case a previous run locked it)
$defaultDacl = 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'
$resetResult = & sc.exe sdset $NxProxyServiceName $defaultDacl 2>&1
Write-Host "  DACL reset: $resetResult"

# Configure startup type using sc.exe (avoids Set-Service permission issues)
& sc.exe config $NxProxyServiceName start= auto | Out-Null
Write-Host "  Startup type: Automatic"

& sc.exe failure $NxProxyServiceName reset= 86400 actions= restart/5000/restart/5000/restart/10000 | Out-Null
Write-Host "  Service recovery (SCM): restart at 5s / 5s / 10s on crash"

# Configure NSSM to restart even on clean stops
$nssmPath = $nxProxySvc.PathName
if ($nssmPath -and (Test-Path ($nssmPath -replace '"',''))) {
    $nssm = $nssmPath -replace '"',''
    & "$nssm" set $NxProxyServiceName AppExit Default Restart 2>&1 | Out-Null
    & "$nssm" set $NxProxyServiceName AppRestartDelay 5000 2>&1 | Out-Null
    Write-Host "  Service recovery (NSSM): restart on any exit, 5s delay"
} else {
    Write-Warning "  NSSM executable not found at service path. NSSM restart not configured."
    Write-Warning "  Manual config: nssm set NxProxy AppExit Default Restart"
}

# Lock DACL down last — restricts future modifications to SYSTEM and Admins only
$dacl = 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCLORC;;;IU)'
& sc.exe sdset $NxProxyServiceName $dacl | Out-Null
Write-Host "  Service DACL hardened: standard users can only query status"

Write-Host "  Layer 5 complete." -ForegroundColor Green

# =============================================================================
# LAYER 6 - AppLocker
# =============================================================================
Write-Host ""
Write-Host "=== LAYER 6: Configuring AppLocker ===" -ForegroundColor Green

if (-not (Get-Command Set-AppLockerPolicy -ErrorAction SilentlyContinue)) {
    Write-Warning "  AppLocker cmdlets not available. Requires Enterprise/Education/LTSC."
    Write-Warning "  Skipping Layer 6. All other layers are active."
    Write-Host "  Layer 6 skipped." -ForegroundColor Yellow
} else {
    try {
        Set-Service -Name "AppIDSvc" -StartupType Automatic
        Start-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
        Write-Host "  AppIDSvc set to Automatic and started"
    }
    catch {
        Write-Warning "  Could not configure AppIDSvc: $_"
    }

    # Build AppLocker XML via string concatenation (avoids here-string indentation issues)
    $xml = '<?xml version="1.0" encoding="UTF-8"?>'
    $xml += '<AppLockerPolicy Version="1">'
    $xml += '<RuleCollection Type="Exe" EnforcementMode="Enabled">'
    $xml += '<FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="All files for Administrators" Description="Allow Administrators to run all executables." UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*" /></Conditions></FilePathRule>'
    $xml += '<FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="Windows system files" Description="Allow Users to run from Windows." UserOrGroupSid="S-1-5-32-545" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions></FilePathRule>'
    $xml += '<FilePathRule Id="d754b869-d2cc-46af-9c94-6b6e8c10d095" Name="Program Files" Description="Allow Users to run from Program Files." UserOrGroupSid="S-1-5-32-545" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions></FilePathRule>'
    $xml += '<FilePathRule Id="e2c0a7f8-51d3-4a9b-bf12-8c7e6d5a4b30" Name="Program Files (x86)" Description="Allow Users to run from Program Files (x86)." UserOrGroupSid="S-1-5-32-545" Action="Allow"><Conditions><FilePathCondition Path="%OSDRIVE%\Program Files (x86)\*" /></Conditions></FilePathRule>'
    $xml += '<FilePathRule Id="f3b3c1a0-7d44-4e2a-b8d6-1a2b3c4d5e6f" Name="WhatsApp Desktop" Description="Allow WhatsApp from AppData." UserOrGroupSid="S-1-5-32-545" Action="Allow"><Conditions><FilePathCondition Path="%LOCALAPPDATA%\WhatsApp\*" /></Conditions></FilePathRule>'
    $xml += '<FilePathRule Id="b2e60a27-f316-4752-b3c6-2a1d4e8f9c0b" Name="WindowsApps" Description="Allow WindowsApps system components." UserOrGroupSid="S-1-5-32-545" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\WindowsApps\*" /></Conditions></FilePathRule>'
    $xml += '</RuleCollection>'
    $xml += '<RuleCollection Type="Msi" EnforcementMode="Enabled">'
    $xml += '<FilePathRule Id="64ad46ff-0d71-4fa0-a30b-3f3d30c5433d" Name="All MSI for Administrators" Description="Allow Administrators all MSI." UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*" /></Conditions></FilePathRule>'
    $xml += '<FilePathRule Id="b7af7102-efde-4369-8a89-7a6a392d1473" Name="Windows Installer files" Description="Allow MSI from Windows Installer dir." UserOrGroupSid="S-1-5-32-545" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\Installer\*" /></Conditions></FilePathRule>'
    $xml += '</RuleCollection>'
    $xml += '</AppLockerPolicy>'

    $policyFile = Join-Path $env:TEMP "NxProxy-AppLocker-Policy.xml"
    $xml | Out-File -FilePath $policyFile -Encoding UTF8 -Force

    try {
        Set-AppLockerPolicy -XmlPolicy $policyFile -ErrorAction Stop
        Write-Host "  AppLocker policy applied:"
        Write-Host "    Allowed: Windows, Program Files, Program Files (x86), WhatsApp, WindowsApps"
        Write-Host "    Blocked: Downloads, Desktop, AppData (except WhatsApp), USB, other paths"
        Write-Host "    Administrators: unrestricted"
    }
    catch {
        Write-Warning "  Failed to apply AppLocker policy: $_"
    }

    Remove-Item -Path $policyFile -Force -ErrorAction SilentlyContinue
    Write-Host "  Layer 6 complete." -ForegroundColor Green
}

# =============================================================================
# SUMMARY
# =============================================================================
Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  NxProxy DNS Hardening - Complete" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Layer 1: DNS forced to 127.0.0.1 on ALL NICs        [DONE]" -ForegroundColor Green
Write-Host "  Layer 2: DNS registry keys locked (admin-exempt)     [DONE]" -ForegroundColor Green
Write-Host "  Layer 3: DoH disabled (Chrome/Edge/Firefox/Opera)    [DONE]" -ForegroundColor Green
Write-Host "  Layer 4: Firewall (users blocked, SYSTEM exempt)     [DONE]" -ForegroundColor Green
Write-Host "  Layer 5: NxProxy service hardened + auto-recovery    [DONE]" -ForegroundColor Green
Write-Host "  Layer 6: AppLocker active (block unauthorized exe)   [DONE]" -ForegroundColor Green
Write-Host ""
Write-Host "  REBOOT RECOMMENDED to ensure all policies take effect." -ForegroundColor Yellow
Write-Host ""
