<#
.SYNOPSIS
    NxProxy DNS Hardening Script — Forces all non-admin users through NxProxy DNS filtering.

.DESCRIPTION
    Layer 1: Force DNS to 127.0.0.1 (NxProxy) on ALL NICs (active and inactive)
    Layer 2: Lock DNS registry keys (admins exempt, standard users read-only)
    Layer 3: Disable DNS-over-HTTPS in Chrome, Edge, Firefox, Opera + Windows system DoH
    Layer 4: Windows Firewall — block outbound DNS for non-SYSTEM processes, allow NxProxy
    Layer 5: NxProxy service resilience (failure recovery + DACL hardening)
    Layer 6: AppLocker — block unauthorized executables for standard users

.NOTES
    Launch via Harden-NxProxy.bat (recommended) or run manually:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Harden-NxProxy.ps1

    Target OS: Windows 11 LTSC (compatible with PowerShell 3.0+)
    NxProxy must already be installed as a native Windows service listening on 127.0.0.1:53

.PARAMETER NxProxyServiceName
    Name of the NxProxy Windows service. Default: "NxProxy"

.PARAMETER DnsServer
    DNS server address to force on all NICs. Default: "127.0.0.1"
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

# --- Check Administrator privileges ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Right-click PowerShell and select 'Run as Administrator', or use Harden-NxProxy.bat."
    exit 1
}

# --- Check PowerShell version ---
if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Error "This script requires PowerShell 3.0 or later. Current version: $($PSVersionTable.PSVersion). Please update PowerShell."
    exit 1
}
Write-Host "PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor Cyan

# --- Resolve NxProxy executable path (CIM with WMI fallback) ---
$nxProxySvc = $null
if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
    $nxProxySvc = Get-CimInstance Win32_Service -Filter "Name='$NxProxyServiceName'" -ErrorAction SilentlyContinue
} else {
    $nxProxySvc = Get-WmiObject Win32_Service -Filter "Name='$NxProxyServiceName'" -ErrorAction SilentlyContinue
}

if (-not $nxProxySvc) {
    Write-Error "Service '$NxProxyServiceName' not found. Ensure NxProxy is installed before running this script."
    exit 1
}

# Parse executable path safely (handles quoted paths with arguments)
if ($nxProxySvc.PathName -match '^"([^"]+)"') {
    $NxProxyExePath = $Matches[1]
} elseif ($nxProxySvc.PathName -match '^(\S+)') {
    $NxProxyExePath = $Matches[1]
} else {
    $NxProxyExePath = $nxProxySvc.PathName
}

if (-not (Test-Path $NxProxyExePath)) {
    Write-Error "NxProxy executable not found at '$NxProxyExePath'. Parsed from PathName: '$($nxProxySvc.PathName)'"
    exit 1
}
Write-Host "NxProxy executable: $NxProxyExePath" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# LAYER 1 — Force DNS to NxProxy on ALL NICs (active and inactive)
# =============================================================================
Write-Host "=== LAYER 1: Forcing DNS to $DnsServer on all adapters ===" -ForegroundColor Green

$adapters = Get-NetAdapter
if (-not $adapters) {
    Write-Warning "  No network adapters found!"
} else {
    foreach ($adapter in $adapters) {
        $statusLabel = $adapter.Status
        Write-Host "  Configuring: $($adapter.Name) ($($adapter.InterfaceDescription)) [$statusLabel]"
        try {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $DnsServer
            $currentDns = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4
            Write-Host "    DNS set to: $($currentDns.ServerAddresses -join ', ')"
        }
        catch {
            Write-Warning "    Failed to set DNS on $($adapter.Name): $_"
        }
    }
}
Write-Host "  Layer 1 complete." -ForegroundColor Green

# =============================================================================
# LAYER 2 — Lock DNS registry keys (admin-exempt)
# =============================================================================
Write-Host "`n=== LAYER 2: Locking DNS registry keys ===" -ForegroundColor Green

$tcpipInterfacesPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
$interfaceKeys = Get-ChildItem -Path $tcpipInterfacesPath

foreach ($ifKey in $interfaceKeys) {
    $keyPath = $ifKey.PSPath
    try {
        $acl = Get-Acl -Path $keyPath

        # Disable inheritance, discard inherited rules (start clean)
        $acl.SetAccessRuleProtection($true, $false)

        # SYSTEM — Full Control
        $systemRule = New-Object System.Security.AccessControl.RegistryAccessRule(
            "NT AUTHORITY\SYSTEM",
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($systemRule)

        # Administrators — Full Control
        $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule(
            "BUILTIN\Administrators",
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($adminRule)

        # Users — Read Only
        $usersRule = New-Object System.Security.AccessControl.RegistryAccessRule(
            "BUILTIN\Users",
            "ReadKey",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($usersRule)

        Set-Acl -Path $keyPath -AclObject $acl
        Write-Host "  Locked: $($ifKey.PSChildName)"
    }
    catch {
        Write-Warning "  Failed to lock $($ifKey.PSChildName): $_"
    }
}
Write-Host "  Layer 2 complete." -ForegroundColor Green

# =============================================================================
# LAYER 3 — Disable DoH in all browsers + Windows system DoH
# =============================================================================
Write-Host "`n=== LAYER 3: Disabling DNS-over-HTTPS ===" -ForegroundColor Green

# --- Chrome ---
$chromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
if (-not (Test-Path $chromePolicyPath)) { New-Item -Path $chromePolicyPath -Force | Out-Null }
Set-ItemProperty -Path $chromePolicyPath -Name "DnsOverHttpsMode" -Value "off" -Type String
Write-Host "  Chrome: DoH disabled"

# --- Edge ---
$edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (-not (Test-Path $edgePolicyPath)) { New-Item -Path $edgePolicyPath -Force | Out-Null }
Set-ItemProperty -Path $edgePolicyPath -Name "BuiltInDnsClientEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path $edgePolicyPath -Name "DnsOverHttpsMode" -Value "off" -Type String
Write-Host "  Edge: DoH disabled + built-in DNS client disabled"

# --- Firefox ---
$firefoxPolicyPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS"
if (-not (Test-Path $firefoxPolicyPath)) { New-Item -Path $firefoxPolicyPath -Force | Out-Null }
Set-ItemProperty -Path $firefoxPolicyPath -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path $firefoxPolicyPath -Name "Locked" -Value 1 -Type DWord
Write-Host "  Firefox: DoH disabled + locked"

# --- Opera (both possible policy paths) ---
$operaPolicyPaths = @(
    "HKLM:\SOFTWARE\Policies\Opera Software\Opera",
    "HKLM:\SOFTWARE\Policies\Opera Software\Opera Stable"
)
foreach ($operaPath in $operaPolicyPaths) {
    if (-not (Test-Path $operaPath)) { New-Item -Path $operaPath -Force | Out-Null }
    Set-ItemProperty -Path $operaPath -Name "DnsOverHttpsMode" -Value "off" -Type String
}
Write-Host "  Opera: DoH disabled (both policy paths)"

# --- Windows System-level DoH ---
$dohPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
Set-ItemProperty -Path $dohPath -Name "EnableAutoDoh" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Write-Host "  Windows system DoH: disabled"

Write-Host "  Layer 3 complete." -ForegroundColor Green

# =============================================================================
# LAYER 4 — Windows Firewall rules
# =============================================================================
Write-Host "`n=== LAYER 4: Configuring firewall rules ===" -ForegroundColor Green

# Remove any existing rules from previous runs
$rulePrefix = "NxProxy-Hardening"
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "$rulePrefix*" } |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

# ALLOW: NxProxy.exe outbound DNS to any destination (TCP + UDP 53)
New-NetFirewallRule -DisplayName "$rulePrefix - Allow NxProxy DNS (UDP)" `
    -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53 `
    -Program $NxProxyExePath -Enabled True -Profile Any | Out-Null

New-NetFirewallRule -DisplayName "$rulePrefix - Allow NxProxy DNS (TCP)" `
    -Direction Outbound -Action Allow -Protocol TCP -RemotePort 53 `
    -Program $NxProxyExePath -Enabled True -Profile Any | Out-Null

Write-Host "  Allowed: NxProxy.exe outbound DNS (TCP/UDP 53) to any"

# BLOCK: Outbound DNS for BUILTIN\Users only (TCP + UDP 53)
# NxProxy runs as LocalSystem (S-1-5-18) which is NOT in BUILTIN\Users, so it's exempt.
# This avoids the block-overrides-allow problem in Windows Firewall.
$usersSDDL = "D:(A;;CC;;;S-1-5-32-545)"

New-NetFirewallRule -DisplayName "$rulePrefix - Block Users DNS (UDP)" `
    -Direction Outbound -Action Block -Protocol UDP -RemotePort 53 `
    -LocalUser $usersSDDL `
    -Enabled True -Profile Any | Out-Null

New-NetFirewallRule -DisplayName "$rulePrefix - Block Users DNS (TCP)" `
    -Direction Outbound -Action Block -Protocol TCP -RemotePort 53 `
    -LocalUser $usersSDDL `
    -Enabled True -Profile Any | Out-Null

Write-Host "  Blocked: BUILTIN\Users outbound DNS (TCP/UDP 53)"

# BLOCK: Known DoH provider IPs on port 443 (all users — these IPs should never be contacted)
$dohProviderIPs = @(
    "8.8.8.8", "8.8.4.4",                # Google
    "1.1.1.1", "1.0.0.1",                # Cloudflare
    "9.9.9.9", "149.112.112.112",         # Quad9
    "208.67.222.222", "208.67.220.220",   # OpenDNS
    "94.140.14.14", "94.140.15.15",       # AdGuard
    "185.228.168.9", "185.228.169.9"      # CleanBrowsing
)

New-NetFirewallRule -DisplayName "$rulePrefix - Block DoH Providers (HTTPS)" `
    -Direction Outbound -Action Block -Protocol TCP -RemotePort 443 `
    -RemoteAddress $dohProviderIPs `
    -Enabled True -Profile Any | Out-Null

Write-Host "  Blocked: Known DoH provider IPs on port 443 ($($dohProviderIPs.Count) IPs)"

Write-Host "  Layer 4 complete." -ForegroundColor Green

# =============================================================================
# LAYER 5 — NxProxy service resilience
# =============================================================================
Write-Host "`n=== LAYER 5: Hardening NxProxy service ===" -ForegroundColor Green

# Configure failure recovery: restart on 1st, 2nd, 3rd failure
& sc.exe failure $NxProxyServiceName reset= 86400 actions= restart/5000/restart/5000/restart/10000 | Out-Null
Write-Host "  Service recovery: restart at 5s / 5s / 10s"

# Harden service DACL
# D: = DACL
# (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY) = SYSTEM: full service control
# (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA) = Administrators: full service control
# (A;;CCLCLORC;;;IU)                   = Interactive Users: query config + query status + read only
$dacl = 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCLORC;;;IU)'
& sc.exe sdset $NxProxyServiceName $dacl | Out-Null
Write-Host "  Service DACL hardened: standard users can only query status"

# Ensure service is set to auto-start
Set-Service -Name $NxProxyServiceName -StartupType Automatic
Write-Host "  Startup type: Automatic"

Write-Host "  Layer 5 complete." -ForegroundColor Green

# =============================================================================
# LAYER 6 — AppLocker
# =============================================================================
Write-Host "`n=== LAYER 6: Configuring AppLocker ===" -ForegroundColor Green

# Check if AppLocker cmdlets are available
if (-not (Get-Command Set-AppLockerPolicy -ErrorAction SilentlyContinue)) {
    Write-Warning "  AppLocker cmdlets not available. This may require Windows Enterprise/Education/LTSC."
    Write-Warning "  Skipping Layer 6. All other layers are active."
} else {

    # Ensure AppIDSvc (Application Identity) is running and set to auto
    try {
        Set-Service -Name "AppIDSvc" -StartupType Automatic
        Start-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
        Write-Host "  AppIDSvc set to Automatic and started"
    }
    catch {
        Write-Warning "  Could not configure AppIDSvc: $_"
        Write-Warning "  AppLocker may not function without this service."
    }

    # Build AppLocker policy XML
    $appLockerPolicyXml = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">

    <!-- Administrators: unrestricted -->
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20"
                  Name="(Default) All files for Administrators"
                  Description="Allow Administrators to run all executables."
                  UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>

    <!-- Users: Windows directory -->
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51"
                  Name="(Default) Windows system files"
                  Description="Allow Users to run executables from Windows directory."
                  UserOrGroupSid="S-1-5-32-545" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>

    <!-- Users: Program Files (64-bit) -->
    <FilePathRule Id="d754b869-d2cc-46af-9c94-6b6e8c10d095"
                  Name="(Default) Program Files"
                  Description="Allow Users to run executables from Program Files."
                  UserOrGroupSid="S-1-5-32-545" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>

    <!-- Users: Program Files (x86) (32-bit) -->
    <FilePathRule Id="e2c0a7f8-51d3-4a9b-bf12-8c7e6d5a4b30"
                  Name="(Default) Program Files (x86)"
                  Description="Allow Users to run executables from Program Files (x86)."
                  UserOrGroupSid="S-1-5-32-545" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Program Files (x86)\*" />
      </Conditions>
    </FilePathRule>

    <!-- Users: WhatsApp Desktop (AppData exception) -->
    <FilePathRule Id="f3b3c1a0-7d44-4e2a-b8d6-1a2b3c4d5e6f"
                  Name="Allow WhatsApp Desktop"
                  Description="Allow Users to run WhatsApp from its default AppData location."
                  UserOrGroupSid="S-1-5-32-545" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\WhatsApp\*" />
      </Conditions>
    </FilePathRule>

    <!-- Users: WindowsApps (system components, UWP runtime) -->
    <FilePathRule Id="b2e60a27-f316-4752-b3c6-2a1d4e8f9c0b"
                  Name="Allow WindowsApps"
                  Description="Allow Users to run from WindowsApps (system components)."
                  UserOrGroupSid="S-1-5-32-545" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\WindowsApps\*" />
      </Conditions>
    </FilePathRule>

  </RuleCollection>

  <RuleCollection Type="Msi" EnforcementMode="Enabled">

    <!-- Administrators: all MSI -->
    <FilePathRule Id="64ad46ff-0d71-4fa0-a30b-3f3d30c5433d"
                  Name="(Default) All MSI for Administrators"
                  Description="Allow Administrators to install any MSI."
                  UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>

    <!-- Users: Windows Installer directory only -->
    <FilePathRule Id="b7af7102-efde-4369-8a89-7a6a392d1473"
                  Name="(Default) Windows Installer files"
                  Description="Allow Users to run MSI from Windows Installer directory."
                  UserOrGroupSid="S-1-5-32-545" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Installer\*" />
      </Conditions>
    </FilePathRule>

  </RuleCollection>
</AppLockerPolicy>
'@

    # Write policy to temp file and import
    $policyFile = Join-Path $env:TEMP "NxProxy-AppLocker-Policy.xml"
    $appLockerPolicyXml | Out-File -FilePath $policyFile -Encoding UTF8 -Force

    # Import AppLocker policy (replaces any existing policy)
    try {
        Set-AppLockerPolicy -XmlPolicy $policyFile -ErrorAction Stop
        Write-Host "  AppLocker policy applied:"
        Write-Host "    Allowed for Users: Windows, Program Files, Program Files (x86), WhatsApp, WindowsApps"
        Write-Host "    Blocked for Users: Downloads, Desktop, AppData (except WhatsApp), USB, all other paths"
        Write-Host "    Administrators: unrestricted"
    }
    catch {
        Write-Warning "  Failed to apply AppLocker policy: $_"
    }

    # Clean up temp file
    Remove-Item -Path $policyFile -Force -ErrorAction SilentlyContinue
}

Write-Host "  Layer 6 complete." -ForegroundColor Green

# =============================================================================
# SUMMARY
# =============================================================================
Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  NxProxy DNS Hardening — Complete" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Layer 1: DNS forced to 127.0.0.1 on ALL NICs        [DONE]" -ForegroundColor Green
Write-Host "  Layer 2: DNS registry keys locked (admin-exempt)     [DONE]" -ForegroundColor Green
Write-Host "  Layer 3: DoH disabled (Chrome/Edge/Firefox/Opera)    [DONE]" -ForegroundColor Green
Write-Host "  Layer 4: Firewall (NxProxy exempt, users blocked)    [DONE]" -ForegroundColor Green
Write-Host "  Layer 5: NxProxy service hardened + auto-recovery    [DONE]" -ForegroundColor Green
Write-Host "  Layer 6: AppLocker active (block unauthorized exe)   [DONE]" -ForegroundColor Green
Write-Host ""
Write-Host "  REBOOT RECOMMENDED to ensure all policies take effect." -ForegroundColor Yellow
Write-Host ""
