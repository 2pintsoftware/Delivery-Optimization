<#
.SYNOPSIS
    Troubleshoots Delivery Optimization (DO) on a Windows client.

.DESCRIPTION
    Performs a comprehensive health check of Delivery Optimization by:
    - Checking the DO service status and configuration
    - Querying the DO cloud service API chain (Geo → KeyValue → ContentPolicy → Discovery → PiecesHash)
    - Inspecting local DO cache, active downloads, and performance counters
    - Correlating local cache entries with remote service data
    - Checking network connectivity, VPN detection, and firewall/proxy indicators
    - Validating content integrity via PiecesHash manifests
    - Checking DO-related Group Policy and MDM settings

    Outputs a structured report with PASS/WARN/FAIL indicators.

.PARAMETER MaxCacheEntries
    Maximum number of local cache entries to inspect against the remote API. Default: 5

.PARAMETER SkipRemoteAPI
    Skip all remote API calls (useful for offline diagnostics).

.PARAMETER ExportPath
    If specified, exports the full report to a JSON file at this path.

.EXAMPLE
    .\Invoke-DOTroubleshoot.ps1

.EXAMPLE
    .\Invoke-DOTroubleshoot.ps1 -MaxCacheEntries 10 -ExportPath C:\temp\do-report.json

.EXAMPLE
    .\Invoke-DOTroubleshoot.ps1 -SkipRemoteAPI

.NOTES
    Version:        1.0
    Author:         Mattias Benninge @ 2Pint Software
    Creation Date:  2026-05-15
    Purpose/Change: Initial script development
    
    Requires Windows 10/11 with Delivery Optimization.
    Some checks require elevated (admin) privileges.
    Remote API endpoints are NOT officially documented by Microsoft.
#>
[CmdletBinding()]
param(
    [int]$MaxCacheEntries = 5,
    [switch]$SkipRemoteAPI,
    [string]$ExportPath
)

$ErrorActionPreference = 'Continue'
$script:Report = [ordered]@{}
$script:Checks = New-Object System.Collections.Generic.List[object]

#region Helper Functions

function Write-Check {
    param(
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO', 'SKIP')]
        [string]$Status,
        [string]$Category,
        [string]$Check,
        [string]$Detail,
        [object]$Data
    )
    $colors = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan'; SKIP = 'DarkGray' }
    $symbol = @{ PASS = '[+]'; WARN = '[!]'; FAIL = '[-]'; INFO = '[i]'; SKIP = '[~]' }

    Write-Host "  $($symbol[$Status]) " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host "$Check" -ForegroundColor White -NoNewline
    if ($Detail) { Write-Host " - $Detail" -ForegroundColor Gray } else { Write-Host }

    $script:Checks.Add([PSCustomObject]@{
            Status   = $Status
            Category = $Category
            Check    = $Check
            Detail   = $Detail
            Data     = $Data
        })
}

function Format-Bytes {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes bytes"
}

function Format-Bps {
    param([long]$Bps)
    if ($Bps -ge 1000000) { return "{0:N1} Mbps" -f ($Bps / 1000000) }
    if ($Bps -ge 1000) { return "{0:N1} Kbps" -f ($Bps / 1000) }
    return "$Bps bps"
}

function Test-IsAdmin {
    try {
        return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

# DO-specific error code lookup (from Microsoft's DeliveryOptimizationTroubleshooter)
$script:DOErrorCodes = @{
    0x80D01001 = 'DO unable to provide service'
    0x80D02002 = 'No download progress within timeout'
    0x80D02003 = 'Job not found'
    0x80D02005 = 'No downloads exist'
    0x80D0200C = 'Job not completed/cancelled before max age'
    0x80D02013 = 'Action not allowed in current job state'
    0x80D03001 = 'Throttled by participation rate'
    0x80D03002 = 'Blocked by user/admin settings'
    0x80D03801 = 'Paused: cost policy restrictions'
    0x80D03802 = 'Download mode restricted by content policy'
    0x80D03803 = 'Paused: cellular network detected'
    0x80D03804 = 'Paused: on battery (check DOMinBatteryPercentageAllowedToUpload)'
    0x80D03805 = 'Paused: lost network connectivity'
    0x80D03806 = 'Download mode restricted by policy'
    0x80D03807 = 'Paused: VPN detected (check DOAllowVPNPeerCaching)'
    0x80D03808 = 'Paused: critical memory usage'
    0x80D03809 = 'Download mode restricted: cache folder absent'
    0x80D0380A = 'Cannot contact DO cloud services'
    0x80D0380B = 'Download mode restricted: unregistered caller'
    0x80D0380C = 'Using simple ranges (simple mode)'
    0x80D05001 = 'HTTP server data size mismatch'
    0x80D05002 = 'HTTP server certificate validation failed'
    0x80D05011 = 'Server missing Range header support'
    0x80D06802 = 'Fatal error in core'
    0x80D06803 = 'Service returned empty JSON'
    0x80D06804 = 'Bad/incomplete piece data'
    0x80D06805 = 'Piece hash check failed'
    0x80D0680B = 'Swarm not running'
    0x80D0680C = 'Peer not recognized'
    0x80D0680D = 'Peer is banned'
    0x80D06810 = 'Max connections reached'
    0x80D06811 = 'Connection lost'
}

function Get-DOErrorDescription {
    param([string]$HexCode)
    try {
        $intVal = [Convert]::ToInt32($HexCode.TrimStart('0x'), 16)
        if ($script:DOErrorCodes.ContainsKey($intVal)) {
            return $script:DOErrorCodes[$intVal]
        }
    }
    catch {}
    return $null
}

#endregion

# ============================================================================
# Header
# ============================================================================
$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Write-Host "`n" -NoNewline
Write-Host ("=" * 78) -ForegroundColor Cyan
Write-Host "  Delivery Optimization Troubleshooter" -ForegroundColor Cyan
Write-Host "  $timestamp" -ForegroundColor Gray
Write-Host ("=" * 78) -ForegroundColor Cyan

$isAdmin = Test-IsAdmin
if (-not $isAdmin) {
    Write-Host "`n  Running without admin privileges - some checks will be limited.`n" -ForegroundColor Yellow
}

$script:Report['Timestamp'] = $timestamp
$script:Report['ComputerName'] = $env:COMPUTERNAME
$script:Report['IsAdmin'] = $isAdmin

# ============================================================================
# SECTION 0: System Information
# ============================================================================
Write-Host "`n== System Information ==" -ForegroundColor White

$osVer = [Environment]::OSVersion.Version
$osBuild = "$($osVer.Major).$($osVer.Minor).$($osVer.Build).$($osVer.Revision)"
Write-Check -Status INFO -Category System -Check "Windows Version" -Detail $osBuild
$script:Report['OSVersion'] = $osBuild

# Windows edition
$osEdition = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).EditionID
if ($osEdition) { Write-Check -Status INFO -Category System -Check "Edition" -Detail $osEdition }

# UUS version (Undocked Update Stack)
$uusVerPath = "$env:ProgramData\Microsoft\Windows\UUS\State\_active.uusver"
if (Test-Path $uusVerPath -ErrorAction SilentlyContinue) {
    $uusVer = Get-Content $uusVerPath -ErrorAction SilentlyContinue
    Write-Check -Status INFO -Category System -Check "UUS Version" -Detail $uusVer
}

Write-Check -Status INFO -Category System -Check "PowerShell" -Detail "$($PSVersionTable.PSVersion)"

# RAM
try {
    $totalRAM = [math]::Round((Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop | Measure-Object -Property Capacity -Sum).Sum / 1GB, 1)
    $minRAM = 4
    if ($totalRAM -ge $minRAM) {
        Write-Check -Status PASS -Category System -Check "RAM" -Detail "$totalRAM GB (minimum ${minRAM} GB for peering)"
    }
    else {
        Write-Check -Status FAIL -Category System -Check "RAM" -Detail "$totalRAM GB — below ${minRAM} GB minimum for peering"
    }
    $script:Report['TotalRAMGB'] = $totalRAM
}
catch {
    Write-Check -Status INFO -Category System -Check "RAM" -Detail "Could not determine: $($_.Exception.Message)"
}

# Disk space
try {
    $sysDrive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceId='$env:SystemDrive'" -ErrorAction Stop
    $totalDiskGB = [math]::Round($sysDrive.Size / 1GB, 1)
    $freeDiskGB = [math]::Round($sysDrive.FreeSpace / 1GB, 1)
    $minDiskGB = 32
    if ($freeDiskGB -ge $minDiskGB) {
        Write-Check -Status PASS -Category System -Check "Disk ($env:SystemDrive)" -Detail "Total: ${totalDiskGB} GB, Free: ${freeDiskGB} GB"
    }
    else {
        Write-Check -Status WARN -Category System -Check "Disk ($env:SystemDrive)" -Detail "Free: ${freeDiskGB} GB — below ${minDiskGB} GB, DO may not cache effectively"
    }
}
catch {
    Write-Check -Status INFO -Category System -Check "Disk" -Detail "Could not determine: $($_.Exception.Message)"
}

# Battery / Power
try {
    $battery = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
    if (-not $battery) {
        Write-Check -Status PASS -Category System -Check "Power" -Detail "AC powered (no battery)"
    }
    else {
        $pct = $battery.EstimatedChargeRemaining
        $charging = $battery.BatteryStatus -ge 6
        if ($charging) {
            Write-Check -Status PASS -Category System -Check "Power" -Detail "Battery $pct% (charging)"
        }
        elseif ($pct -ge 40) {
            Write-Check -Status PASS -Category System -Check "Power" -Detail "Battery $pct%"
        }
        else {
            Write-Check -Status WARN -Category System -Check "Power" -Detail "Battery $pct% — uploading may be paused (default min: 40%)"
        }
    }
}
catch {}

# ============================================================================
# SECTION 1: DO Service Health
# ============================================================================
Write-Host "`n== DO Service Status ==" -ForegroundColor White

# Check DO service
$doSvc = Get-Service -Name 'DoSvc' -ErrorAction SilentlyContinue
if ($doSvc) {
    $script:Report['DOServiceStatus'] = $doSvc.Status.ToString()
    if ($doSvc.Status -eq 'Running') {
        Write-Check -Status PASS -Category Service -Check "DO Service (DoSvc)" -Detail "Running (StartType: $($doSvc.StartType))"
    }
    elseif ($doSvc.Status -eq 'Stopped') {
        Write-Check -Status WARN -Category Service -Check "DO Service (DoSvc)" -Detail "Stopped (StartType: $($doSvc.StartType)). Service starts on demand."
    }
    else {
        Write-Check -Status FAIL -Category Service -Check "DO Service (DoSvc)" -Detail "$($doSvc.Status) (StartType: $($doSvc.StartType))"
    }
}
else {
    Write-Check -Status FAIL -Category Service -Check "DO Service (DoSvc)" -Detail "Service not found"
    $script:Report['DOServiceStatus'] = 'NotFound'
}

# Check DO download mode from registry
$doRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
$doConfig = Get-ItemProperty -Path $doRegPath -ErrorAction SilentlyContinue
$downloadModeNames = @{
    0   = 'HTTP only (no peering)'
    1   = 'LAN (same NAT/subnet)'
    2   = 'Group (same AD site/domain)'
    3   = 'Internet (LAN + Internet peers)'
    99  = 'Simple (HTTP only, no peering, no DO cloud)'
    100 = 'Bypass (use BITS instead of DO)'
}

if ($doConfig -and $null -ne $doConfig.DODownloadMode) {
    $mode = $doConfig.DODownloadMode
    $modeName = $downloadModeNames[$mode]
    if (-not $modeName) { $modeName = "Unknown ($mode)" }
    $script:Report['ConfiguredDownloadMode'] = $mode
    $script:Report['ConfiguredDownloadModeName'] = $modeName

    if ($mode -eq 0 -or $mode -eq 99 -or $mode -eq 100) {
        Write-Check -Status WARN -Category Config -Check "Download Mode (Policy)" -Detail "$mode = $modeName — P2P is disabled"
    }
    else {
        Write-Check -Status PASS -Category Config -Check "Download Mode (Policy)" -Detail "$mode = $modeName"
    }
}
else {
    # Check if set via MDM instead
    $doMdmPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeliveryOptimization'
    $doMdm = Get-ItemProperty -Path $doMdmPath -ErrorAction SilentlyContinue
    if ($doMdm -and $null -ne $doMdm.DODownloadMode) {
        $mode = $doMdm.DODownloadMode
        $modeName = $downloadModeNames[$mode]
        if (-not $modeName) { $modeName = "Unknown ($mode)" }
        $script:Report['ConfiguredDownloadMode'] = $mode
        $script:Report['ConfiguredDownloadModeName'] = $modeName
        Write-Check -Status INFO -Category Config -Check "Download Mode (MDM)" -Detail "$mode = $modeName"
    }
    else {
        Write-Check -Status INFO -Category Config -Check "Download Mode" -Detail "Not configured by policy — using OS default (LAN)"
        $script:Report['ConfiguredDownloadMode'] = 'Default'
        $script:Report['ConfiguredDownloadModeName'] = 'LAN (default)'
    }
}

# Check additional DO policies
$policyChecks = @(
    @{ Name = 'DOMaxCacheSize'; Desc = 'Max Cache Size (%)' },
    @{ Name = 'DOAbsoluteMaxCacheSize'; Desc = 'Absolute Max Cache Size (GB)' },
    @{ Name = 'DOMaxCacheAge'; Desc = 'Max Cache Age (seconds)' },
    @{ Name = 'DOMaxUploadBandwidth'; Desc = 'Max Upload Bandwidth' },
    @{ Name = 'DOMaxDownloadBandwidth'; Desc = 'Max Download Bandwidth' },
    @{ Name = 'DOPercentageMaxForegroundBandwidth'; Desc = 'Max Foreground Bandwidth (%)' },
    @{ Name = 'DOPercentageMaxBackgroundBandwidth'; Desc = 'Max Background Bandwidth (%)' },
    @{ Name = 'DOGroupId'; Desc = 'Group ID' },
    @{ Name = 'DOGroupIdSource'; Desc = 'Group ID Source' },
    @{ Name = 'DOMinFileSizeToCache'; Desc = 'Min File Size to Cache (MB)' },
    @{ Name = 'DORestrictPeerSelectionBy'; Desc = 'Restrict Peer Selection' },
    @{ Name = 'DOMonthlyUploadDataCap'; Desc = 'Monthly Upload Data Cap (GB)' },
    @{ Name = 'DOAllowVPNPeerCaching'; Desc = 'Allow VPN Peer Caching' },
    @{ Name = 'DOMinRAMAllowedToPeer'; Desc = 'Min RAM to Peer (GB)' },
    @{ Name = 'DOMinDiskSizeAllowedToPeer'; Desc = 'Min Disk Size to Peer (GB)' },
    @{ Name = 'DOMinBatteryPercentageAllowedToUpload'; Desc = 'Min Battery % to Upload' },
    @{ Name = 'DOMinBackgroundQoS'; Desc = 'Min Background QoS (KB/s)' },
    @{ Name = 'DODelayForegroundDownloadFromHttp'; Desc = 'Delay Foreground from HTTP (s)' },
    @{ Name = 'DODelayBackgroundDownloadFromHttp'; Desc = 'Delay Background from HTTP (s)' },
    @{ Name = 'DOCacheHost'; Desc = 'Cache Host (MCC)' },
    @{ Name = 'DOCacheHostSource'; Desc = 'Cache Host Source' },
    @{ Name = 'DODelayCacheServerFallbackForeground'; Desc = 'Delay CacheServer Fallback FG (s)' },
    @{ Name = 'DODelayCacheServerFallbackBackground'; Desc = 'Delay CacheServer Fallback BG (s)' },
    @{ Name = 'DODisallowCacheServerDownloadsOnVPN'; Desc = 'Disallow CacheServer on VPN' }
)

$configuredPolicies = @()
foreach ($p in $policyChecks) {
    $val = $null
    if ($doConfig) { $val = $doConfig.($p.Name) }
    if ($null -eq $val -and $doMdm) { $val = $doMdm.($p.Name) }
    if ($null -ne $val) {
        Write-Check -Status INFO -Category Config -Check $p.Desc -Detail "Value: $val"
        $configuredPolicies += [PSCustomObject]@{ Policy = $p.Name; Value = $val }
    }
}
if ($configuredPolicies.Count -eq 0) {
    Write-Check -Status INFO -Category Config -Check "DO Policies" -Detail "No additional policies configured"
}
else {
    # Validate: GroupId requires DownloadMode 2
    $groupIdPolicy = $configuredPolicies | Where-Object { $_.Policy -eq 'DOGroupId' }
    if ($groupIdPolicy) {
        $effectiveMode = $script:Report['ConfiguredDownloadMode']
        if ($effectiveMode -ne 2 -and $effectiveMode -ne 'Default') {
            Write-Check -Status WARN -Category Config -Check "GroupId vs DownloadMode" -Detail "DOGroupId is set but DownloadMode is $effectiveMode (requires 2/Group) — GroupId will be ignored"
        }
    }

    # Validate: VPN peering policy
    $vpnPeerPolicy = $configuredPolicies | Where-Object { $_.Policy -eq 'DOAllowVPNPeerCaching' }
    if ($vpnPeerPolicy -and $vpnPeerPolicy.Value -eq 1) {
        Write-Check -Status INFO -Category Config -Check "VPN Peering" -Detail "Enabled via policy — P2P will work over VPN"
    }
}
$script:Report['ConfiguredPolicies'] = $configuredPolicies

# Cache folder and state file
$doCachePath = "$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization"
if ((Test-Path $doCachePath -ErrorAction SilentlyContinue) -eq $true) {
    Write-Check -Status PASS -Category Service -Check "Cache Folder" -Detail $doCachePath
}
else {
    Write-Check -Status FAIL -Category Service -Check "Cache Folder" -Detail "Not found: $doCachePath"
}

$doStatePath = "$doCachePath\State\dosvcState.dat"
if ((Test-Path $doStatePath -ErrorAction SilentlyContinue) -eq $true) {
    Write-Check -Status PASS -Category Service -Check "State File" -Detail "dosvcState.dat exists"
}
else {
    if ($isAdmin) {
        Write-Check -Status FAIL -Category Service -Check "State File" -Detail "dosvcState.dat not found — DO may not have initialized"
    }
    else {
        Write-Check -Status INFO -Category Service -Check "State File" -Detail "Cannot verify (requires admin)"
    }
}

# ============================================================================
# SECTION 2: Local DO Cache & Performance
# ============================================================================
Write-Host "`n== Local DO Cache ==" -ForegroundColor White

$doStatus = $null
try {
    $doStatus = Get-DeliveryOptimizationStatus -ErrorAction Stop
}
catch {
    Write-Check -Status WARN -Category Cache -Check "Get-DeliveryOptimizationStatus" -Detail "Failed: $($_.Exception.Message)"
}

if ($doStatus) {
    $cacheCount = @($doStatus).Count
    $totalSize = ($doStatus | Measure-Object -Property FileSize -Sum -ErrorAction SilentlyContinue).Sum
    $script:Report['CacheEntryCount'] = $cacheCount
    $script:Report['CacheTotalSize'] = $totalSize

    if ($cacheCount -gt 0) {
        Write-Check -Status PASS -Category Cache -Check "Cache Entries" -Detail "$cacheCount files, $(Format-Bytes $totalSize) total"
    }
    else {
        Write-Check -Status INFO -Category Cache -Check "Cache Entries" -Detail "Cache is empty"
    }

    # Show download modes in use
    $modes = $doStatus | Group-Object DownloadMode | Sort-Object Count -Descending
    foreach ($m in $modes) {
        Write-Check -Status INFO -Category Cache -Check "Download Mode: $($m.Name)" -Detail "$($m.Count) files"
    }

    # Show download status
    $statuses = $doStatus | Group-Object Status | Sort-Object Count -Descending
    foreach ($s in $statuses) {
        Write-Check -Status INFO -Category Cache -Check "Download Status: $($s.Name)" -Detail "$($s.Count) files"
    }

    # Show caller breakdown
    $callers = $doStatus | Group-Object PredefinedCallerApplication | Sort-Object Count -Descending
    foreach ($c in $callers) {
        $callerSize = ($doStatus | Where-Object { $_.PredefinedCallerApplication -eq $c.Name } | Measure-Object -Property FileSize -Sum).Sum
        Write-Check -Status INFO -Category Cache -Check "Caller: $($c.Name)" -Detail "$($c.Count) files, $(Format-Bytes $callerSize)"
    }

    # Check for expired content
    $now = Get-Date
    $expired = @($doStatus | Where-Object { $_.ExpireOn -and $_.ExpireOn -lt $now })
    if ($expired.Count -gt 0) {
        Write-Check -Status WARN -Category Cache -Check "Expired Cache Entries" -Detail "$($expired.Count) files past expiry"
    }

    # ---- Download Analytics ----
    $totalDownloaded = ($doStatus | Measure-Object -Property TotalBytesDownloaded -Sum -ErrorAction SilentlyContinue).Sum
    $totalFromCDN = ($doStatus | Measure-Object -Property BytesFromHttp -Sum -ErrorAction SilentlyContinue).Sum
    $totalFromPeers = ($doStatus | Measure-Object -Property BytesFromPeers -Sum -ErrorAction SilentlyContinue).Sum
    $totalFromCache = ($doStatus | Measure-Object -Property BytesFromCacheServer -Sum -ErrorAction SilentlyContinue).Sum
    $totalFromLan = ($doStatus | Measure-Object -Property BytesFromLanPeers -Sum -ErrorAction SilentlyContinue).Sum
    $totalFromGroup = ($doStatus | Measure-Object -Property BytesFromGroupPeers -Sum -ErrorAction SilentlyContinue).Sum
    $totalFromInternet = ($doStatus | Measure-Object -Property BytesFromInternetPeers -Sum -ErrorAction SilentlyContinue).Sum

    # Upload analytics
    $totalToLan = ($doStatus | Measure-Object -Property BytesToLanPeers -Sum -ErrorAction SilentlyContinue).Sum
    $totalToGroup = ($doStatus | Measure-Object -Property BytesToGroupPeers -Sum -ErrorAction SilentlyContinue).Sum
    $totalToInternet = ($doStatus | Measure-Object -Property BytesToInternetPeers -Sum -ErrorAction SilentlyContinue).Sum
    $totalUploaded = $totalToLan + $totalToGroup + $totalToInternet

    # Files with peer data vs total
    $withPeers = @($doStatus | Where-Object { $_.BytesFromPeers -and $_.BytesFromPeers -gt 0 })
    $withCache = @($doStatus | Where-Object { $_.BytesFromCacheServer -and $_.BytesFromCacheServer -gt 0 })
    $withCacheHost = @($doStatus | Where-Object { $_.CacheHost })

    # Average peer caching percentage
    $peerCachingEntries = @($doStatus | Where-Object { $_.PercentPeerCaching -and $_.PercentPeerCaching -gt 0 })
    $avgPeerCaching = 0
    if ($peerCachingEntries.Count -gt 0) {
        $avgPeerCaching = [math]::Round(($peerCachingEntries | Measure-Object -Property PercentPeerCaching -Average).Average, 1)
    }

    # Efficiency calculation
    $nonCdnTotal = $totalFromPeers + $totalFromCache
    $grandTotal = $totalFromCDN + $nonCdnTotal
    $peerCachePct = 0; if ($grandTotal -gt 0) { $peerCachePct = [math]::Round($nonCdnTotal / $grandTotal * 100, 1) }
    $cdnPct = 0; if ($grandTotal -gt 0) { $cdnPct = [math]::Round($totalFromCDN / $grandTotal * 100, 1) }
    $peerPct = 0; if ($grandTotal -gt 0) { $peerPct = [math]::Round($totalFromPeers / $grandTotal * 100, 1) }
    $cachePct = 0; if ($grandTotal -gt 0) { $cachePct = [math]::Round($totalFromCache / $grandTotal * 100, 1) }

    # Store for summary
    $script:Report['Analytics'] = [ordered]@{
        TotalDownloaded     = $totalDownloaded
        TotalFromCDN        = $totalFromCDN
        TotalFromPeers      = $totalFromPeers
        TotalFromCache      = $totalFromCache
        TotalFromLAN        = $totalFromLan
        TotalFromGroup      = $totalFromGroup
        TotalFromInternet   = $totalFromInternet
        TotalUploaded       = $totalUploaded
        TotalToLAN          = $totalToLan
        TotalToGroup        = $totalToGroup
        TotalToInternet     = $totalToInternet
        PeerCacheEfficiency = $peerCachePct
        AvgPeerCachingPct   = $avgPeerCaching
        FilesWithPeers      = $withPeers.Count
        FilesWithCache      = $withCache.Count
        TotalFiles          = $cacheCount
    }

    Write-Host "`n  --- Download Analytics ---" -ForegroundColor Gray
    Write-Check -Status INFO -Category Analytics -Check "Total Downloaded" -Detail (Format-Bytes $totalDownloaded)
    Write-Check -Status INFO -Category Analytics -Check "  From CDN (HTTP)" -Detail "$(Format-Bytes $totalFromCDN) ($cdnPct%)"
    Write-Check -Status INFO -Category Analytics -Check "  From Peers (total)" -Detail "$(Format-Bytes $totalFromPeers) ($peerPct%)"
    if ($totalFromLan -gt 0) {
        Write-Check -Status INFO -Category Analytics -Check "    LAN Peers" -Detail (Format-Bytes $totalFromLan)
    }
    if ($totalFromGroup -gt 0) {
        Write-Check -Status INFO -Category Analytics -Check "    Group Peers" -Detail (Format-Bytes $totalFromGroup)
    }
    if ($totalFromInternet -gt 0) {
        Write-Check -Status INFO -Category Analytics -Check "    Internet Peers" -Detail (Format-Bytes $totalFromInternet)
    }
    Write-Check -Status INFO -Category Analytics -Check "  From Cache Server" -Detail "$(Format-Bytes $totalFromCache) ($cachePct%)"

    if ($peerCachePct -gt 0) {
        Write-Check -Status PASS -Category Analytics -Check "P2P/Cache Efficiency" -Detail "$peerCachePct% from peers/cache ($($withPeers.Count)/$cacheCount files used peers, avg $avgPeerCaching% peer caching)"
    }
    else {
        Write-Check -Status WARN -Category Analytics -Check "P2P/Cache Efficiency" -Detail "0% — all $cacheCount files downloaded entirely from CDN"
    }

    # Upload analytics
    Write-Host "`n  --- Upload Analytics ---" -ForegroundColor Gray
    Write-Check -Status INFO -Category Analytics -Check "Total Uploaded" -Detail (Format-Bytes $totalUploaded)
    if ($totalToLan -gt 0) {
        Write-Check -Status INFO -Category Analytics -Check "  To LAN Peers" -Detail (Format-Bytes $totalToLan)
    }
    if ($totalToGroup -gt 0) {
        Write-Check -Status INFO -Category Analytics -Check "  To Group Peers" -Detail (Format-Bytes $totalToGroup)
    }
    if ($totalToInternet -gt 0) {
        Write-Check -Status INFO -Category Analytics -Check "  To Internet Peers" -Detail (Format-Bytes $totalToInternet)
    }
    if ($totalUploaded -eq 0) {
        Write-Check -Status INFO -Category Analytics -Check "Upload Activity" -Detail "No data uploaded to peers"
    }

    # Bandwidth savings estimate
    if ($nonCdnTotal -gt 0) {
        Write-Check -Status PASS -Category Analytics -Check "WAN Bandwidth Saved" -Detail "$(Format-Bytes $nonCdnTotal) served locally instead of CDN"
    }

    # Per-caller download breakdown
    Write-Host "`n  --- Per-Caller Breakdown ---" -ForegroundColor Gray
    $callerGroups = $doStatus | Group-Object PredefinedCallerApplication | Sort-Object { ($_.Group | Measure-Object -Property TotalBytesDownloaded -Sum).Sum } -Descending
    foreach ($cg in $callerGroups) {
        $callerTotal = ($cg.Group | Measure-Object -Property TotalBytesDownloaded -Sum).Sum
        $callerPeer = ($cg.Group | Measure-Object -Property BytesFromPeers -Sum).Sum
        $callerCache = ($cg.Group | Measure-Object -Property BytesFromCacheServer -Sum).Sum
        $callerCDN = ($cg.Group | Measure-Object -Property BytesFromHttp -Sum).Sum
        $callerNonCdn = $callerPeer + $callerCache
        $callerPeerPct = 0; if ($callerTotal -gt 0) { $callerPeerPct = [math]::Round($callerNonCdn / $callerTotal * 100, 1) }
        $callerName = '(Unknown)'; if ($cg.Name) { $callerName = $cg.Name }
        Write-Check -Status INFO -Category Analytics -Check $callerName -Detail "$($cg.Count) files, $(Format-Bytes $callerTotal) total — CDN: $(Format-Bytes $callerCDN), Peers: $(Format-Bytes $callerPeer), Cache: $(Format-Bytes $callerCache) ($callerPeerPct% P2P/Cache)"
    }

    # Connected Cache hosts
    if ($withCacheHost.Count -gt 0) {
        $cacheHosts = $withCacheHost | Select-Object -ExpandProperty CacheHost -Unique
        Write-Check -Status PASS -Category Analytics -Check "Connected Cache (MCC/DOINC)" -Detail "Active — hosts: $($cacheHosts -join ', '), $($withCache.Count) files served"
    }
    else {
        Write-Check -Status INFO -Category Analytics -Check "Connected Cache (MCC/DOINC)" -Detail "Not detected in current cache"
    }

}
else {
    $script:Report['CacheEntryCount'] = 0
}

# Performance snapshot
Write-Host "`n== DO Performance ==" -ForegroundColor White
$perfSnap = $null
try {
    $perfSnap = Get-DeliveryOptimizationPerfSnap -ErrorAction Stop
}
catch {
    Write-Check -Status WARN -Category Perf -Check "Get-DeliveryOptimizationPerfSnap" -Detail "Failed: $($_.Exception.Message)"
}

if ($perfSnap) {
    $script:Report['PerfSnap'] = [ordered]@{
        DownloadMode              = $perfSnap.DownloadMode
        FilesDownloaded           = $perfSnap.FilesDownloaded
        CacheSizeBytes            = $perfSnap.CacheSizeBytes
        NumberOfPeers             = $perfSnap.NumberOfPeers
        CacheHostConnections      = $perfSnap.CacheHostConnections
        CdnConnections            = $perfSnap.CdnConnections
        DownlinkBps               = $perfSnap.DownlinkBps
        UplinkBps                 = $perfSnap.UplinkBps
        ForegroundDownloadRatePct = $perfSnap.ForegroundDownloadRatePct
        BackgroundDownloadRatePct = $perfSnap.BackgroundDownloadRatePct
    }

    Write-Check -Status INFO -Category Perf -Check "Active Download Mode" -Detail $perfSnap.DownloadMode
    Write-Check -Status INFO -Category Perf -Check "Files Downloaded" -Detail $perfSnap.FilesDownloaded
    Write-Check -Status INFO -Category Perf -Check "Cache Size" -Detail (Format-Bytes $perfSnap.CacheSizeBytes)
    Write-Check -Status INFO -Category Perf -Check "Number of Peers" -Detail $perfSnap.NumberOfPeers

    if ($perfSnap.CacheHostConnections -gt 0) {
        Write-Check -Status PASS -Category Perf -Check "Cache Host Connections" -Detail $perfSnap.CacheHostConnections
    }
    else {
        Write-Check -Status INFO -Category Perf -Check "Cache Host Connections" -Detail "0"
    }
    Write-Check -Status INFO -Category Perf -Check "CDN Connections" -Detail $perfSnap.CdnConnections
    Write-Check -Status INFO -Category Perf -Check "Downlink" -Detail (Format-Bps $perfSnap.DownlinkBps)
    Write-Check -Status INFO -Category Perf -Check "Uplink" -Detail (Format-Bps $perfSnap.UplinkBps)
    Write-Check -Status INFO -Category Perf -Check "Foreground Rate Limit" -Detail "$($perfSnap.ForegroundDownloadRatePct)%"
    Write-Check -Status INFO -Category Perf -Check "Background Rate Limit" -Detail "$($perfSnap.BackgroundDownloadRatePct)%"
}

# Monthly performance summary
try {
    $monthSnap = Get-DeliveryOptimizationPerfSnapThisMonth -ErrorAction Stop
    if ($monthSnap) {
        Write-Host "`n  --- This Month ---" -ForegroundColor Gray
        $monthHttpDl = [long]$monthSnap.DownloadHttpBytes
        $monthLanDl = [long]$monthSnap.DownloadLanBytes
        $monthIntDl = [long]$monthSnap.DownloadInternetBytes
        $monthCacheDl = [long]$monthSnap.DownloadCacheHostBytes
        $monthTotal = $monthHttpDl + $monthLanDl + $monthIntDl + $monthCacheDl
        $monthPeer = $monthLanDl + $monthIntDl + $monthCacheDl
        $monthPeerPct = 0; if ($monthTotal -gt 0) { $monthPeerPct = [math]::Round($monthPeer / $monthTotal * 100, 1) }

        Write-Check -Status INFO -Category Perf -Check "Month Total Downloaded" -Detail (Format-Bytes $monthTotal)
        Write-Check -Status INFO -Category Perf -Check "  Month from CDN" -Detail (Format-Bytes $monthHttpDl)
        Write-Check -Status INFO -Category Perf -Check "  Month from LAN Peers" -Detail (Format-Bytes $monthLanDl)
        Write-Check -Status INFO -Category Perf -Check "  Month from Internet Peers" -Detail (Format-Bytes $monthIntDl)
        Write-Check -Status INFO -Category Perf -Check "  Month from Cache Server" -Detail (Format-Bytes $monthCacheDl)
        if ($monthPeerPct -gt 0) {
            Write-Check -Status PASS -Category Perf -Check "Month P2P/Cache Efficiency" -Detail "$monthPeerPct% — $(Format-Bytes $monthPeer) saved from WAN"
        }
        else {
            Write-Check -Status INFO -Category Perf -Check "Month P2P/Cache Efficiency" -Detail "0%"
        }

        $monthUpLan = [long]$monthSnap.UploadLanBytes
        $monthUpInt = [long]$monthSnap.UploadInternetBytes
        $monthUpTotal = $monthUpLan + $monthUpInt
        if ($monthUpTotal -gt 0) {
            Write-Check -Status INFO -Category Perf -Check "Month Uploaded" -Detail "$(Format-Bytes $monthUpTotal) (LAN: $(Format-Bytes $monthUpLan), Internet: $(Format-Bytes $monthUpInt))"
        }

        $script:Report['MonthlyPerf'] = [ordered]@{
            HttpBytes           = $monthHttpDl
            LanBytes            = $monthLanDl
            InternetBytes       = $monthIntDl
            CacheHostBytes      = $monthCacheDl
            UploadLanBytes      = $monthUpLan
            UploadInternetBytes = $monthUpInt
            PeerEfficiency      = $monthPeerPct
        }
    }
}
catch {
    Write-Check -Status INFO -Category Perf -Check "Monthly Stats" -Detail "Get-DeliveryOptimizationPerfSnapThisMonth not available: $($_.Exception.Message)"
}

# ============================================================================
# SECTION 3: Network / Connectivity Checks
# ============================================================================
Write-Host "`n== Network Connectivity ==" -ForegroundColor White

# VPN detection (uses same keywords as DO client)
$vpnKeywords = @('VPN', 'Secure', 'Virtual Private Network', 'Juniper', 'PANGP', 'Citrix')
$adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
$vpnDetected = $false
if ($adapters) {
    foreach ($adapter in $adapters) {
        $matchedKeyword = $vpnKeywords | Where-Object { $adapter.InterfaceDescription -match $_ -or $adapter.Name -match $_ }
        if ($matchedKeyword) {
            Write-Check -Status WARN -Category Network -Check "VPN Detected" -Detail "'$($adapter.Name)' matches keyword '$($matchedKeyword -join ', ')' — DO may restrict P2P"
            $vpnDetected = $true
        }
    }
    if (-not $vpnDetected) {
        Write-Check -Status PASS -Category Network -Check "VPN Detection" -Detail "No VPN adapter keywords detected"
    }
}
else {
    Write-Check -Status WARN -Category Network -Check "Network Adapters" -Detail "Could not enumerate adapters"
}
$script:Report['VPNDetected'] = $vpnDetected

# Test connectivity to DO endpoints (using TcpClient — Test-NetConnection hangs in VS Code terminal)
$connectivityTargets = @(
    @{ Name = 'Geo Endpoint'; Host = 'geo.prod.do.dsp.mp.microsoft.com'; Port = 443 },
    @{ Name = 'GeoVersion Endpoint'; Host = 'geover.prod.do.dsp.mp.microsoft.com'; Port = 443 },
    @{ Name = 'CDN (dl.delivery)'; Host = 'dl.delivery.mp.microsoft.com'; Port = 80 }
)

foreach ($target in $connectivityTargets) {
    $tcpClient = $null
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectTask = $tcpClient.ConnectAsync($target.Host, $target.Port)
        if ($connectTask.Wait(5000)) {
            if ($tcpClient.Connected) {
                Write-Check -Status PASS -Category Network -Check $target.Name -Detail "$($target.Host):$($target.Port) reachable"
            }
            else {
                Write-Check -Status FAIL -Category Network -Check $target.Name -Detail "$($target.Host):$($target.Port) BLOCKED"
            }
        }
        else {
            Write-Check -Status FAIL -Category Network -Check $target.Name -Detail "$($target.Host):$($target.Port) timeout (5s)"
        }
    }
    catch {
        Write-Check -Status FAIL -Category Network -Check $target.Name -Detail "$($target.Host):$($target.Port) - $($_.Exception.Message)"
    }
    finally {
        if ($tcpClient) { $tcpClient.Dispose() }
    }
}

# DO P2P port 7680 (TCP) — inbound listener for peer-to-peer
$tcpListener = $null
try {
    $tcpListener = New-Object System.Net.Sockets.TcpClient
    $listenTask = $tcpListener.ConnectAsync('localhost', 7680)
    if ($listenTask.Wait(2000) -and $tcpListener.Connected) {
        Write-Check -Status PASS -Category Network -Check "P2P Port 7680/TCP" -Detail "Listening on localhost:7680"
    }
    else {
        Write-Check -Status WARN -Category Network -Check "P2P Port 7680/TCP" -Detail "Not listening — DO service may not be accepting P2P connections"
    }
}
catch {
    Write-Check -Status WARN -Category Network -Check "P2P Port 7680/TCP" -Detail "Not listening (expected if DO service is idle)"
}
finally {
    if ($tcpListener) { $tcpListener.Dispose() }
}

# Firewall rules for DO
try {
    $doFwRules = Get-NetFirewallRule -DisplayName '*Delivery Optimization*' -ErrorAction SilentlyContinue
    if ($doFwRules) {
        $enabledRules = @($doFwRules | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Allow' })
        $blockedRules = @($doFwRules | Where-Object { $_.Action -eq 'Block' -and $_.Enabled -eq 'True' })
        if ($blockedRules.Count -gt 0) {
            Write-Check -Status FAIL -Category Network -Check "Firewall Rules (DO)" -Detail "$($blockedRules.Count) BLOCKING rules found: $($blockedRules.DisplayName -join ', ')"
        }
        elseif ($enabledRules.Count -gt 0) {
            Write-Check -Status PASS -Category Network -Check "Firewall Rules (DO)" -Detail "$($enabledRules.Count) allow rules active"
        }
        else {
            Write-Check -Status WARN -Category Network -Check "Firewall Rules (DO)" -Detail "DO firewall rules exist but none are enabled"
        }
    }
    else {
        Write-Check -Status WARN -Category Network -Check "Firewall Rules (DO)" -Detail "No Delivery Optimization firewall rules found"
    }

    # Check port 7680 inbound rule specifically
    $port7680Rules = Get-NetFirewallPortFilter -Protocol TCP -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -eq 7680 } |
    ForEach-Object { $_ | Get-NetFirewallRule -ErrorAction SilentlyContinue } |
    Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' -and $_.Enabled -eq 'True' }
    if ($port7680Rules) {
        Write-Check -Status PASS -Category Network -Check "Firewall Port 7680 Inbound" -Detail "Allowed by $($port7680Rules.Count) rule(s)"
    }
    else {
        Write-Check -Status WARN -Category Network -Check "Firewall Port 7680 Inbound" -Detail "No active inbound allow rule for TCP 7680 — P2P may be blocked"
    }
}
catch {
    Write-Check -Status INFO -Category Network -Check "Firewall Rules" -Detail "Could not check: $($_.Exception.Message)"
}

# Proxy settings
try {
    $winhttp = netsh winhttp show proxy 2>&1
    $winhttpText = ($winhttp | Out-String).Trim()
    $hasDirectAccess = $winhttpText -match '(?im)^\s*Direct access'
    $hasProxyServer = $winhttpText -match '(?im)\bProxy Server\(s\)\s*:'
    $hasAutoConfig = $winhttpText -match '(?im)\bAutoconfig URL\s*:'
    if ($hasDirectAccess -and -not $hasProxyServer -and -not $hasAutoConfig) {
        Write-Check -Status PASS -Category Network -Check "WinHTTP Proxy" -Detail "Direct access (no proxy server)"
    }
    else {
        $proxyDetail = $winhttpText -replace "`r?`n", ' | '
        Write-Check -Status WARN -Category Network -Check "WinHTTP Proxy" -Detail $proxyDetail
    }
}
catch {
    Write-Check -Status INFO -Category Network -Check "WinHTTP Proxy" -Detail "Could not check"
}

try {
    $ieProxy = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($ieProxy.ProxyEnable -eq 1) {
        Write-Check -Status INFO -Category Network -Check "IE/System Proxy" -Detail "Enabled: $($ieProxy.ProxyServer)"
    }
    if ($ieProxy.AutoConfigURL) {
        Write-Check -Status INFO -Category Network -Check "Proxy PAC" -Detail $ieProxy.AutoConfigURL
    }
}
catch {}

# NLM connectivity and cost
try {
    $nlmCost = netsh nlm show cost 2>&1
    $isCostUnrestricted = $nlmCost -match 'Unrestricted|Fixed'
    if ($isCostUnrestricted) {
        Write-Check -Status PASS -Category Network -Check "Network Cost (NLM)" -Detail "Unrestricted/Fixed — DO will download normally"
    }
    else {
        $costLine = ($nlmCost | Select-String 'Cost' | Select-Object -First 1).ToString().Trim()
        Write-Check -Status WARN -Category Network -Check "Network Cost (NLM)" -Detail "Metered or restricted ($costLine) — DO may pause Background downloads"
    }
}
catch {
    Write-Check -Status INFO -Category Network -Check "Network Cost" -Detail "Could not determine"
}

# HTTP byte-range support test (DO requires Range headers for P2P)
try {
    $brUri = 'http://dl.delivery.mp.microsoft.com/filestreamingservice/files/52fa8751-747d-479d-8f22-e32730cc0eb1'
    $req = [System.Net.WebRequest]::Create($brUri)
    $req.Method = 'GET'
    $req.AddRange('bytes', 0, 9)
    $req.Timeout = 10000
    $resp = $req.GetResponse()
    $statusCode = [int]$resp.StatusCode
    $contentRange = $resp.GetResponseHeader('Content-Range')
    $resp.Close()
    if ($statusCode -eq 206 -and $contentRange -match 'bytes 0-9/') {
        Write-Check -Status PASS -Category Network -Check "HTTP Byte-Range (206)" -Detail "CDN supports Range requests: $contentRange"
    }
    else {
        Write-Check -Status FAIL -Category Network -Check "HTTP Byte-Range (206)" -Detail "Unexpected: HTTP $statusCode, Content-Range: $contentRange — DO P2P requires byte-range support"
    }
}
catch {
    Write-Check -Status FAIL -Category Network -Check "HTTP Byte-Range (206)" -Detail "Failed: $($_.Exception.Message) — proxy or firewall may be stripping Range headers"
}

# Hostname resolution for key DO hosts
$dnsTargets = @('dl.delivery.mp.microsoft.com', 'download.windowsupdate.com')
foreach ($dnsHost in $dnsTargets) {
    try {
        $resolved = [System.Net.Dns]::GetHostAddresses($dnsHost)
        if ($resolved) {
            Write-Check -Status PASS -Category Network -Check "DNS: $dnsHost" -Detail "$($resolved.Count) addresses ($($resolved[0]))"
        }
        else {
            Write-Check -Status FAIL -Category Network -Check "DNS: $dnsHost" -Detail "No addresses returned"
        }
    }
    catch {
        Write-Check -Status FAIL -Category Network -Check "DNS: $dnsHost" -Detail "Resolution failed: $($_.Exception.Message)"
    }
}

# ============================================================================
# SECTION 4: Remote DO Service API
# ============================================================================
if ($SkipRemoteAPI) {
    Write-Host "`n== DO Cloud Service API (SKIPPED) ==" -ForegroundColor DarkGray
    Write-Check -Status SKIP -Category API -Check "Remote API" -Detail "Skipped via -SkipRemoteAPI parameter"
}
else {
    Write-Host "`n== DO Cloud Service API ==" -ForegroundColor White

    # --- Geo (with captive portal detection) ---
    $Geo = $null
    try {
        $geoStart = Get-Date
        $geoWebResp = Invoke-WebRequest -Uri "https://geo.prod.do.dsp.mp.microsoft.com/geo" -UseBasicParsing -ErrorAction Stop
        $geoMs = [math]::Round(((Get-Date) - $geoStart).TotalMilliseconds)
        $geoContentType = $geoWebResp.Headers.'Content-Type'

        if ($geoContentType -match 'text/html') {
            Write-Check -Status FAIL -Category API -Check "Geo Endpoint" -Detail "Possible CAPTIVE PORTAL — received text/html instead of text/json. Login to network and retry."
        }
        elseif ($geoContentType -match 'text/json|application/json') {
            $Geo = $geoWebResp.Content | ConvertFrom-Json
            if (-not $Geo.Version -or -not $Geo.KeyValue_EndpointFullUri) {
                Write-Check -Status FAIL -Category API -Check "Geo Endpoint" -Detail "Invalid response — missing Version or KeyValue_EndpointFullUri"
                $Geo = $null
            }
            elseif ($Geo.ExternalIpAddress -eq '0.0.0.0') {
                Write-Check -Status WARN -Category API -Check "Geo Endpoint" -Detail "OK (${geoMs}ms) — External IP is 0.0.0.0 (possible proxy/NAT issue)"
                $script:Report['Geo'] = $Geo
            }
            else {
                Write-Check -Status PASS -Category API -Check "Geo Endpoint" -Detail "OK (${geoMs}ms) — IP: $($Geo.ExternalIpAddress), Country: $($Geo.CountryCode), CacheId: $($Geo.CacheId)"
                $script:Report['Geo'] = $Geo
            }
        }
        else {
            Write-Check -Status FAIL -Category API -Check "Geo Endpoint" -Detail "Unexpected Content-Type: $geoContentType"
        }
    }
    catch {
        Write-Check -Status FAIL -Category API -Check "Geo Endpoint" -Detail $_.Exception.Message
    }

    if ($Geo) {
        # Check DownloadModeFailSafe
        if ($Geo.DownloadModeFailSafe -and $Geo.DownloadModeFailSafe -ne '') {
            Write-Check -Status WARN -Category API -Check "DownloadModeFailSafe" -Detail "Active: $($Geo.DownloadModeFailSafe) — service may be forcing a fallback mode"
        }
        else {
            Write-Check -Status PASS -Category API -Check "DownloadModeFailSafe" -Detail "Not active"
        }

        # --- GeoVersion ---
        try {
            $GeoVersion = Invoke-RestMethod -Uri "https://geover.prod.do.dsp.mp.microsoft.com/geoversion" -ErrorAction Stop
            $script:Report['GeoVersion'] = $GeoVersion

            # Compare versions
            if ($Geo.Version -eq $GeoVersion.Version) {
                Write-Check -Status PASS -Category API -Check "GeoVersion" -Detail "Version matches Geo — Config timestamp: $($GeoVersion.Timestamp)"
            }
            else {
                Write-Check -Status WARN -Category API -Check "GeoVersion" -Detail "Version MISMATCH — Geo: $($Geo.Version.Substring(0,16))... vs GeoVer: $($GeoVersion.Version.Substring(0,16))... (config may be updating)"
            }
        }
        catch {
            Write-Check -Status WARN -Category API -Check "GeoVersion Endpoint" -Detail $_.Exception.Message
        }

        # --- KeyValue ---
        $KeyValue = $null
        try {
            $kvStart = Get-Date
            $KeyValue = Invoke-RestMethod -Uri $Geo.KeyValue_EndpointFullUri -ErrorAction Stop
            $kvMs = [math]::Round(((Get-Date) - $kvStart).TotalMilliseconds)
            $kvFieldCount = ($KeyValue.PSObject.Properties | Measure-Object).Count
            Write-Check -Status PASS -Category API -Check "KeyValue Endpoint" -Detail "OK (${kvMs}ms) — $kvFieldCount fields returned"
            $script:Report['KeyValue'] = $KeyValue
        }
        catch {
            Write-Check -Status FAIL -Category API -Check "KeyValue Endpoint" -Detail $_.Exception.Message
        }

        if ($KeyValue) {
            # P2P participation rate — controls Discovery service enrollment, NOT whether peers work
            $partRate = [double]$KeyValue.ParticipationRate
            $pubPartRate = [double]$KeyValue.PublicParticipationRate
            if ($partRate -eq 0 -and $pubPartRate -eq 0) {
                # Check if local cache actually has peer data
                $localPeerBytes = 0
                if ($doStatus) {
                    $localPeerBytes = ($doStatus | Measure-Object -Property BytesFromPeers -Sum -ErrorAction SilentlyContinue).Sum
                }
                if ($localPeerBytes -gt 0) {
                    Write-Check -Status INFO -Category API -Check "Discovery Participation Rate" -Detail "0% (service enrollment) — but local P2P is working ($(Format-Bytes $localPeerBytes) from peers). Rate controls Discovery service registration, not LAN/Group peering."
                }
                else {
                    Write-Check -Status INFO -Category API -Check "Discovery Participation Rate" -Detail "0% (both private and public) — this client won't register with Discovery service. LAN/Group peering still works via local mechanisms."
                }
            }
            else {
                Write-Check -Status PASS -Category API -Check "Discovery Participation Rate" -Detail "Private: ${partRate}%, Public: ${pubPartRate}%"
            }

            # Upload limit
            Write-Check -Status INFO -Category API -Check "Monthly Upload Limit" -Detail "$($KeyValue.UploadLimitGBMonth) GB/month"

            # Max CDN connections & speed
            Write-Check -Status INFO -Category API -Check "Max CDN Connections" -Detail $KeyValue.Client_MaxCDNConnections
            Write-Check -Status INFO -Category API -Check "CDN Speed Threshold" -Detail "$(Format-Bps ([long]$KeyValue.Client_CDNConnSpeedBps * 8))"

            # DNS peer discovery
            $dnsPeerRate = [double]$KeyValue.Client_DnsPeerDiscoveryConsumerParticipationRate
            if ($dnsPeerRate -eq 0) {
                Write-Check -Status INFO -Category API -Check "DNS Peer Discovery" -Detail "Disabled (participation rate: 0)"
            }
            else {
                Write-Check -Status INFO -Category API -Check "DNS Peer Discovery" -Detail "Enabled (participation rate: $dnsPeerRate)"
            }

            # Check primary vs secondary endpoints
            $failoverMismatch = $false
            @('KeyValue', 'Discovery', 'ContentPolicy') | ForEach-Object {
                $primary = $KeyValue."${_}_EndpointUri"
                $secondary = $KeyValue."${_}2_EndpointUri"
                if ($primary -ne $secondary) {
                    Write-Check -Status WARN -Category API -Check "$_ Failover" -Detail "Primary and secondary differ — Primary: $primary, Secondary: $secondary"
                    $failoverMismatch = $true
                }
            }
            if (-not $failoverMismatch) {
                Write-Check -Status PASS -Category API -Check "Endpoint Failover" -Detail "Primary and secondary endpoints match (no active failover)"
            }

            # VPN keywords from service vs local detection
            try {
                $svcVpnKeywords = $KeyValue.Client_VpnKeywords | ConvertFrom-Json -ErrorAction Stop
                Write-Check -Status INFO -Category API -Check "Service VPN Keywords" -Detail ($svcVpnKeywords -join ', ')
            }
            catch {
                Write-Check -Status INFO -Category API -Check "Service VPN Keywords" -Detail $KeyValue.Client_VpnKeywords
            }

            # --- ContentPolicy + Discovery + PiecesHash for local cache entries ---
            if ($doStatus -and @($doStatus).Count -gt 0) {
                $entriesToCheck = @($doStatus | Where-Object { $_.SourceURL } | Select-Object -First $MaxCacheEntries)

                if ($entriesToCheck.Count -gt 0) {
                    Write-Host "`n  --- Cache Entry Verification (up to $MaxCacheEntries) ---" -ForegroundColor Gray

                    $cpBase = $KeyValue.ContentPolicy_EndpointUri.TrimEnd('/')
                    $discBase = $KeyValue.Discovery_EndpointUri.TrimEnd('/')
                    $registeredCallers = @()
                    if ($KeyValue.Client_RegisteredCallersFilterList) {
                        $registeredCallers = @($KeyValue.Client_RegisteredCallersFilterList -split ',')
                    }
                    $script:Report['ContentPolicyResults'] = @()

                    $entryNum = 0
                    foreach ($entry in $entriesToCheck) {
                        $entryNum++
                        $fileId = $entry.FileId
                        $sourceUrl = $entry.SourceURL
                        $callerApp = $entry.PredefinedCallerApplication

                        Write-Host "`n  --- Entry $entryNum/$($entriesToCheck.Count): $callerApp ---" -ForegroundColor Gray
                        Write-Check -Status INFO -Category Content -Check "FileId" -Detail $fileId
                        $sourceUrlDisplay = $sourceUrl; if ($sourceUrl.Length -gt 80) { $sourceUrlDisplay = $sourceUrl.Substring(0, 80) + '...' }
                        Write-Check -Status INFO -Category Content -Check "SourceURL" -Detail $sourceUrlDisplay

                        # Registered caller validation (per entry/job)
                        if ($registeredCallers.Count -gt 0 -and $callerApp) {
                            $matched = $registeredCallers | Where-Object {
                                $pattern = $_.Trim()
                                try { $callerApp -match "^${pattern}$" } catch { $callerApp -eq $pattern }
                            }
                            if ($matched) {
                                Write-Check -Status PASS -Category Callers -Check "Caller" -Detail "$callerApp - Matches registered filter"
                            }
                            else {
                                Write-Check -Status WARN -Category Callers -Check "Caller" -Detail "$callerApp - NOT in registered callers list — may not use DO service"
                            }
                        }
                        elseif (-not $callerApp) {
                            Write-Check -Status INFO -Category Callers -Check "Caller" -Detail "No caller name on this cache entry"
                        }
                        else {
                            Write-Check -Status INFO -Category Callers -Check "Caller" -Detail "$callerApp - Registered caller filter list not returned by KeyValue"
                        }

                        # ContentPolicy
                        $cp = $null
                        try {
                            $cpUrl = "$cpBase/content/$fileId/contentpolicy?altCatalogId=$sourceUrl"
                            $cp = Invoke-RestMethod -Uri $cpUrl -ErrorAction Stop

                            if ($cp.ContentId) {
                                Write-Check -Status PASS -Category Content -Check "ContentPolicy" -Detail "ContentId: $($cp.ContentId.Substring(0, [Math]::Min(40, $cp.ContentId.Length)))..."

                                # QoS policies
                                if ($cp.Policies) {
                                    $fgQos = Format-Bps ([long]$cp.Policies.ForegroundQosBps)
                                    $bgQos = Format-Bps ([long]$cp.Policies.BackgroundQosBps)
                                    $cacheAge = [math]::Round([long]$cp.Policies.MaxCacheAgeSecs / 86400, 1)
                                    Write-Check -Status INFO -Category Content -Check "QoS Limits" -Detail "FG: $fgQos, BG: $bgQos"
                                    Write-Check -Status INFO -Category Content -Check "Cache TTL" -Detail "$cacheAge days (MaxCacheAgeSecs: $($cp.Policies.MaxCacheAgeSecs))"
                                }

                                # Validate local cache expiry vs policy
                                if ($entry.ExpireOn -and $cp.Policies.MaxCacheAgeSecs) {
                                    $policyDays = [long]$cp.Policies.MaxCacheAgeSecs / 86400
                                    $remainingDays = [math]::Round(($entry.ExpireOn - $now).TotalDays, 1)
                                    if ($remainingDays -lt 0) {
                                        Write-Check -Status WARN -Category Content -Check "Cache Expiry" -Detail "EXPIRED $([math]::Abs($remainingDays)) days ago (policy: $policyDays days)"
                                    }
                                    else {
                                        Write-Check -Status INFO -Category Content -Check "Cache Expiry" -Detail "$remainingDays days remaining (policy: $policyDays days)"
                                    }
                                }

                                # Discovery
                                try {
                                    $discUrl = "$discBase/content/$($cp.ContentId)"
                                    $peers = Invoke-RestMethod -Uri $discUrl -ErrorAction Stop
                                    $peerCount = @($peers).Count
                                    if ($peerCount -gt 0 -and $peers -ne '[]') {
                                        Write-Check -Status PASS -Category Content -Check "Discovery" -Detail "$peerCount peers available"
                                    }
                                    else {
                                        Write-Check -Status INFO -Category Content -Check "Discovery" -Detail "No peers (empty array)"
                                    }
                                }
                                catch {
                                    Write-Check -Status WARN -Category Content -Check "Discovery" -Detail "Failed: $($_.Exception.Message)"
                                }

                                # PiecesHash validation
                                if ($cp.PiecesHashFileCdnUrls -and $cp.PiecesHashFileCdnUrls[0]) {
                                    try {
                                        $phUrl = $cp.PiecesHashFileCdnUrls[0]
                                        $phBytes = (Invoke-WebRequest -Uri $phUrl -UseBasicParsing -ErrorAction Stop).Content
                                        $piecesHash = [System.Text.Encoding]::UTF8.GetString($phBytes) | ConvertFrom-Json

                                        $phSizeMB = [math]::Round($piecesHash.ContentLength / 1MB, 1)
                                        $expectedPieces = [math]::Ceiling($piecesHash.ContentLength / $piecesHash.PieceSize)
                                        $actualPieces = $piecesHash.Pieces.Count

                                        if ($expectedPieces -eq $actualPieces) {
                                            Write-Check -Status PASS -Category Content -Check "PiecesHash" -Detail "${phSizeMB} MB, $actualPieces pieces (verified)"
                                        }
                                        else {
                                            Write-Check -Status FAIL -Category Content -Check "PiecesHash" -Detail "Piece count mismatch: expected $expectedPieces, got $actualPieces"
                                        }

                                        # Verify HashOfHashes matches ContentPolicy
                                        if ($piecesHash.HashOfHashes -eq $cp.HashOfHashes) {
                                            Write-Check -Status PASS -Category Content -Check "HashOfHashes" -Detail "PiecesHash matches ContentPolicy"
                                        }
                                        else {
                                            Write-Check -Status FAIL -Category Content -Check "HashOfHashes" -Detail "MISMATCH — PiecesHash: $($piecesHash.HashOfHashes) vs CP: $($cp.HashOfHashes)"
                                        }

                                        # Verify local file size matches manifest
                                        if ($entry.FileSize -and $entry.FileSize -gt 0) {
                                            if ($entry.FileSize -eq $piecesHash.ContentLength) {
                                                Write-Check -Status PASS -Category Content -Check "File Size Match" -Detail "Local $(Format-Bytes $entry.FileSize) = Manifest $(Format-Bytes $piecesHash.ContentLength)"
                                            }
                                            else {
                                                Write-Check -Status WARN -Category Content -Check "File Size Match" -Detail "Local $(Format-Bytes $entry.FileSize) != Manifest $(Format-Bytes $piecesHash.ContentLength)"
                                            }
                                        }
                                    }
                                    catch {
                                        Write-Check -Status WARN -Category Content -Check "PiecesHash" -Detail "Failed to fetch: $($_.Exception.Message)"
                                    }
                                }
                                else {
                                    Write-Check -Status INFO -Category Content -Check "PiecesHash" -Detail "No PiecesHash URL in ContentPolicy"
                                }
                            }
                            else {
                                Write-Check -Status WARN -Category Content -Check "ContentPolicy" -Detail "Empty response (no ContentId) — altCatalogId may be expired or invalid"
                            }
                        }
                        catch {
                            Write-Check -Status WARN -Category Content -Check "ContentPolicy" -Detail "Failed: $($_.Exception.Message)"
                        }

                        $script:Report['ContentPolicyResults'] += [PSCustomObject]@{
                            FileId    = $fileId
                            Caller    = $callerApp
                            ContentId = $cp.ContentId
                            HasPolicy = [bool]$cp.ContentId
                        }
                    }
                }
                else {
                    Write-Check -Status INFO -Category Content -Check "Cache Entry Verification" -Detail "No cache entries with SourceURL to verify"
                }
            }

            # --- MCC/Connected Cache Download Test ---
            # Determine cache host from: policy > Geo response > cache entries
            $mccHost = $null
            $mccHostSource = 'none'

            # Check policy first
            $cacheHostPolicy = $configuredPolicies | Where-Object { $_.Policy -eq 'DOCacheHost' }
            if ($cacheHostPolicy -and $cacheHostPolicy.Value) {
                $mccHost = $cacheHostPolicy.Value
                $mccHostSource = 'policy'
            }
            # Check Geo response
            if (-not $mccHost -and $Geo.CacheHost) {
                $mccHost = $Geo.CacheHost
                $mccHostSource = 'geo'
            }
            # Check cache entries for CacheHost field
            if (-not $mccHost -and $doStatus) {
                $cacheHostEntry = $doStatus | Where-Object { $_.CacheHost } | Select-Object -First 1
                if ($cacheHostEntry) {
                    $mccHost = $cacheHostEntry.CacheHost
                    $mccHostSource = 'cache'
                }
            }

            if ($mccHost) {
                Write-Host "`n  --- Connected Cache (MCC) Test ---" -ForegroundColor Gray
                Write-Check -Status INFO -Category MCC -Check "Cache Host" -Detail "$mccHost (source: $mccHostSource)"

                # Test MCC download using same test file as Microsoft's troubleshooter
                $mccServers = $mccHost -split ','
                foreach ($mccSrv in $mccServers) {
                    $mccTestUrl = "http://$($mccSrv.Trim())/filestreamingservice/files/7bc846e0-af9c-49be-a03d-bb04428c9bb5/Microsoft.png?cacheHostOrigin=dl.delivery.mp.microsoft.com"
                    try {
                        $mccResp = Invoke-WebRequest -Uri $mccTestUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
                        if ($mccResp.StatusCode -eq 200 -and $mccResp.Headers.'Content-Type' -match 'octet-stream') {
                            Write-Check -Status PASS -Category MCC -Check "MCC Download Test" -Detail "$($mccSrv.Trim()) — HTTP $($mccResp.StatusCode), $(Format-Bytes $mccResp.RawContentLength)"
                        }
                        elseif ($mccResp.Headers.'Content-Type' -match 'text/html') {
                            Write-Check -Status WARN -Category MCC -Check "MCC Download Test" -Detail "$($mccSrv.Trim()) — Possible captive portal (received text/html)"
                        }
                        else {
                            Write-Check -Status WARN -Category MCC -Check "MCC Download Test" -Detail "$($mccSrv.Trim()) — HTTP $($mccResp.StatusCode), Content-Type: $($mccResp.Headers.'Content-Type')"
                        }
                    }
                    catch {
                        Write-Check -Status FAIL -Category MCC -Check "MCC Download Test" -Detail "$($mccSrv.Trim()) — $($_.Exception.Message)"
                    }
                }
            }
        }
    }
}

# ============================================================================
# SECTION 5: DO Logs (via Get-DeliveryOptimizationLog)
# ============================================================================
Write-Host "`n== Recent DO Log Entries ==" -ForegroundColor White

$doLogEntries = $null
try {
    # Get-DeliveryOptimizationLog is the supported way to extract DO logs
    $doLogEntries = Get-DeliveryOptimizationLog -ErrorAction Stop

    if ($doLogEntries -and @($doLogEntries).Count -gt 0) {
        $allEntries = @($doLogEntries)
        Write-Check -Status PASS -Category Events -Check "DO Log" -Detail "$($allEntries.Count) total log entries retrieved"

        # Filter for errors and warnings from recent entries
        $errorEntries = @($allEntries | Where-Object { $_.Function -match 'Error|Fail|Exception' -or $_.Level -match 'Error' } | Select-Object -Last 50)
        $warnEntries = @($allEntries | Where-Object { $_.Function -match 'Warn' -or $_.Level -match 'Warn' } | Select-Object -Last 50)

        # Also look for specific known problem indicators
        $connectFailures = @($allEntries | Where-Object { $_.Message -match 'connect|timeout|refused|unreachable|0x80' } | Select-Object -Last 20)

        if ($errorEntries.Count -gt 0) {
            Write-Check -Status FAIL -Category Events -Check "DO Log Errors" -Detail "$($errorEntries.Count) error entries found"

            # Extract and group by HRESULT with DO error code lookup
            $errorGroups = @{}
            foreach ($entry in $errorEntries) {
                $hrMatches = [regex]::Matches("$($entry.Function): $($entry.Message)", '(?:hr:\s*|0x)([0-9a-fA-Fx]{8})')
                if ($hrMatches.Count -gt 0) {
                    $hrCode = "0x$($hrMatches[0].Groups[1].Value)"
                    $funcMatch = [regex]::Match("$($entry.Function)", '(\w+)$')
                    $funcName = 'Unknown'; if ($funcMatch.Success) { $funcName = $funcMatch.Groups[1].Value }
                    $key = $hrCode
                    if (-not $errorGroups.ContainsKey($key)) {
                        $errorGroups[$key] = @{ Count = 0; Function = $funcName; Description = Get-DOErrorDescription $hrCode; LastSeen = $null }
                    }
                    $errorGroups[$key].Count++
                    $ts = $null; if ($entry.TimeCreated) { $ts = $entry.TimeCreated } elseif ($entry.Timestamp) { $ts = $entry.Timestamp }
                    if ($ts -and (-not $errorGroups[$key].LastSeen -or $ts -gt $errorGroups[$key].LastSeen)) {
                        $errorGroups[$key].LastSeen = $ts
                    }
                }
                else {
                    $key = '_nohr'
                    if (-not $errorGroups.ContainsKey($key)) {
                        $errorGroups[$key] = @{ Count = 0; Function = ''; Description = $null; LastSeen = $null }
                    }
                    $errorGroups[$key].Count++
                }
            }

            foreach ($eg in $errorGroups.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending) {
                if ($eg.Key -eq '_nohr') {
                    Write-Check -Status FAIL -Category Events -Check "  Errors (no HRESULT)" -Detail "$($eg.Value.Count) entries without specific error code"
                }
                else {
                    $desc = ''; if ($eg.Value.Description) { $desc = " — $($eg.Value.Description)" }
                    $lastTs = ''; if ($eg.Value.LastSeen) { $lastTs = " (last: $(([datetime]$eg.Value.LastSeen).ToString('yyyy-MM-dd HH:mm')))" }
                    Write-Check -Status FAIL -Category Events -Check "  Error $($eg.Key)" -Detail "$($eg.Value.Count)x in $($eg.Value.Function)$desc$lastTs"
                }
            }
        }
        else {
            Write-Check -Status PASS -Category Events -Check "DO Log Errors" -Detail "No error entries found"
        }

        if ($warnEntries.Count -gt 0) {
            Write-Check -Status WARN -Category Events -Check "DO Log Warnings" -Detail "$($warnEntries.Count) warning entries"
        }
        else {
            Write-Check -Status PASS -Category Events -Check "DO Log Warnings" -Detail "No warning entries"
        }

        if ($connectFailures.Count -gt 0) {
            # Group connection failures by function pattern
            $connGroups = @{}
            foreach ($cf in $connectFailures) {
                $fnMatch = [regex]::Match("$($cf.Function): $($cf.Message)", '(\w+::\w+)')
                $key = 'Other'; if ($fnMatch.Success) { $key = $fnMatch.Groups[1].Value }
                if (-not $connGroups.ContainsKey($key)) { $connGroups[$key] = 0 }
                $connGroups[$key]++
            }
            $connSummary = ($connGroups.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Value)x $($_.Key)" }) -join ', '
            Write-Check -Status WARN -Category Events -Check "Connection Issues" -Detail "$($connectFailures.Count) entries: $connSummary"
        }

        # Show recent activity summary
        $recentEntries = @($allEntries | Select-Object -Last 100)
        $functions = $recentEntries | Group-Object Function -ErrorAction SilentlyContinue | Sort-Object Count -Descending | Select-Object -First 5
        if ($functions) {
            $topFuncs = ($functions | ForEach-Object { "$($_.Name)($($_.Count))" }) -join ', '
            Write-Check -Status INFO -Category Events -Check "Recent Activity" -Detail "Top functions in last 100 entries: $topFuncs"
        }
    }
    else {
        Write-Check -Status INFO -Category Events -Check "DO Log" -Detail "No log entries returned (log may be empty)"
    }
}
catch {
    # Get-DeliveryOptimizationLog decodes ETW trace files and requires admin
    # DO does NOT use a standard Windows Event Log — there is no WinEvent fallback
    if ($_.Exception.Message -match 'Admin') {
        Write-Check -Status WARN -Category Events -Check "DO Log" -Detail "Requires admin — re-run elevated for full log analysis"
    }
    else {
        Write-Check -Status WARN -Category Events -Check "DO Log" -Detail "Get-DeliveryOptimizationLog failed: $($_.Exception.Message)"
    }
    # Check if ETW trace files exist as a basic health indicator
    $doLogPath = "$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs"
    if ((Test-Path $doLogPath -ErrorAction SilentlyContinue) -eq $true) {
        $logFiles = Get-ChildItem -Path $doLogPath -Filter '*.etl' -ErrorAction SilentlyContinue
        if ($logFiles) {
            $newestLog = $logFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            $logAge = [math]::Round(((Get-Date) - $newestLog.LastWriteTime).TotalHours, 1)
            Write-Check -Status INFO -Category Events -Check "DO ETW Trace Files" -Detail "$($logFiles.Count) .etl files found, newest: $($newestLog.Name) ($logAge hours old)"
        }
        else {
            Write-Check -Status WARN -Category Events -Check "DO ETW Trace Files" -Detail "Log directory exists but no .etl files found"
        }
    }
    else {
        Write-Check -Status INFO -Category Events -Check "DO ETW Trace Files" -Detail "Log directory not accessible (run elevated)"
    }
}

# ============================================================================
# SUMMARY
# ============================================================================
Write-Host "`n" -NoNewline
Write-Host ("=" * 78) -ForegroundColor Cyan
Write-Host "  Summary" -ForegroundColor Cyan
Write-Host ("=" * 78) -ForegroundColor Cyan

$passCount = @($script:Checks | Where-Object { $_.Status -eq 'PASS' }).Count
$warnCount = @($script:Checks | Where-Object { $_.Status -eq 'WARN' }).Count
$failCount = @($script:Checks | Where-Object { $_.Status -eq 'FAIL' }).Count
$infoCount = @($script:Checks | Where-Object { $_.Status -eq 'INFO' }).Count

Write-Host "  PASS: $passCount  |  " -ForegroundColor Green -NoNewline
Write-Host "WARN: $warnCount  |  " -ForegroundColor Yellow -NoNewline
Write-Host "FAIL: $failCount  |  " -ForegroundColor Red -NoNewline
Write-Host "INFO: $infoCount" -ForegroundColor Cyan

# --- Analytics Summary ---
if ($script:Report['Analytics']) {
    $a = $script:Report['Analytics']
    Write-Host "`n  Download/Upload Overview:" -ForegroundColor Cyan
    Write-Host "    Total Downloaded:      $(Format-Bytes $a.TotalDownloaded)" -ForegroundColor White
    Write-Host "    From CDN (HTTP):       $(Format-Bytes $a.TotalFromCDN)" -ForegroundColor White
    Write-Host "    From Peers:            $(Format-Bytes $a.TotalFromPeers)" -ForegroundColor White
    Write-Host "    From Cache Server:     $(Format-Bytes $a.TotalFromCache)" -ForegroundColor White
    Write-Host "    Total Uploaded:        $(Format-Bytes $a.TotalUploaded)" -ForegroundColor White
    Write-Host "    P2P/Cache Efficiency:  $($a.PeerCacheEfficiency)% of data from local sources" -ForegroundColor $(if ($a.PeerCacheEfficiency -gt 0) { 'Green' } else { 'Yellow' })
    if ($a.TotalFromPeers + $a.TotalFromCache -gt 0) {
        Write-Host "    WAN Savings:           $(Format-Bytes ($a.TotalFromPeers + $a.TotalFromCache)) avoided from CDN" -ForegroundColor Green
    }
}

# --- Grouped Critical Issues ---
$fails = @($script:Checks | Where-Object { $_.Status -eq 'FAIL' })
if ($fails.Count -gt 0) {
    Write-Host "`n  Critical Issues:" -ForegroundColor Red

    # Group log errors - show count + unique error types instead of each line
    $logErrors = @($fails | Where-Object { $_.Category -eq 'Events' })
    $otherFails = @($fails | Where-Object { $_.Category -ne 'Events' })

    if ($logErrors.Count -gt 0) {
        # Count parent vs sub-entries
        $parentLogErrors = @($logErrors | Where-Object { $_.Check -notmatch '^\s' })
        $subLogErrors = @($logErrors | Where-Object { $_.Check -match '^\s' })

        foreach ($ple in $parentLogErrors) {
            Write-Host "    [-] $($ple.Check) - $($ple.Detail)" -ForegroundColor Red
        }
        if ($subLogErrors.Count -gt 0) {
            # Group by HRESULT/error pattern
            $errorPatterns = @{}
            foreach ($sle in $subLogErrors) {
                $hrMatch = [regex]::Match($sle.Detail, 'hr:\s*([0-9a-fA-F]{8})')
                $funcMatch = [regex]::Match($sle.Detail, ':\s*(\w+),')
                $key = $sle.Detail.Substring(0, [Math]::Min(60, $sle.Detail.Length))
                if ($hrMatch.Success -and $funcMatch.Success) {
                    $key = "0x$($hrMatch.Groups[1].Value) ($($funcMatch.Groups[1].Value))"
                }
                elseif ($hrMatch.Success) {
                    $key = "0x$($hrMatch.Groups[1].Value)"
                }
                if (-not $errorPatterns.ContainsKey($key)) { $errorPatterns[$key] = 0 }
                $errorPatterns[$key]++
            }
            Write-Host "        Error breakdown:" -ForegroundColor DarkRed
            foreach ($ep in $errorPatterns.GetEnumerator() | Sort-Object Value -Descending) {
                Write-Host "          $($ep.Value)x  $($ep.Key)" -ForegroundColor DarkRed
            }
        }
    }

    foreach ($f in $otherFails) {
        Write-Host "    [-] $($f.Check) - $($f.Detail)" -ForegroundColor Red
    }
}

# --- Grouped Warnings ---
$warns = @($script:Checks | Where-Object { $_.Status -eq 'WARN' })
if ($warns.Count -gt 0) {
    Write-Host "`n  Warnings:" -ForegroundColor Yellow

    # Deduplicate: group identical Check names and summarize
    $contentPolicyWarns = @($warns | Where-Object { $_.Check -eq 'ContentPolicy' -and $_.Detail -match 'Empty response' })
    $connectionWarns = @($warns | Where-Object { $_.Check -match '^\s+Connection' })
    $connectionParent = @($warns | Where-Object { $_.Check -eq 'Connection Issues' })
    $otherWarns = @($warns | Where-Object {
            $_.Check -ne 'ContentPolicy' -or $_.Detail -notmatch 'Empty response'
        } | Where-Object {
            $_.Check -notmatch '^\s+Connection'
        } | Where-Object {
            $_.Check -ne 'Connection Issues'
        })

    # ContentPolicy empties — single line with count
    if ($contentPolicyWarns.Count -gt 0) {
        $cpTotal = $script:Report['ContentPolicyResults'].Count
        Write-Host "    [!] ContentPolicy - $($contentPolicyWarns.Count) of $cpTotal cache entries returned empty (altCatalogId expired/invalid)" -ForegroundColor Yellow
    }

    # Connection issues — single line with breakdown
    if ($connectionParent.Count -gt 0 -or $connectionWarns.Count -gt 0) {
        $connCount = $connectionWarns.Count
        if ($connectionParent.Count -gt 0) {
            Write-Host "    [!] $($connectionParent[0].Check) - $($connectionParent[0].Detail)" -ForegroundColor Yellow
        }
        if ($connectionWarns.Count -gt 0) {
            # Group by error type
            $connPatterns = @{}
            foreach ($cw in $connectionWarns) {
                $fnMatch = [regex]::Match($cw.Detail, '— (\w+::?\w+):')
                $key = 'Other'; if ($fnMatch.Success) { $key = $fnMatch.Groups[1].Value }
                if (-not $connPatterns.ContainsKey($key)) { $connPatterns[$key] = 0 }
                $connPatterns[$key]++
            }
            foreach ($cp in $connPatterns.GetEnumerator() | Sort-Object Value -Descending) {
                Write-Host "          $($cp.Value)x  $($cp.Key)" -ForegroundColor DarkYellow
            }
        }
    }

    # All other warnings — show as-is but skip sub-entries already handled
    foreach ($w in $otherWarns) {
        Write-Host "    [!] $($w.Check) - $($w.Detail)" -ForegroundColor Yellow
    }
}

# --- Recommendations ---
$recommendations = @()

if ($script:Report['Analytics']) {
    $a = $script:Report['Analytics']
    if ($a.PeerCacheEfficiency -eq 0 -and $a.TotalDownloaded -gt 0) {
        $recommendations += "No data from peers/cache — check Download Mode is set to LAN (1) or higher, and that peers exist on the same subnet."
    }
    if ($a.TotalUploaded -eq 0 -and $a.TotalFromPeers -gt 0) {
        $recommendations += "Receiving from peers but not uploading — check upload bandwidth limits and monthly upload cap."
    }
}

$expiredWarns = @($warns | Where-Object { $_.Check -eq 'Expired Cache Entries' })
if ($expiredWarns.Count -gt 0) {
    $recommendations += "Expired cache entries present — these will be cleaned up automatically by DO, but may indicate stale content."
}

if ($script:Report['VPNDetected']) {
    $recommendations += "VPN detected — DO may restrict P2P while VPN is active. Disconnect VPN or use split-tunnel for DO traffic."
}

$failoverWarns = @($warns | Where-Object { $_.Check -match 'Failover' })
if ($failoverWarns.Count -gt 0) {
    $recommendations += "Primary/secondary endpoints differ — a server-side failover may be in progress. Monitor and re-check."
}

if (-not $isAdmin) {
    $recommendations += "Run elevated (as Administrator) for full DO log analysis and ETW trace access."
}

if ($recommendations.Count -gt 0) {
    Write-Host "`n  Recommendations:" -ForegroundColor White
    foreach ($r in $recommendations) {
        Write-Host "    > $r" -ForegroundColor Gray
    }
}

# ============================================================================
# Export
# ============================================================================
if ($ExportPath) {
    $script:Report['Checks'] = $script:Checks | Select-Object Status, Category, Check, Detail
    $script:Report | ConvertTo-Json -Depth 10 | Set-Content -Path $ExportPath -Encoding UTF8
    Write-Host "`n  Report exported to: $ExportPath" -ForegroundColor Green
}

Write-Host "`n" -NoNewline
