<#
.SYNOPSIS
    Interactive Delivery Optimization log analysis and troubleshooting tool.

.DESCRIPTION
    Parses DO ETL log files (or the live system log) into typed event collections,
    then exposes them through a menu-driven interface. Key capabilities:
      - Diagnosis: rule-based findings on why peering did or did not work, with evidence and actions
      - Summary dashboard (bytes by source, peer share, connections, errors)
      - Per-download analysis, job trace, failed / incomplete / paused jobs
      - Peer / P2P activity, including upload activity and peering failure analysis
      - Network, Connected Cache, cloud service and CDN error views
      - Effective DO configuration as logged with each download
      - Time and text filters that apply to every report
      - Correlation with Get-DeliveryOptimizationStatus (live system)
      - CSV export for any dataset, or everything at once with a text report
    Without a desktop session (Server Core, remoting) GridView views fall back to console tables.

.PARAMETER LogPath
    A folder containing dosvc*.etl files (searched recursively), a single .etl file, or 'Live'.
    If omitted you will be prompted.

.PARAMETER ResolvePeerNames
    Reverse-resolve peer IP addresses to host names in the per-download P2P view.
    Off by default because lookups stall when the logs are analysed away from the source network.

.PARAMETER Summary
    Print the diagnosis and summary dashboard for -LogPath and exit (no menu).

.PARAMETER ExportPath
    Export every dataset as CSV plus a text report for -LogPath into this folder and exit (no menu).

.PARAMETER NoGridView
    Never open Out-GridView; show console tables instead.

.PARAMETER StartTime
    Only analyse events at or after this time.

.PARAMETER EndTime
    Only analyse events at or before this time.

.PARAMETER Filter
    Only analyse downloads whose caller, URL, FileId, SessionId or JobId contains this text.

.EXAMPLE
    .\Invoke-2PDOLogAnalyzer.ps1

.EXAMPLE
    .\Invoke-2PDOLogAnalyzer.ps1 -LogPath "C:\DOLogs\DOETLLogs_Machine_20250515"

.EXAMPLE
    .\Invoke-2PDOLogAnalyzer.ps1 -LogPath "C:\DOLogs\Machine1" -Summary
    Prints the diagnosis and dashboard, then exits.

.EXAMPLE
    .\Invoke-2PDOLogAnalyzer.ps1 -LogPath Live -ExportPath C:\Temp\DOReport -StartTime '2026-04-23 12:30'
    Exports all data from 12:30 onwards plus a text report, then exits.

.NOTES
    Version:        1.4
    Author:         Mattias Benninge @ 2Pint Software
    Creation Date:  2026-05-15
    Purpose/Change: Comprehensive update for DO API spec alignment, error lookup fixes,
                    expanded protocol enums, and improved multi-segment correlation.
                    v1.2: Single-result GridView popups (job timeline, per-swarm summary,
                    MCC server breakdown, GEO history, status correlation) replaced with
                    bordered console tables/cards via Write-DOTable / Write-DOCard.
                    v1.3: Byte percentages use network bytes (CDN+MCC+peers) instead of file size;
                    local cache and pre-log session bytes shown separately. Fixed duration display,
                    timeMs parsing, mode-0/zero values shown as blank, unlogged mode shown as mode 0,
                    large HRESULT formatting, peer connection outcomes, cache host parsing (IPv6 /
                    host names / per-server bytes), unnamed error sources. Reverse DNS is opt-in.
                    v1.4: Diagnosis engine; job states, cloud service / CDN errors, inbound handshakes
                    and logged configuration parsed; time/text filters; console fallback for GridView;
                    shared menu, grid and download-row helpers; one-pass parsing with progress;
                    -Summary / -ExportPath / -NoGridView / -StartTime / -EndTime / -Filter switches;
                    single .etl and quoted paths accepted; wrong-machine warning for status correlation.

    Requires Windows 10/11 with the DeliveryOptimization PowerShell module.
    GridView output requires Windows PowerShell or PowerShell 7+ on Windows.
    Some features (Status Correlation) require running on the source machine.
#>
[CmdletBinding()]
param(
    [string]$LogPath,
    [switch]$ResolvePeerNames,
    [switch]$Summary,
    [string]$ExportPath,
    [switch]$NoGridView,
    [datetime]$StartTime,
    [datetime]$EndTime,
    [string]$Filter
)

$ErrorActionPreference = 'Continue'

#region ─── Lookup Tables ─────────────────────────────────────────────────────

$script:DODownloadModeNames = @{
    0   = 'HTTP Only (no peering)'
    1   = 'LAN (same network)'
    2   = 'Group (AD/AAD/custom group)'
    3   = 'Internet (all peers)'
    99  = 'Simple (HTTP, cloud unavailable)'
    100 = 'Bypass (deprecated, uses BITS)'
}

$script:DODownloadModeSrcNames = @{
    0  = 'Default / Not set'
    1  = 'Policy (MDM or Group Policy)'
    2  = 'Registry override'
    3  = 'Connected Cache fallback'
    4  = 'User setting'
    5  = 'Simple mode (auto)'
    7  = 'Caller / App-specified'
    99 = 'Simple mode (cloud fallback)'
}

$script:DOScopeNames = @{
    1 = 'LAN'
    2 = 'Group (Legacy)'
    3 = 'Internet'
    6 = 'Group'
}

$script:DOJoinRequestEventNames = @{
    1 = 'Join / Start'
    2 = 'Update'
    3 = 'Leave / Stop'
}

# Error codes from Microsoft DO Engine + Official Troubleshooter + Common Windows networking errors
$script:DOErrorCodes = @{
    # DO Specific Errors (0x80D0xxxx)
    '0x80D01001' = 'DO unable to provide service'
    '0x80D02002' = 'No download progress within timeout'
    '0x80D02003' = 'Job not found'
    '0x80D02004' = 'No files in job'
    '0x80D02005' = 'No downloads exist'
    '0x80D0200B' = 'Memory stream transfer not supported'
    '0x80D0200C' = 'Job not completed/cancelled before max age'
    '0x80D0200D' = 'No local file path specified for download'
    '0x80D02010' = 'No file available (no URL generated error)'
    '0x80D02011' = 'Unknown property ID in Get/SetProperty'
    '0x80D02012' = 'Cannot SetProperty on read-only property'
    '0x80D02013' = 'Action not allowed in current job state'
    '0x80D02015' = 'Cannot GetProperty on write-only property'
    '0x80D02016' = 'Integrity info required but not specified'
    '0x80D02017' = 'Integrity info could not be retrieved'
    '0x80D02018' = 'No download sink specified'
    '0x80D02019' = 'Attempt to set sink failed (another sink already set)'
    '0x80D0201A' = 'Cannot determine file size from HTTP 200'
    '0x80D0201B' = 'Decryption key provided but CDN file not encrypted'
    '0x80D0201C' = 'Cannot determine file size from HTTP 206'
    '0x80D0201D' = 'Cannot determine file size from unexpected HTTP 2xx'
    '0x80D0201E' = 'User network consent required'
    '0x80D02200' = 'Download started without URI'
    '0x80D02201' = 'Download started without content ID'
    '0x80D02202' = 'Invalid content ID'
    '0x80D02203' = 'Ranges unexpected for current download'
    '0x80D02204' = 'Ranges expected for current download'
    '0x80D03001' = 'Throttled by participation rate'
    '0x80D03002' = 'Blocked by user/admin settings'
    '0x80D03801' = 'Paused: cost policy restrictions'
    '0x80D03802' = 'Download mode restricted by content policy'
    '0x80D03803' = 'Paused: cellular network detected'
    '0x80D03804' = 'Paused: on battery (check DOMinBatteryPercentageAllowedToUpload)'
    '0x80D03805' = 'Paused: lost network connectivity'
    '0x80D03806' = 'Download mode restricted by policy'
    '0x80D03807' = 'Paused: VPN detected (check DOAllowVPNPeerCaching)'
    '0x80D03808' = 'Paused: critical memory usage'
    '0x80D03809' = 'Download mode restricted: cache folder absent'
    '0x80D0380A' = 'Cannot contact DO cloud services'
    '0x80D0380B' = 'Download mode restricted: unregistered caller'
    '0x80D0380C' = 'Using simple ranges (simple mode)'
    '0x80D0380D' = 'Paused: unexpected HTTP response code (e.g. 204)'
    '0x80D0482A' = 'Content policy validation error'
    '0x80D05001' = 'HTTP server data size mismatch'
    '0x80D05002' = 'HTTP server certificate validation failed'
    '0x80D05010' = 'Specified byte range is invalid'
    '0x80D05011' = 'Server missing Range header support'
    '0x80D05012' = 'Overlapping byte ranges not supported'
    '0x80D06800' = 'Too many bad pieces during upload'
    '0x80D06802' = 'Fatal error in core'
    '0x80D06803' = 'Service returned empty JSON'
    '0x80D06804' = 'Bad/incomplete piece data'
    '0x80D06805' = 'Piece hash check failed'
    '0x80D06806' = 'Piece hash failed (source not banned yet)'
    '0x80D06807' = 'Piece rejected: already exists in cache'
    '0x80D06808' = 'Piece requested no longer in cache'
    '0x80D06809' = 'Invalid metainfo content'
    '0x80D0680A' = 'Invalid metainfo version'
    '0x80D0680B' = 'Swarm not running'
    '0x80D0680C' = 'Peer not recognized'
    '0x80D0680D' = 'Peer is banned'
    '0x80D0680E' = 'Client trying to connect to itself'
    '0x80D0680F' = 'Socket/peer already connected'
    '0x80D06810' = 'Max connections reached'
    '0x80D06811' = 'Connection lost'
    '0x80D06812' = 'Swarm ID not recognized'
    '0x80D06813' = 'Invalid handshake length'
    '0x80D06814' = 'Socket closed'
    '0x80D06815' = 'Message too long'
    '0x80D06816' = 'Message invalid'
    '0x80D06817' = 'Peer is an upload'
    '0x80D06818' = 'Cannot pin swarm (not in peering mode)'
    '0x80D06819' = 'Cannot delete pinned swarm without force'
    # Win32 / WinInet / Crypto Common DO Errors
    '0x80072EE2' = 'Timeout contacting DO service/server (ERROR_INTERNET_TIMEOUT)'
    '0x80072EFD' = 'Cannot connect to DO service/server (ERROR_INTERNET_CANNOT_CONNECT)'
    '0x80072EFE' = 'Connection aborted with server (ERROR_INTERNET_CONNECTION_ABORTED)'
    '0x80072F78' = 'Invalid server response (ERROR_HTTP_INVALID_SERVER_RESPONSE)'
    '0x800B0004' = 'Certificate not trusted (TRUST_E_SUBJECT_NOT_TRUSTED)'
    '0x80070005' = 'Access denied (E_ACCESSDENIED)'
    '0x80070490' = 'Element not found (ERROR_NOT_FOUND)'
    '0x80004002' = 'Interface not supported (E_NOINTERFACE)'
    '0x8000FFFF' = 'Unexpected failure (E_UNEXPECTED)'
    # BITS-style HTTP status HRESULTs (0x8019xxxx = HTTP status xxx)
    '0x80190190' = 'HTTP 400 Bad Request'
    '0x80190191' = 'HTTP 401 Unauthorized'
    '0x80190193' = 'HTTP 403 Forbidden'
    '0x80190194' = 'HTTP 404 Not Found'
    '0x801901F4' = 'HTTP 500 Internal Server Error'
    '0x801901F6' = 'HTTP 502 Bad Gateway'
    '0x801901F7' = 'HTTP 503 Service Unavailable'
    '0x801901F8' = 'HTTP 504 Gateway Timeout'
}

#endregion

#region ─── Helper Functions ──────────────────────────────────────────────────

function Format-Bytes {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function ConvertTo-MB {
    # Numeric MB value for GridView/CSV columns (sorts correctly, unlike '9.00 MB' strings)
    param($Bytes)
    if ($null -eq $Bytes) { return $null }
    [math]::Round([double]$Bytes / 1MB, 2)
}

function Format-TimeMs {
    param($Ms)
    if ($null -eq $Ms) { return '(not logged)' }
    $Ms = [long]$Ms
    if ($Ms -ge 3600000) { return "{0}h {1:D2}m" -f [math]::Floor($Ms / 3600000), [int][math]::Floor(($Ms % 3600000) / 60000) }
    if ($Ms -ge 60000)   { return "{0:N1} min" -f ($Ms / 60000) }
    if ($Ms -ge 1000)    { return "{0:N1} sec" -f ($Ms / 1000) }
    return "$Ms ms"
}

function Format-Pct {
    # Percentage of Part in Whole, or $null when Whole is zero/absent (avoids misleading 0%)
    param($Part, $Whole)
    if ($null -eq $Whole -or [double]$Whole -le 0) { return $null }
    return [math]::Round(([double]$Part / [double]$Whole) * 100, 1)
}

function Get-DODownloadModeDescription {
    param($Mode)
    if ($null -eq $Mode -or "$Mode" -eq '') { return '(not logged)' }
    $m = [int]$Mode
    if ($script:DODownloadModeNames.ContainsKey($m)) { return $script:DODownloadModeNames[$m] }
    return "Unknown ($m)"
}

function Get-DODownloadModeSrcDescription {
    param($Src)
    if ($null -eq $Src -or "$Src" -eq '') { return '(not logged)' }
    $s = [int]$Src
    if ($script:DODownloadModeSrcNames.ContainsKey($s)) { return $script:DODownloadModeSrcNames[$s] }
    return "Unknown ($s)"
}

function Get-DOModeGroups {
    # Groups downloads by DownloadMode with a numeric sort; downloads without a logged mode
    # get their own '(not logged)' group instead of being shown as mode 0 (HTTP Only)
    param([object[]]$Downloads)
    $Downloads |
        Group-Object { if ($null -eq $_.DownloadMode) { '(not logged)' } else { [string]$_.DownloadMode } } |
        Sort-Object { if ($_.Name -match '^\d+$') { [int]$_.Name } else { [int]::MaxValue } }
}

function Get-DOEventSource {
    # Function name of a log event, or the source file name when the Function field is empty
    # (e.g. 858 PolicyProvider.cpp errors in one sample log had no Function)
    param($LogEvent)
    if ($LogEvent.Function) { return $LogEvent.Function }
    if ($LogEvent.Message -match '\\([\w\.]+\.(?:cpp|h)),\s*\d+\]') { return "($($matches[1]))" }
    return '(unknown)'
}

function Get-DOJobWindow {
    # Estimated active window for an aggregated download: from its first segment (or completion
    # time minus duration, whichever is earlier) minus 2 minutes, to completion plus 2 minutes
    param([PSCustomObject]$Download)
    $end   = $Download.TimeCreated
    $start = $end.AddMilliseconds(-[math]::Max([long]$Download.DurationMs, 0))
    if ($Download.FirstSegmentTime -and $Download.FirstSegmentTime -lt $start) { $start = $Download.FirstSegmentTime }
    [PSCustomObject]@{ Start = $start.AddMinutes(-2); End = $end.AddMinutes(2) }
}

function Find-DOSwarmIds {
    # Correlates an aggregated download to discovery swarm IDs.
    # 1) ContentId == FileId   2) AltCatalogId == CDN URL without query   3) all swarms in the job window
    param([PSCustomObject]$Download)
    $fileId = $Download.FileId
    $ids = @($script:InternalAnnounce | Where-Object { $_.ContentId -and $fileId -and $_.ContentId -eq $fileId } |
        Select-Object -ExpandProperty SwarmId | Where-Object { $_ } | Sort-Object -Unique)
    if ($ids.Count -gt 0) { return [PSCustomObject]@{ SwarmIds = $ids; Method = 'ContentId'; Exact = $true } }

    if ($Download.CdnUrl) {
        $cleanUrl = $Download.CdnUrl.Split('?')[0].TrimEnd('/')
        $ids = @($script:InternalAnnounce | Where-Object {
            $_.AltCatalogId -and ($_.AltCatalogId.Split('?')[0].TrimEnd('/') -eq $cleanUrl)
        } | Select-Object -ExpandProperty SwarmId | Where-Object { $_ } | Sort-Object -Unique)
        if ($ids.Count -gt 0) { return [PSCustomObject]@{ SwarmIds = $ids; Method = 'AltCatalogId (Source URL)'; Exact = $true } }
    }

    $w = Get-DOJobWindow $Download
    $ids = @($script:InternalAnnounce | Where-Object { $_.TimeCreated -ge $w.Start -and $_.TimeCreated -le $w.End } |
        Select-Object -ExpandProperty SwarmId | Where-Object { $_ } | Sort-Object -Unique)
    return [PSCustomObject]@{ SwarmIds = $ids; Method = 'TimeWindow (approximate)'; Exact = $false }
}

function Format-ErrorCode {
    # Formats any error code representation (signed int, long, hex string, decimal string) as '0xHHHHHHHH'
    # -AlreadyHex: treat an all-digit string as hex, not decimal (e.g. ETW 'hr:' fields are always printed in hex)
    param($Code, [switch]$AlreadyHex)
    if ($null -eq $Code) { return $null }
    try {
        if ($Code -is [int] -or $Code -is [long] -or $Code -is [uint32] -or $Code -is [int64] -or $Code -is [uint64]) {
            # Keep the low 32 bits: handles signed int32 (-2133825522) and unsigned values (2161141774) alike
            $u = ([long]$Code) -band [long]4294967295
            return '0x{0:X8}' -f $u
        }
        if ($Code -is [string]) {
            $str = $Code.Trim()
            if ([string]::IsNullOrEmpty($str)) { return $null }
            if (-not $AlreadyHex -and $str -match '^-?\d+$') {
                # Truncate to the low 32 bits rather than casting to [int], which throws for
                # unsigned decimal HRESULT representations above 2147483647
                $u = [System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes([long]::Parse($str)), 0)
                return '0x{0:X8}' -f $u
            }
            if ($str -match '^(?:0[xX])?([0-9a-fA-F]+)$') {
                return '0x' + $matches[1].ToUpper().PadLeft(8, '0')
            }
        }
    } catch {}
    return [string]$Code
}

function Get-DOErrorDescription {
    # Accepts: signed int32 (from ETL ErrorCode property), hex string ('0x80D01001' or '80D01001'), or decimal string
    param($Code, [switch]$AlreadyHex)
    if ($null -eq $Code) { return $null }
    try {
        $hex = Format-ErrorCode $Code -AlreadyHex:$AlreadyHex
        if ($hex -and $script:DOErrorCodes.ContainsKey($hex)) {
            return $script:DOErrorCodes[$hex]
        }
    } catch {}
    return $null
}

function Get-MCCTypeDescription {
    # Classifies a Connected Cache server by its X-CID HTTP response header value.
    # X-CID < 100         → CDN (not MCC)
    # X-CID = 100         → MCC on Distribution Point (ConfigMgr DP)
    # X-CID = 10000       → MCC Standalone / Container
    # X-CID 100-9999      → MCC Enterprise / Hosted
    # X-CID > 10000       → Internet MCC (ISP/Microsoft-hosted)
    param([object]$XCid)
    if ($null -eq $XCid) { return $null }
    try {
        $cid = [int]$XCid
        if ($cid -lt 100)                      { return 'CDN' }
        if ($cid -eq 100)                      { return 'MCC on Distribution Point' }
        if ($cid -eq 10000)                    { return 'MCC Standalone' }
        if ($cid -gt 100 -and $cid -lt 10000)  { return 'MCC Enterprise' }
        if ($cid -gt 10000)                    { return 'Internet MCC' }
    } catch {}
    return "Unknown (X-CID=$XCid)"
}

function Show-DOByteSourceSummary {
    # Single renderer for the byte breakdown of one aggregated download (or a totals object with the same fields).
    # Percentages are of NetworkBytes (CDN + MCC + LAN + Group + Internet). Those sources are disjoint and add up
    # to DO's own session byte counter. Local cache (lcache) overlaps them and can exceed the file size, so it is
    # shown separately without a percentage.
    param(
        [PSCustomObject]$Download,
        [string]$TitleSuffix = '',
        [switch]$NoJobDetails
    )
    Write-SubHeader "Byte Sources$TitleSuffix"
    $net = [long]$Download.NetworkBytes
    $lanDoSvcBytes = [math]::Max(0, [long]$Download.LanBytes - [long]$Download.LinkLocalBytes)
    $sources = [ordered]@{
        'CDN'                       = @{ Bytes = [long]$Download.CdnBytes;       Color = 'Gray'  }
        'Connected Cache (MCC)'     = @{ Bytes = [long]$Download.DoincBytes;     Color = 'Cyan'  }
        'LAN peers (DO service)'    = @{ Bytes = $lanDoSvcBytes;                 Color = 'Green' }
        'Link-local peers (DNS-SD)' = @{ Bytes = [long]$Download.LinkLocalBytes; Color = 'Green' }
        'Group peers'               = @{ Bytes = [long]$Download.GroupBytes;     Color = 'Green' }
        'Internet peers'            = @{ Bytes = [long]$Download.InetBytes;      Color = 'Green' }
    }
    if ($net -gt 0) {
        foreach ($src in $sources.GetEnumerator()) {
            if ($src.Value.Bytes -gt 0) {
                Write-Host ("  {0,-27} : {1,10}  ({2}%)" -f $src.Key, (Format-Bytes $src.Value.Bytes), (Format-Pct $src.Value.Bytes $net)) -ForegroundColor $src.Value.Color
            }
        }
        Write-Host ("  {0,-27} : {1,10}" -f 'Network bytes (this log)', (Format-Bytes $net)) -ForegroundColor White
        $p2pPct   = Format-Pct $Download.P2PBytes $net
        $p2pColor = if ($p2pPct -gt 30) { 'Green' } elseif ($p2pPct -gt 0) { 'Yellow' } else { 'Red' }
        Write-Host ("  {0,-27} : {1}%  ({2})" -f 'Peer share (P2P)', $p2pPct, (Format-Bytes $Download.P2PBytes)) -ForegroundColor $p2pColor
    } else {
        Write-Host "  No bytes were downloaded over the network in this log." -ForegroundColor Yellow
    }
    if ([long]$Download.PreLogBytes -gt 0) {
        Write-Host ("  {0,-27} : {1,10}  (DO session counter; source not visible in this log)" -f 'Downloaded before this log', (Format-Bytes $Download.PreLogBytes)) -ForegroundColor DarkYellow
    }
    if ([long]$Download.LcacheBytes -gt 0) {
        Write-Host ("  {0,-27} : {1,10}  (re-read from DO cache; overlaps the sources above)" -f 'Served from local cache', (Format-Bytes $Download.LcacheBytes)) -ForegroundColor DarkGray
    }
    Write-Host ("  {0,-27} : {1,10}" -f 'File size', (Format-Bytes $Download.FileBytes)) -ForegroundColor Cyan
    if ($NoJobDetails) { return }

    Write-Host ("  {0,-27} : {1}" -f 'Duration', (Format-TimeMs $Download.DurationMs)) -ForegroundColor Cyan
    if ([long]$Download.AvgBytesPerSec -gt 0) {
        Write-Host ("  {0,-27} : {1}/s  (network bytes / duration)" -f 'Avg network throughput', (Format-Bytes $Download.AvgBytesPerSec)) -ForegroundColor Cyan
    }
    Write-Host ("  {0,-27} : {1}  ({2})" -f 'Download Mode', $Download.DownloadMode, (Get-DODownloadModeDescription $Download.DownloadMode)) -ForegroundColor Cyan
    Write-Host ("  {0,-27} : {1}  ({2})" -f 'Mode Source', $Download.DownloadModeSrc, (Get-DODownloadModeSrcDescription $Download.DownloadModeSrc)) -ForegroundColor Cyan
    if ($Download.MccHost) { Write-Host ("  {0,-27} : {1}" -f 'Cache host', $Download.MccHost) -ForegroundColor Cyan }
    if ($Download.IsVpn)       { Write-Host "  VPN was active during this download" -ForegroundColor Yellow }
    if ($Download.IsThrottled) { Write-Host "  Download was throttled"              -ForegroundColor Yellow }
}

function Get-DODownloadTotals {
    # Sums aggregated downloads into one object with the same byte fields Show-DOByteSourceSummary expects
    param([object[]]$Downloads)
    $sum = { param($p) [long](($Downloads | Measure-Object -Property $p -Sum).Sum) }
    $net = & $sum 'NetworkBytes'
    $p2p = & $sum 'P2PBytes'
    [PSCustomObject]@{
        FileBytes      = & $sum 'FileBytes'
        NetworkBytes   = $net
        P2PBytes       = $p2p
        PeerPct        = Format-Pct $p2p $net
        CdnBytes       = & $sum 'CdnBytes'
        DoincBytes     = & $sum 'DoincBytes'
        LanBytes       = & $sum 'LanBytes'
        LinkLocalBytes = & $sum 'LinkLocalBytes'
        GroupBytes     = & $sum 'GroupBytes'
        InetBytes      = & $sum 'InetBytes'
        LcacheBytes    = & $sum 'LcacheBytes'
        PreLogBytes    = & $sum 'PreLogBytes'
    }
}

function Show-DOPeerConnectionStats {
    # Peer connection counts by outcome. HTTP (CDN / cache server) connections are not peers and are counted apart.
    $peerConns  = @($script:ConnectionComplete | Where-Object { $_.Kind -eq 'Peer' })
    $ok         = @($peerConns | Where-Object { $_.Outcome -eq 'Connected' })
    $failed     = @($peerConns | Where-Object { $_.Outcome -eq 'Failed' })
    $httpConns  = @($script:ConnectionComplete | Where-Object { $_.Kind -eq 'HTTP' -and $_.Outcome -eq 'Connected' })
    $okIps      = @($ok.PeerIP | Sort-Object -Unique)
    $failIps    = @($failed.PeerIP | Sort-Object -Unique)
    Write-SubHeader "Peer Connections"
    Write-Host ("  Peer connections established : {0}  ({1} unique peer IP(s))" -f $ok.Count, $okIps.Count) -ForegroundColor $(if ($ok.Count -gt 0) { 'Green' } else { 'Yellow' })
    Write-Host ("  Peer connections failed      : {0}  ({1} unique peer IP(s))" -f $failed.Count, $failIps.Count) -ForegroundColor $(if ($failed.Count -gt 0) { 'Red' } else { 'Gray' })
    if ($failed.Count -gt 0) {
        $failed | Group-Object ErrorHex | Sort-Object Count -Descending | ForEach-Object {
            $desc = $_.Group[0].ErrorDesc
            Write-Host ("    {0,-12} x{1,-4} {2}" -f $_.Name, $_.Count, $(if ($desc) { "— $desc" } else { '' })) -ForegroundColor Red
        }
    }
    Write-Host ("  HTTP connections (CDN/cache) : {0}  ({1})" -f $httpConns.Count, ((@($httpConns.HttpHost | Sort-Object -Unique)) -join ', ')) -ForegroundColor Gray
}

function Write-Header {
    param([string]$Title)
    $line = "=" * 70
    Write-Host "`n$line" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
}

function Write-SubHeader {
    param([string]$Title)
    Write-Host "`n  --- $Title ---" -ForegroundColor Yellow
}

function Pause-ForUser {
    if ($script:NonInteractive) { return }
    Write-Host "`nPress Enter to continue..." -ForegroundColor DarkGray
    $null = Read-Host
}

function Write-DOTable {
    # Bordered console table -- a lightweight alternative to Out-GridView for small datasets
    param(
        [object[]]$Data,
        [string[]]$Columns,
        [scriptblock]$RowColor,
        [int]$MaxColWidth = 34
    )
    if (-not $Data -or $Data.Count -eq 0) { return }
    if (-not $Columns) { $Columns = @($Data[0].PSObject.Properties.Name) }

    $widths = @{}
    foreach ($c in $Columns) {
        $dataLen = ($Data | ForEach-Object { "$($_.$c)".Length } | Measure-Object -Maximum).Maximum
        $widths[$c] = [math]::Min([math]::Max($c.Length, $dataLen), $MaxColWidth)
    }

    $rule   = '  +' + (($Columns | ForEach-Object { '-' * ($widths[$_] + 2) }) -join '+') + '+'
    $header = '  |' + (($Columns | ForEach-Object { ' ' + $_.PadRight($widths[$_]) + ' ' }) -join '|') + '|'

    Write-Host $rule   -ForegroundColor DarkGray
    Write-Host $header -ForegroundColor Cyan
    Write-Host $rule   -ForegroundColor DarkGray
    foreach ($row in $Data) {
        $color = if ($RowColor) { & $RowColor $row } else { 'White' }
        $cells = $Columns | ForEach-Object {
            $val = "$($row.$_)"
            if ($val.Length -gt $widths[$_]) { $val = $val.Substring(0, $widths[$_] - 1) + '.' }
            ' ' + $val.PadRight($widths[$_]) + ' '
        }
        Write-Host ('  |' + ($cells -join '|') + '|') -ForegroundColor $color
    }
    Write-Host $rule -ForegroundColor DarkGray
}

function Test-DOGridViewAvailable {
    # Out-GridView needs a desktop session: it is missing on Server Core / Linux and fails in remote sessions
    if ($script:NoGridView) { return $false }
    if (-not (Get-Command Out-GridView -ErrorAction SilentlyContinue)) { return $false }
    if ($Host.Name -eq 'ServerRemoteHost' -or $PSSenderInfo) { return $false }
    if ([Environment]::OSVersion.Platform -ne 'Win32NT') { return $false }
    return $true
}

function Show-DOGrid {
    # Shows rows in Out-GridView, or as a numbered console table when GridView is unavailable.
    # -Single returns the chosen row (GridView selection or a typed row number).
    # -Columns limits the console table; GridView always shows every property.
    param(
        [object[]]$Data,
        [string]$Title,
        [switch]$Single,
        [string[]]$Columns,
        [int]$MaxRows = 40
    )
    $Data = @($Data | Where-Object { $null -ne $_ })
    if ($Data.Count -eq 0) {
        Write-Host "`n  $Title — no rows." -ForegroundColor Yellow
        if (-not $Single) { Pause-ForUser }
        return
    }
    if ($script:NonInteractive) { return }

    if (Test-DOGridViewAvailable) {
        if ($Single) {
            Write-Host "  Select a row in the GridView window..." -ForegroundColor Yellow
            return ($Data | Out-GridView -Title $Title -OutputMode Single)
        }
        $Data | Out-GridView -Title $Title
        Write-Host "  Opened in GridView: $Title" -ForegroundColor DarkGray
        Pause-ForUser
        return
    }

    # Console fallback
    if (-not $Columns) { $Columns = @($Data[0].PSObject.Properties.Name | Select-Object -First 7) }
    $shown = @($Data | Select-Object -First $MaxRows)
    $i = 0
    $rows = foreach ($r in $shown) {
        $o = [ordered]@{ '#' = $i++ }
        foreach ($c in $Columns) { $o[$c] = $r.$c }
        [PSCustomObject]$o
    }
    Write-SubHeader $Title
    Write-DOTable -Data $rows -Columns (@('#') + $Columns) -MaxColWidth 40
    if ($Data.Count -gt $MaxRows) {
        Write-Host "  Showing $MaxRows of $($Data.Count) rows. Use the Export menu for the full data set." -ForegroundColor DarkGray
    }
    if ($Single) {
        $answer = (Read-Host "  Row number (Enter to cancel)").Trim()
        if ($answer -match '^\d+$' -and [int]$answer -lt $shown.Count) { return $shown[[int]$answer] }
        return
    }
    Pause-ForUser
}

function Invoke-DOMenu {
    # Generic menu loop. Items: ordered list of @{ Key; Label; Action }; 'Q' always returns.
    # -Title may be a scriptblock so counts in the header refresh on every loop.
    param(
        $Title,
        [object[]]$Items,
        [switch]$RequireLogs,
        [string]$QuitLabel = 'Back'
    )
    do {
        if ($RequireLogs -and -not (Assert-LogsLoaded)) { return }
        $t = if ($Title -is [scriptblock]) { & $Title } else { $Title }
        Write-Header $t
        if ($script:RawLogs) { Show-DOFilterStatus }
        foreach ($it in $Items) {
            if ($it.Label -eq '-') { Write-Host ''; continue }
            Write-Host ("  {0}. {1}" -f $it.Key, $it.Label)
        }
        Write-Host "  Q. $QuitLabel"
        $sel  = (Read-Host "`n  Selection").Trim()
        if ($sel -eq '') { continue }      # Enter just redraws the menu
        if ($sel -ieq 'q') { return }
        $item = $Items | Where-Object { $_.Key -and $_.Key -ieq $sel } | Select-Object -First 1
        if ($item) { & $item.Action }
        else { Write-Host "  Invalid selection." -ForegroundColor Red; Pause-ForUser }
    } while ($true)
}

function Write-DOCard {
    # Bordered key/value card for a single object -- used where a GridView would otherwise open with just one row
    param(
        [string]$Title,
        [System.Collections.Specialized.OrderedDictionary]$Fields
    )
    $labelWidth = ($Fields.Keys | Measure-Object -Property Length -Maximum).Maximum
    Write-Host ""
    Write-Host ("  +-- {0}" -f $Title) -ForegroundColor Cyan
    foreach ($key in $Fields.Keys) {
        $val = $Fields[$key]
        # Only null/empty strings become '(none)'; 0 and $false are real values and must be shown
        if ($null -eq $val -or ($val -is [string] -and $val -eq '')) { $val = '(none)' }
        Write-Host ("  | {0} : {1}" -f $key.PadRight($labelWidth), $val) -ForegroundColor White
    }
    Write-Host "  +$('-' * 40)" -ForegroundColor Cyan
}

function Show-JobTimelineConsole {
    # Chronological, colour-coded rendering of a single job's event timeline (replaces the old GridView popup)
    param([object[]]$Timeline)
    $meta = @{
        'AnnounceRequest'  = @{ Icon = '->'; Color = 'DarkCyan' }
        'AnnounceResponse' = @{ Icon = '<-'; Color = 'Cyan' }
        'PeerConnected'    = @{ Icon = '<>'; Color = 'Green' }
        'PeerConnectFail'  = @{ Icon = 'X';  Color = 'Red' }
        'HttpConnected'    = @{ Icon = '>>'; Color = 'Gray' }
        'PeerDataTransfer' = @{ Icon = '<->'; Color = 'Yellow' }
        'DownloadComplete' = @{ Icon = 'OK'; Color = 'Magenta' }
    }
    Write-SubHeader "Event Timeline ($($Timeline.Count) events)"
    foreach ($e in $Timeline) {
        $m     = if ($meta.ContainsKey($e.EventType)) { $meta[$e.EventType] } else { @{ Icon = '*'; Color = 'White' } }
        $peer  = if ($e.PeerIP) { "  [$($e.PeerIP)]" } else { '' }
        $bytes = @(
            if ($e.BytesRecv) { "recv $($e.BytesRecv)" }
            if ($e.BytesSent) { "sent $($e.BytesSent)" }
        ) -join '  '
        Write-Host ("  {0}  {1,-4} {2,-17}{3}" -f $e.TimeCreated.ToString('HH:mm:ss.fff'), $m.Icon, $e.EventType, $peer) -ForegroundColor $m.Color
        if ($e.Detail) { Write-Host "                       $($e.Detail)" -ForegroundColor DarkGray }
        if ($bytes)    { Write-Host "                       $bytes"       -ForegroundColor DarkGray }
    }
}

#endregion

#region ─── Log Parsing Functions ─────────────────────────────────────────────

function Get-DOParsedDownloadComplete {
    param([object[]]$RawLogs)
    $RawLogs | Where-Object { $_.Function -eq 'CTelemetryLogger::TraceDownloadCompletedImpl' } |
    ForEach-Object {
        $msg = $_.Message
        [PSCustomObject]@{
            TimeCreated        = $_.TimeCreated
            Level              = $_.Level
            LevelName          = $_.LevelName
            ErrorCode          = $_.ErrorCode
            JobId              = if ($msg -match 'jobId: ([^,]+)') { $matches[1] } else { $null }
            FileId             = if ($msg -match 'fileId: ([^,]+)') { $matches[1] } else { $null }
            SessionId          = if ($msg -match 'sessionId: ([^,]+)') { $matches[1] } else { $null }
            UpdateId           = if ($msg -match 'updateId: ([^,]+)') { $matches[1] } else { $null }
            Caller             = if ($msg -match 'caller: ([^,]+)') { $matches[1] } else { $null }
            CdnUrl             = if ($msg -match 'cdnUrl = (https?://[^,]+)') { $matches[1] } else { $null }
            # 'cdnIp = 199.232.210.172:80;X-CCC:SE;X-CID:3' -> '199.232.210.172:80' (X-CID/X-CCC parsed separately)
            CdnIp              = if ($msg -match 'cdnIp = (.+?)(?:,|\s|$)') {
                ($matches[1] -replace '\[([^\]]+)\]', '$1').Split(';')[0]
            } else { $null }
            CacheHost          = if ($msg -match 'cacheHost = ([^,]*)') { $matches[1].Trim() } else { $null }
            # Cache server address without the source prefix ('Services:77.111.102.201' -> '77.111.102.201').
            # Accepts IPv4, bracketed/bare IPv6 and host names.
            MccHost            = if ($msg -match 'cacheHost = ([^,\s]+)') {
                # Strip a word prefix only if it contains a non-hex letter, so IPv6 such as 'fd::1' is kept intact
                $h = $matches[1] -replace '^(?=[A-Za-z]*[g-zG-Z])[A-Za-z]+:(?!:)', ''
                $h -replace '^\[(.+)\]$', '$1'
            } else { $null }
            XCid               = if ($msg -match 'X-CID:\s*(\d+)') { [int]$matches[1] } else { $null }
            XCcc               = if ($msg -match 'X-CCC:\s*([^;,\s]+)') { $matches[1] } else { $null }
            FileBytes          = if ($msg -match 'File: (\d+)') { [long]$matches[1] } else { $null }
            CdnBytes           = if ($msg -match 'CDN: (\d+)') { [long]$matches[1] } else { $null }
            DoincBytes         = if ($msg -match 'DOINC: (\d+)') { [long]$matches[1] } else { $null }
            RledbatBytes       = if ($msg -match 'rledbat: (\d+)') { [long]$matches[1] } else { $null }
            LanBytes           = if ($msg -match 'LAN: (\d+)') { [long]$matches[1] } else { $null }
            LinkLocalBytes     = if ($msg -match 'LinkLocal: (\d+)') { [long]$matches[1] } else { $null }
            GroupBytes         = if ($msg -match 'Group: (\d+)') { [long]$matches[1] } else { $null }
            InetBytes          = if ($msg -match 'inet: (\d+)') { [long]$matches[1] } else { $null }
            LcacheBytes        = if ($msg -match 'lcache: (\d+)') { [long]$matches[1] } else { $null }
            TotalBytes         = if ($msg -match 'total: \d+:(\d+)') { [long]$matches[1] }
                                   elseif ($msg -match 'total: (\d+)') { [long]$matches[1] }
                                   else { $null }
            Peers              = if ($msg -match 'peers: (\d+)') { [int]$matches[1] } else { $null }
            LocalPeers         = if ($msg -match 'local (\d+)') { [int]$matches[1] } else { $null }
            DownBps            = if ($msg -match 'downBps: (\d+)') { [long]$matches[1] } else { $null }
            UpBps              = if ($msg -match 'upBps: (\d+)') { [long]$matches[1] } else { $null }
            DownUsageBps       = if ($msg -match 'downUsageBps: (\d+)') { [long]$matches[1] } else { $null }
            UpUsageBps         = if ($msg -match 'upUsageBps: (\d+)') { [long]$matches[1] } else { $null }
            # \b stops 'timeMs' from matching inside 'sessionTimeMs' (-match is case-insensitive)
            TimeMs             = if ($msg -match '\btimeMs: (\d+)') { [long]$matches[1] } else { $null }
            SessionTimeMs      = if ($msg -match '\bsessionTimeMs: (\d+)') { [long]$matches[1] } else { $null }
            # Base64 group IDs can contain '+' and '/' (e.g. '+1Qvt4T9JImEh1m4...')
            GroupId            = if ($msg -match 'groupId = ([^,\s]+)') { $matches[1] } else { $null }
            Background         = if ($msg -match 'background\? ([01])') { $matches[1] -eq '1' } else { $null }
            UploadRestr        = if ($msg -match 'uploadRestr\: ([01])') { $matches[1] -eq '1' } else { $null }
            DownloadMode       = if ($msg -match 'downloadMode\: (\d+)') { [int]$matches[1] } else { $null }
            DownloadModeDesc   = if ($msg -match 'downloadMode\: (\d+)') { Get-DODownloadModeDescription ([int]$matches[1]) } else { $null }
            DownloadModeSrc    = if ($msg -match 'downloadModeSrc\: (\d+)') { [int]$matches[1] } else { $null }
            DownloadModeSrcDesc = if ($msg -match 'downloadModeSrc\: (\d+)') { Get-DODownloadModeSrcDescription ([int]$matches[1]) } else { $null }
            DownloadModeReason = if ($msg -match 'downloadModeReason\: (\d+)') { [int]$matches[1] } else { $null }
            IsVpn              = if ($msg -match 'isVpn\: ([01])') { $matches[1] -eq '1' } else { $null }
            Encrypted          = if ($msg -match 'encrypted\? ([01])') { $matches[1] -eq '1' } else { $null }
            IsThrottled        = if ($msg -match 'isThrottled = ([01])') { $matches[1] -eq '1' } else { $null }
            ExpireAt           = if ($msg -match 'expire at\: ([^,]+)') {
                try { [datetime]$matches[1] } catch { $matches[1] }
            } else { $null }
        }
    }
}

function Get-DOParsedAnnounceComplete {
    param([object[]]$RawLogs)
    $RawLogs | Where-Object { $_.Function -eq 'CAnnounceSequencer::_OnComplete' } |
    ForEach-Object {
        $msg = $_.Message
        $responseData = $null
        if ($msg -match 'response: ({.+})$') {
            try { $responseData = $matches[1] | ConvertFrom-Json } catch { $responseData = $matches[1] }
        } elseif ($msg -match 'response: (.*)$') {
            $responseData = $matches[1].Trim()
        }
        [PSCustomObject]@{
            TimeCreated              = $_.TimeCreated
            Level                    = $_.Level
            LevelName                = $_.LevelName
            ErrorCode                = $_.ErrorCode
            SwarmId                  = if ($msg -match 'Swarm:\s*([^,]+)') { $matches[1].Trim() } else { $null }
            Event                    = if ($msg -match 'event:\s*(\d+)') { [int]$matches[1] } else { $null }
            Hr                       = if ($msg -match 'hr:\s*([\w\d]+)') { $matches[1] } else { $null }
            Server                   = if ($msg -match 'server:\s*\[(.*?)\]') { $matches[1] } else { $null }
            ServerUrl                = if ($msg -match '\((https://[^)]+)\)') { $matches[1] } else { $null }
            NPeers                   = if ($msg -match 'nPeers:\s*(\d+)') { [int]$matches[1] } else { $null }
            FailureReason            = if ($responseData -is [PSObject] -and $responseData.FailureReason) { $responseData.FailureReason } else { $null }
            NextJoinTimeIntervalInMs = if ($responseData -is [PSObject] -and $responseData.NextJoinTimeIntervalInMs) { $responseData.NextJoinTimeIntervalInMs } else { $null }
            Complete                 = if ($responseData -is [PSObject] -and $null -ne $responseData.Complete) { $responseData.Complete } else { $null }
            Incomplete               = if ($responseData -is [PSObject] -and $null -ne $responseData.Incomplete) { $responseData.Incomplete } else { $null }
            Rediscover               = if ($responseData -is [PSObject] -and $null -ne $responseData.Rediscover) { $responseData.Rediscover } else { $null }
            KVVersion                = if ($responseData -is [PSObject] -and $responseData.KVVersion) { $responseData.KVVersion } else { $null }
            GeoVersion               = if ($responseData -is [PSObject] -and $responseData.GeoVersion) { $responseData.GeoVersion } else { $null }
            PeerCount                = if ($responseData -is [PSObject] -and $responseData.Peers) { $responseData.Peers.Count } else { $null }
            Peers                    = if ($responseData -is [PSObject] -and $responseData.Peers) { $responseData.Peers } else { $null }
            Leave                    = if ($responseData -is [PSObject] -and $null -ne $responseData.Leave) { $responseData.Leave } else { $null }
        }
    }
}

function Get-DOParsedInternalAnnounce {
    param([object[]]$RawLogs)
    $RawLogs | Where-Object { $_.Function -eq 'CAnnounceSequencer::_InternalAnnounce' } |
    ForEach-Object {
        $msg = $_.Message
        $jsonData = $null
        if ($msg -match 'announce request: ({.+})$') {
            try { $jsonData = $matches[1] | ConvertFrom-Json }
            catch { Write-Warning "Failed to parse InternalAnnounce JSON" }
        }
        $swarmId = if ($msg -match 'Swarm:\s*([^,]+),') { $matches[1].Trim() } else { $null }
        [PSCustomObject]@{
            TimeCreated          = $_.TimeCreated
            Level                = $_.Level
            LevelName            = $_.LevelName
            ErrorCode            = $_.ErrorCode
            SwarmId              = $swarmId
            ContentId            = if ($jsonData) { $jsonData.ContentId } else { $null }
            AltCatalogId         = if ($jsonData) { $jsonData.AltCatalogId } else { $null }
            PeerId               = if ($jsonData) { $jsonData.PeerId } else { $null }
            ReportedIp           = if ($jsonData) { $jsonData.ReportedIp } else { $null }
            SubnetMask           = if ($jsonData) { $jsonData.SubnetMask } else { $null }
            Ipv6                 = if ($jsonData) { $jsonData.Ipv6 } else { $null }
            IsBackground         = if ($jsonData) { [bool][int]$jsonData.IsBackground } else { $null }
            ClientCompactVersion = if ($jsonData) { $jsonData.ClientCompactVersion } else { $null }
            Uploaded             = if ($jsonData) { [long]$jsonData.Uploaded } else { $null }
            Downloaded           = if ($jsonData) { [long]$jsonData.Downloaded } else { $null }
            DownloadedCdn        = if ($jsonData) { [long]$jsonData.DownloadedCdn } else { $null }
            DownloadedDoinc      = if ($jsonData) { [long]$jsonData.DownloadedDoinc } else { $null }
            Left                 = if ($jsonData) { [long]$jsonData.Left } else { $null }
            JoinRequestEvent     = if ($jsonData) { [int]$jsonData.JoinRequestEvent } else { $null }
            JoinRequestEventDesc = if ($jsonData -and $script:DOJoinRequestEventNames.ContainsKey([int]$jsonData.JoinRequestEvent)) {
                $script:DOJoinRequestEventNames[[int]$jsonData.JoinRequestEvent]
            } else { $null }
            RestrictedUpload     = if ($jsonData) { [bool][int]$jsonData.RestrictedUpload } else { $null }
            PeersWanted          = if ($jsonData) { [int]$jsonData.PeersWanted } else { $null }
            GroupId              = if ($jsonData) { $jsonData.GroupId } else { $null }
            Scope                = if ($jsonData) { [int]$jsonData.Scope } else { $null }
            ScopeDesc            = if ($jsonData -and $script:DOScopeNames.ContainsKey([int]$jsonData.Scope)) {
                $script:DOScopeNames[[int]$jsonData.Scope]
            } else { $null }
            UploadedBPS          = if ($jsonData) { [long]$jsonData.UploadedBPS } else { $null }
            DownloadedBPS        = if ($jsonData) { [long]$jsonData.DownloadedBPS } else { $null }
            HttpDelayLeftSecs    = if ($jsonData) { [int]$jsonData.HttpDelayLeftSecs } else { $null }
            Profile              = if ($jsonData) { $jsonData.Profile } else { $null }
            Seq                  = if ($jsonData) { [int]$jsonData.Seq } else { $null }
        }
    }
}

function Get-DOParsedConnectionComplete {
    # CConnMan::ConnectionComplete emits, per connection:
    #   'Got connection complete for <target>'      (Level 5)  -> Outcome 'Attempt'
    #   'connected to <target> (<peerId>)'          (Level 4)  -> Outcome 'Connected'
    #   '<target> <reason>' with a non-zero ErrorCode (Level 3) -> Outcome 'Failed'
    # <target> is either [ip]:port (a peer) or an http(s) URL (CDN / Connected Cache).
    param([object[]]$RawLogs)
    $RawLogs | Where-Object { $_.Function -eq 'CConnMan::ConnectionComplete' } |
    ForEach-Object {
        $msg     = $_.Message
        $isHttp  = $msg -match 'https?://'
        $peerIp  = $null; $port = $null; $httpHost = $null; $peerId = $null
        if ($isHttp) {
            if ($msg -match 'https?://([^/:\s]+|\[[^\]]+\])') { $httpHost = $matches[1].Trim('[', ']') }
        } elseif ($msg -match '\[([0-9a-fA-F\.:]+)\]:(\d+)') {
            $peerIp = $matches[1]; $port = [int]$matches[2]
        }
        $failed  = ($_.ErrorCode -and $_.ErrorCode -ne 0)
        $outcome = if ($failed) { 'Failed' }
                   elseif ($msg -match '^\s*connected to') { 'Connected' }
                   else { 'Attempt' }
        if ($outcome -eq 'Connected' -and $msg -match '\(([0-9a-fA-F]{20,})\)\s*$') { $peerId = $matches[1] }
        $errHex  = if ($failed) { Format-ErrorCode $_.ErrorCode } else { $null }
        [PSCustomObject]@{
            TimeCreated  = $_.TimeCreated
            Level        = $_.Level
            LevelName    = $_.LevelName
            ErrorCode    = $_.ErrorCode
            Kind         = if ($isHttp) { 'HTTP' } elseif ($peerIp) { 'Peer' } else { 'Other' }
            Outcome      = $outcome
            PeerIP       = $peerIp
            Port         = $port
            PeerId       = $peerId
            HttpHost     = $httpHost
            ErrorHex     = $errHex
            ErrorDesc    = if ($errHex) { Get-DOErrorDescription $errHex } else { $null }
            Message      = $msg
        }
    }
}

function Get-DOParsedPeerStats {
    # Parses CSwarmConn::~CSwarmConn "peer stats (final)" events — one record per TCP session
    param([object[]]$RawLogs)
    $RawLogs | Where-Object {
        $_.Function -eq 'CSwarmConn::~CSwarmConn' -and $_.Message -match 'peer stats \(final\)'
    } | ForEach-Object {
        if ($_.Message -match 'Swarm:\s*([^,]+),\s*peer stats \(final\),\s*type:\s*(\w+),\s*pid:\s*(\w+),\s*ip:\s*\[(.+?)\]:(\d+),\s*sent:\s*(\d+),\s*received:\s*(\d+)') {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                SwarmId     = $matches[1].Trim()
                ConnType    = $matches[2]
                PeerId      = $matches[3]
                PeerIP      = $matches[4]
                Port        = [int]$matches[5]
                BytesSent   = [long]$matches[6]
                BytesRecv   = [long]$matches[7]
            }
        }
    }
}

function Get-DOParsedGeoResponse {
    param([object[]]$RawLogs)
    $RawLogs |
    Where-Object { $_.Function -eq 'CServiceConfigProvider::_CallService' -and $_.Message -match 'GEO(:)? response:' } |
    ForEach-Object {
        $jsonStr = $_.Message -replace 'GEO(:)? response: ?', ''
        $geo = $null
        try { $geo = $jsonStr | ConvertFrom-Json } catch {}
        [PSCustomObject]@{
            TimeCreated          = $_.TimeCreated
            Level                = $_.Level
            LevelName            = $_.LevelName
            ExternalIpAddress    = if ($geo) { $geo.ExternalIpAddress } else { $null }
            CountryCode          = if ($geo) { $geo.CountryCode } else { $null }
            CacheId              = if ($geo) { $geo.CacheId } else { $null }
            Version              = if ($geo) { $geo.Version } else { $null }
            ContentCert          = if ($geo -and $null -ne $geo.ContentCert) { $geo.ContentCert } else { $null }
            DownloadModeFailSafe = if ($geo) { $geo.DownloadModeFailSafe } else { $null }
            KeyValueUri          = if ($geo) { $geo.KeyValue_EndpointFullUri } else { $null }
            RawJson              = $jsonStr
        }
    }
}

function Get-DOMessageField {
    # Reads 'name = value' or 'name: value' from a telemetry message (value ends at the next comma)
    param([string]$Message, [string]$Name)
    if ($Message -match "\b$Name(?: =|:) ?([^,]*)") { $v = $matches[1].Trim(); if ($v -ne '') { return $v } }
    return $null
}

function Get-DOParsedJobEvents {
    # Lifecycle of each DO job: Started / Progress / Paused / Resumed (CTelemetryLogger::TraceDownload*).
    # Completion comes from DownloadComplete and is joined in Get-DOJobStates.
    param([object[]]$RawLogs)
    $map = @{
        'CTelemetryLogger::TraceDownloadStartedImpl' = 'Started'
        'CTelemetryLogger::TraceDownloadProgress'    = 'Progress'
        'CTelemetryLogger::TraceDownloadPaused'      = 'Paused'
        'CTelemetryLogger::TraceDownloadResumed'     = 'Resumed'
    }
    $RawLogs | Where-Object { $map.ContainsKey([string]$_.Function) } | ForEach-Object {
        $msg = $_.Message
        $hr  = Get-DOMessageField $msg 'hr'
        $hex = if ($hr -and $hr -notmatch '^0+$') { Format-ErrorCode $hr -AlreadyHex } else { $null }
        [PSCustomObject]@{
            TimeCreated  = $_.TimeCreated
            Event        = $map[$_.Function]
            JobId        = Get-DOMessageField $msg 'jobId'
            FileId       = Get-DOMessageField $msg 'fileId'
            SessionId    = Get-DOMessageField $msg 'sessionId'
            Caller       = Get-DOMessageField $msg 'caller'
            ErrorHex     = $hex
            ErrorDesc    = if ($hex) { Get-DOErrorDescription $hex } else { $null }
            ProgressPct  = if ($msg -match 'progressPct = (\d+)') { [int]$matches[1] } else { $null }
            DownloadMode = if ($msg -match 'downloadMode = (\d+)') { [int]$matches[1] } else { $null }
            # setConfigs JSON on Started events: effective DO settings for the job
            Configs      = if ($msg -match 'setConfigs: (\{.*\})') { try { $matches[1] | ConvertFrom-Json } catch { $null } } else { $null }
        }
    }
}

function Get-DOJobStates {
    # One row per JobId: when it started, whether a DownloadComplete was logged, pauses and last error
    param([object[]]$JobEvents, [object[]]$DownloadComplete)
    $completed = @{}
    foreach ($d in $DownloadComplete) { if ($d.JobId) { $completed[$d.JobId] = $d } }
    $JobEvents | Where-Object { $_.JobId } | Group-Object JobId | ForEach-Object {
        $evs     = $_.Group | Sort-Object TimeCreated
        $started = $evs | Where-Object Event -eq 'Started' | Select-Object -First 1
        $paused  = @($evs | Where-Object Event -eq 'Paused')
        $done    = $completed[$_.Name]
        $lastErr = $evs | Where-Object ErrorHex | Select-Object -Last 1
        $state   = if ($done) { if ($done.ErrorCode) { 'Completed with error' } else { 'Completed' } }
                   elseif (($evs[-1]).Event -eq 'Paused') { 'Paused (not completed)' }
                   else { 'Not completed in log' }
        [PSCustomObject]@{
            JobId        = $_.Name
            FileId       = ($evs | Where-Object FileId | Select-Object -First 1).FileId
            Caller       = if ($started) { $started.Caller } elseif ($done) { $done.Caller } else { $null }
            Started      = if ($started) { $started.TimeCreated } else { $null }
            LastEvent    = $evs[-1].TimeCreated
            State        = $state
            Pauses       = $paused.Count
            LastProgress = ($evs | Where-Object { $null -ne $_.ProgressPct } | Select-Object -Last 1).ProgressPct
            LastError    = if ($lastErr) { $lastErr.ErrorHex } else { $null }
            LastErrorDesc = if ($lastErr) { $lastErr.ErrorDesc } else { $null }
        }
    }
}

function Get-DOParsedServiceErrors {
    # CTelemetryLogger::TraceErrorServicesConnect — failures reaching DO cloud services (GEO, KV, discovery, CP)
    param([object[]]$RawLogs)
    $RawLogs | Where-Object { $_.Function -eq 'CTelemetryLogger::TraceErrorServicesConnect' } | ForEach-Object {
        $msg = $_.Message
        $hr  = Get-DOMessageField $msg 'hr'
        $hex = if ($hr) { Format-ErrorCode $hr -AlreadyHex } else { $null }
        $url = if ($msg -match 'url = (\S+?)(?:,|\s|$)') { $matches[1] } else { $null }
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            ErrorHex    = $hex
            ErrorDesc   = if ($hex) { Get-DOErrorDescription $hex } else { $null }
            ErrMsg      = if ($msg -match 'errMsg = (.*?), sessionId') { $matches[1] } else { $null }
            ServiceId   = if ($msg -match 'serviceId = (\d+)') { [int]$matches[1] } else { $null }
            ServiceHost = if ($url -match '^https?://([^/:?]+)') { $matches[1] } else { $null }
            Url         = $url
        }
    }
}

function Get-DOParsedCdnErrors {
    # CTelemetryLogger::TraceErrorCdnComm — HTTP failures against the CDN or a cache server
    # 'Too early to send FailureCdnCommunication event' lines are telemetry throttling notices, not errors
    param([object[]]$RawLogs)
    $RawLogs | Where-Object { $_.Function -eq 'CTelemetryLogger::TraceErrorCdnComm' -and $_.Message -match '\burl: ' } | ForEach-Object {
        $msg = $_.Message
        $hr  = Get-DOMessageField $msg 'hr'
        $hex = if ($hr) { Format-ErrorCode $hr -AlreadyHex } else { $null }
        $url = Get-DOMessageField $msg 'url'
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            ErrorHex    = $hex
            ErrorDesc   = if ($hex) { Get-DOErrorDescription $hex } else { $null }
            HttpCode    = Get-DOMessageField $msg 'httpCode'
            # 'expired? yes(2026-04-23T12:29:17Z)': the signed CDN URL was past its expiry when used
            UrlExpiredAt = if ($msg -match 'expired\? yes\(([^)]+)\)') { $matches[1] } else { $null }
            FileId      = Get-DOMessageField $msg 'fileId'
            Host        = if ($url -match '^https?://([^/:?]+)') { $matches[1] } else { $null }
            ServerIp    = if ($msg -match 'serverIp: \[([^\]]+)\]') { $matches[1] } else { $null }
            Url         = $url
        }
    }
}

function Get-DOParsedInboundHandshakes {
    # CSwarmConnPeerSockListener::OnPartialHandshake — other peers connecting to this machine (upload side)
    param([object[]]$RawLogs)
    $RawLogs | Where-Object { $_.Function -eq 'CSwarmConnPeerSockListener::OnPartialHandshake' } | ForEach-Object {
        if ($_.Message -match 'from \[([0-9a-fA-F\.:]+)\]:(\d+)\.\s*swarm\s+(\w+)') {
            [PSCustomObject]@{ TimeCreated = $_.TimeCreated; PeerIP = $matches[1]; Port = [int]$matches[2]; Swarm = $matches[3] }
        }
    }
}

function Get-DOConfigFromLog {
    # Effective DO settings from the most recent DownloadStarted event that carries setConfigs.
    # 'Provider' is DO's own source id for the value, shown as logged.
    param([object[]]$JobEvents)
    $latest = $JobEvents | Where-Object { $_.Event -eq 'Started' -and $_.Configs } | Sort-Object TimeCreated | Select-Object -Last 1
    if (-not $latest) { return @() }
    $latest.Configs.PSObject.Properties | ForEach-Object {
        [PSCustomObject]@{ Setting = $_.Name; Value = $_.Value.v; Provider = $_.Value.p; LoggedAt = $latest.TimeCreated }
    } | Sort-Object Setting
}

#endregion

#region ─── Log Loading ───────────────────────────────────────────────────────

function Resolve-DOLogSource {
    # Turns user input into a log source: 'L' / 'live', a folder containing dosvc*.etl files, or one .etl file.
    # Surrounding quotes (as pasted from Explorer's "Copy as path") are removed.
    param([string]$InputPath)
    $p = "$InputPath".Trim().Trim('"', "'").Trim()
    if ($p -ieq 'L' -or $p -ieq 'live') {
        return [PSCustomObject]@{ Kind = 'Live'; Path = $null; Files = @(); Desc = 'Live system' }
    }
    if (-not (Test-Path -LiteralPath $p)) {
        Write-Host "  ERROR: Path not found: $p" -ForegroundColor Red
        return $null
    }
    $item = Get-Item -LiteralPath $p
    if ($item.PSIsContainer) {
        $files = @(Get-ChildItem -LiteralPath $p -Recurse -File -Filter 'dosvc*.etl' | Sort-Object Name)
        if ($files.Count -eq 0) {
            $other = @(Get-ChildItem -LiteralPath $p -Recurse -File -Filter '*.etl')
            Write-Host "  ERROR: No dosvc*.etl files found in: $p" -ForegroundColor Red
            if ($other.Count -gt 0) { Write-Host "  Found $($other.Count) other .etl file(s); pass one directly to load it." -ForegroundColor Yellow }
            return $null
        }
        return [PSCustomObject]@{ Kind = 'Folder'; Path = $item.FullName; Files = $files; Desc = "ETL folder: $($item.FullName)" }
    }
    if ($item.Extension -ieq '.etl') {
        return [PSCustomObject]@{ Kind = 'File'; Path = $item.FullName; Files = @($item); Desc = "ETL file: $($item.FullName)" }
    }
    Write-Host "  ERROR: Not a folder or .etl file: $p" -ForegroundColor Red
    return $null
}

function Read-DOLogSource {
    # Interactive prompt; an empty answer only uses the previous path, never silently switches to the live log
    $default = $script:LogPath
    Write-Host "`n  Log source options:" -ForegroundColor White
    Write-Host "    L            Live system log on this machine" -ForegroundColor Gray
    Write-Host "    <folder>     Folder containing dosvc*.etl files (searched recursively)" -ForegroundColor Gray
    Write-Host "    <file.etl>   A single ETL file" -ForegroundColor Gray
    while ($true) {
        $prompt = if ($default) { "`n  Source (Enter = $default)" } else { "`n  Source" }
        $answer = (Read-Host $prompt).Trim()
        if ($answer -eq '' -and $default) { $answer = $default }
        if ($answer -eq '') { Write-Host "  Type L for the live log, or a path." -ForegroundColor Yellow; continue }
        $src = Resolve-DOLogSource $answer
        if ($src) { return $src }
        if ((Read-Host "  Try another source? (Y/n)").Trim() -ieq 'n') { return $null }
    }
}

function Get-DOUniqueDownloads {
    # Group the DownloadComplete events (one per DO job / byte-range request) by (FileId + SessionId)
    # into one logical download per file. FileBytes is the file size repeated on every event; the
    # per-source byte counters are per-event and disjoint, so they are summed.
    # Using SessionId as part of the key means a re-download of the same FileId gets its own entry.
    # Events with neither FileId nor SessionId parsed are kept as their own entries (keyed by JobId)
    # instead of all collapsing into one '|' group.
    param([object[]]$DownloadComplete)
    $DownloadComplete | Group-Object {
        if ($_.FileId -or $_.SessionId) { "$($_.FileId)|$($_.SessionId)" }
        else { "job|$($_.JobId)|$($_.TimeCreated.Ticks)" }
    } | ForEach-Object {
        $grp          = $_.Group | Sort-Object TimeCreated
        $rep          = $grp | Select-Object -Last 1
        $fileBytesMax = [long]($grp | Measure-Object FileBytes      -Maximum).Maximum
        $lanSum       = [long]($grp | Measure-Object LanBytes        -Sum).Sum
        $grpSum       = [long]($grp | Measure-Object GroupBytes      -Sum).Sum
        $inetSum      = [long]($grp | Measure-Object InetBytes       -Sum).Sum
        $cdnSum       = [long]($grp | Measure-Object CdnBytes        -Sum).Sum
        $doincSum     = [long]($grp | Measure-Object DoincBytes      -Sum).Sum
        $llSum        = [long]($grp | Measure-Object LinkLocalBytes  -Sum).Sum
        $lcacheSum    = [long]($grp | Measure-Object LcacheBytes     -Sum).Sum
        $sessTotalMax = [long]($grp | Measure-Object TotalBytes      -Maximum).Maximum
        $sessionMsMax = [long]($grp | Measure-Object SessionTimeMs   -Maximum).Maximum
        $timeMsMax    = [long]($grp | Measure-Object TimeMs          -Maximum).Maximum
        $downBpsMax   = [long]($grp | Measure-Object DownBps         -Maximum).Maximum
        $upBpsMax     = [long]($grp | Measure-Object UpBps           -Maximum).Maximum
        $mccHosts     = @($grp | Where-Object { $_.MccHost } | Select-Object -ExpandProperty MccHost -Unique)
        # Network sources are disjoint (verified: their sum equals DO's 'total:' session counter).
        # LinkLocal is a subset of LAN, so it is not added again.
        $p2pBytes     = $lanSum + $grpSum + $inetSum
        $netBytes     = $cdnSum + $doincSum + $p2pBytes
        $durationMs   = if ($sessionMsMax -gt 0) { $sessionMsMax } else { $timeMsMax }
        [PSCustomObject]@{
            TimeCreated         = $rep.TimeCreated
            FirstSegmentTime    = $grp[0].TimeCreated
            FileId              = $rep.FileId
            SessionId           = $rep.SessionId
            SegmentCount        = $grp.Count
            Caller              = $rep.Caller
            CdnUrl              = $rep.CdnUrl
            CdnIp               = $rep.CdnIp
            CacheHost           = $rep.CacheHost
            FileBytes           = if ($fileBytesMax -gt 0) { $fileBytesMax } else { $rep.FileBytes }
            NetworkBytes        = $netBytes
            P2PBytes            = $p2pBytes
            PeerPct             = Format-Pct $p2pBytes $netBytes
            SessionTotalBytes   = $sessTotalMax
            # Bytes DO counted for this session before the first event in this log
            PreLogBytes         = [math]::Max(0, $sessTotalMax - $netBytes)
            CdnBytes            = $cdnSum
            DoincBytes          = $doincSum
            LcacheBytes         = $lcacheSum
            LanBytes            = $lanSum
            LinkLocalBytes      = $llSum
            GroupBytes          = $grpSum
            InetBytes           = $inetSum
            Peers               = [int]($grp | Measure-Object Peers -Maximum).Maximum
            DownBps             = if ($downBpsMax -gt 0) { $downBpsMax } else { $rep.DownBps }
            UpBps               = if ($upBpsMax -gt 0) { $upBpsMax } else { $rep.UpBps }
            TimeMs              = $timeMsMax
            SessionTimeMs       = $sessionMsMax
            DurationMs          = $durationMs
            AvgBytesPerSec      = if ($netBytes -gt 0 -and $durationMs -gt 0) { [long]($netBytes / ($durationMs / 1000.0)) } else { 0 }
            DownloadMode        = $rep.DownloadMode
            DownloadModeDesc    = $rep.DownloadModeDesc
            DownloadModeSrc     = $rep.DownloadModeSrc
            DownloadModeSrcDesc = $rep.DownloadModeSrcDesc
            GroupId             = $rep.GroupId
            Background          = $rep.Background
            IsVpn               = $rep.IsVpn
            IsThrottled         = $rep.IsThrottled
            ErrorCode           = ($grp | Where-Object { $_.ErrorCode } | Select-Object -Last 1).ErrorCode
            MccHost             = $mccHosts -join '; '
        }
    }
}

# Names of the parsed collections; each lives in $script:All (full log) and as $script:<Name> (current view)
$script:DODatasets = @('DownloadComplete', 'AnnounceComplete', 'InternalAnnounce', 'ConnectionComplete', 'PeerStats',
                       'GeoResponses', 'ErrorEvents', 'JobEvents', 'ServiceErrors', 'CdnErrors', 'InboundHandshakes')

function Import-DOLogs {
    # Reads the log source, splits events by Function in one pass, and parses each event type from its own subset
    param([Parameter(Mandatory)][PSCustomObject]$Source)

    $activity = 'Loading Delivery Optimization logs'
    Write-Host "`n  Loading: $($Source.Desc)" -ForegroundColor Yellow
    if ($Source.Files.Count -gt 0) {
        $sizeMB = [math]::Round(($Source.Files | Measure-Object Length -Sum).Sum / 1MB, 1)
        Write-Host "  $($Source.Files.Count) ETL file(s), $sizeMB MB" -ForegroundColor Gray
    }
    Write-Progress -Activity $activity -Status 'Decoding ETL (this is the slow part)...' -PercentComplete 5
    try {
        $raw = if ($Source.Kind -eq 'Live') { Get-DeliveryOptimizationLog } else { Get-DeliveryOptimizationLog -Path $Source.Files.FullName }
    } catch {
        Write-Progress -Activity $activity -Completed
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
    $raw = @($raw)
    if ($raw.Count -eq 0) {
        Write-Progress -Activity $activity -Completed
        Write-Host "  WARNING: Log returned 0 entries." -ForegroundColor Yellow
        return $false
    }

    Write-Progress -Activity $activity -Status "Indexing $($raw.Count) events..." -PercentComplete 50
    $byFunc = @{}
    foreach ($e in $raw) {
        $k = [string]$e.Function
        if (-not $byFunc.ContainsKey($k)) { $byFunc[$k] = [System.Collections.Generic.List[object]]::new() }
        $byFunc[$k].Add($e)
    }
    $sub = {
        param([string[]]$Names)
        $out = [System.Collections.Generic.List[object]]::new()
        foreach ($n in $Names) { if ($byFunc.ContainsKey($n)) { $out.AddRange($byFunc[$n]) } }
        , $out.ToArray()
    }

    $steps = [ordered]@{
        DownloadComplete   = { Get-DOParsedDownloadComplete   (& $sub 'CTelemetryLogger::TraceDownloadCompletedImpl') }
        AnnounceComplete   = { Get-DOParsedAnnounceComplete   (& $sub 'CAnnounceSequencer::_OnComplete') }
        InternalAnnounce   = { Get-DOParsedInternalAnnounce   (& $sub 'CAnnounceSequencer::_InternalAnnounce') }
        ConnectionComplete = { Get-DOParsedConnectionComplete (& $sub 'CConnMan::ConnectionComplete') }
        PeerStats          = { Get-DOParsedPeerStats          (& $sub 'CSwarmConn::~CSwarmConn') }
        GeoResponses       = { Get-DOParsedGeoResponse        (& $sub 'CServiceConfigProvider::_CallService') }
        JobEvents          = { Get-DOParsedJobEvents          (& $sub 'CTelemetryLogger::TraceDownloadStartedImpl', 'CTelemetryLogger::TraceDownloadProgress', 'CTelemetryLogger::TraceDownloadPaused', 'CTelemetryLogger::TraceDownloadResumed') }
        ServiceErrors      = { Get-DOParsedServiceErrors      (& $sub 'CTelemetryLogger::TraceErrorServicesConnect') }
        CdnErrors          = { Get-DOParsedCdnErrors          (& $sub 'CTelemetryLogger::TraceErrorCdnComm') }
        InboundHandshakes  = { Get-DOParsedInboundHandshakes  (& $sub 'CSwarmConnPeerSockListener::OnPartialHandshake') }
        # Level 1=Critical, 2=Error, 3=Warning, 4=Info, 5=Verbose. Source = Function, or the .cpp file when Function is empty.
        ErrorEvents        = { $raw.Where({ $_.Level -ge 1 -and $_.Level -le 3 }) |
                                Select-Object TimeCreated, Level, LevelName, @{ N = 'Source'; E = { Get-DOEventSource $_ } },
                                    Function, ErrorCode, @{ N = 'ErrorHex'; E = { if ($_.ErrorCode) { Format-ErrorCode $_.ErrorCode } } },
                                    Message, ProcessId, ThreadId, LineNumber }
    }
    $all = @{}
    $i = 0
    foreach ($s in $steps.GetEnumerator()) {
        Write-Progress -Activity $activity -Status "Parsing $($s.Key)..." -PercentComplete (55 + [int](40 * $i++ / $steps.Count))
        $all[$s.Key] = @(& $s.Value)
    }

    # IP → X-CID lookup from any event carrying both a server IP and an X-CID header value
    $xcid = @{}
    foreach ($e in $raw.Where({ $_.Message -like '*X-CID*' })) {
        if ($e.Message -match '\[(\d{1,3}(?:\.\d{1,3}){3})\].*?X-CID:\s*(\d+)') {
            if (-not $xcid.ContainsKey($matches[1])) { $xcid[$matches[1]] = [int]$matches[2] }
        }
    }
    Write-Progress -Activity $activity -Completed

    $timeStats = $raw | Measure-Object TimeCreated -Minimum -Maximum
    $script:AllRaw        = $raw
    $script:All           = $all
    $script:XCidByIp      = $xcid
    $script:LogStart      = $timeStats.Minimum
    $script:LogEnd        = $timeStats.Maximum
    $script:LogSource     = $Source
    $script:LogSourceDesc = $Source.Desc
    if ($Source.Path) { $script:LogPath = $Source.Path }
    $script:DOConfig      = @(Get-DOConfigFromLog $all.JobEvents)
    $script:DOFilter        = @{ Start = $null; End = $null; Text = $null }
    Set-DOView

    Write-Host ""
    Write-Host ("  Loaded {0} events  {1}  →  {2}" -f $raw.Count, $script:LogStart, $script:LogEnd) -ForegroundColor Green
    Write-Host ("  {0} file download(s) from {1} job event(s), {2} peer connection event(s), {3} announce response(s)" -f `
        $script:UniqueDownloads.Count, $script:DownloadComplete.Count, $script:ConnectionComplete.Count, $script:AnnounceComplete.Count) -ForegroundColor Gray
    $errCount  = @($script:ErrorEvents | Where-Object { $_.Level -le 2 }).Count
    $warnCount = @($script:ErrorEvents | Where-Object { $_.Level -eq 3 }).Count
    Write-Host ("  {0} error and {1} warning event(s)" -f $errCount, $warnCount) -ForegroundColor $(if ($errCount -gt 0) { 'Yellow' } else { 'Gray' })
    $diag = @(Get-DODiagnosis)
    $sev  = foreach ($s in 'Error', 'Warning', 'Info', 'OK') {
        $n = @($diag | Where-Object Severity -eq $s).Count
        if ($n -gt 0) { "$n $($s.ToLower())" }
    }
    if ($sev -and -not $script:NonInteractive) { Write-Host ("  Diagnosis: {0}  (main menu option 2)" -f ($sev -join ', ')) -ForegroundColor Cyan }
    return $true
}

function Initialize-DOLogs {
    # Menu entry: prompt for a source (or use -LogPath when -Silent) and load it
    param([switch]$Silent)
    $src = if ($Silent -and $script:LogPath) { Resolve-DOLogSource $script:LogPath } else { Read-DOLogSource }
    if (-not $src) { return $false }
    return (Import-DOLogs -Source $src)
}

function Set-DOView {
    # Applies $script:DOFilter (time window for everything; text for download-related data) to the full
    # parsed data in $script:All and publishes the result as $script:<Dataset> for all reports.
    $f = $script:DOFilter
    $inTime = {
        param($t)
        (-not $f.Start -or $t -ge $f.Start) -and (-not $f.End -or $t -le $f.End)
    }
    foreach ($name in $script:DODatasets) {
        $data = $script:All[$name]
        if ($f.Start -or $f.End) { $data = @($data | Where-Object { & $inTime $_.TimeCreated }) }
        Set-Variable -Scope Script -Name $name -Value @($data)
    }
    $script:RawLogs = if ($f.Start -or $f.End) { $script:AllRaw.Where({ & $inTime $_.TimeCreated }) } else { $script:AllRaw }

    if ($f.Text) {
        $like = "*$($f.Text)*"
        $match = { param($o) $o.Caller -like $like -or $o.CdnUrl -like $like -or $o.FileId -like $like -or $o.SessionId -like $like -or $o.JobId -like $like }
        $script:DownloadComplete = @($script:DownloadComplete | Where-Object { & $match $_ })
        $jobIds  = @($script:DownloadComplete.JobId)
        $fileIds = @($script:DownloadComplete.FileId | Sort-Object -Unique)
        $script:JobEvents = @($script:JobEvents | Where-Object { (& $match $_) -or $jobIds -contains $_.JobId })
        $script:CdnErrors = @($script:CdnErrors | Where-Object { $fileIds -contains $_.FileId })
    }
    $script:UniqueDownloads = @(Get-DOUniqueDownloads $script:DownloadComplete)
    $script:JobStates       = @(Get-DOJobStates $script:JobEvents $script:DownloadComplete)
}

function Test-DOFilterActive { return [bool]($script:DOFilter -and ($script:DOFilter.Start -or $script:DOFilter.End -or $script:DOFilter.Text)) }

function Show-DOFilterStatus {
    if (-not (Test-DOFilterActive)) { return }
    $f = $script:DOFilter
    $parts = @()
    if ($f.Start -or $f.End) { $parts += "time {0} → {1}" -f $(if ($f.Start) { $f.Start } else { 'start' }), $(if ($f.End) { $f.End } else { 'end' }) }
    if ($f.Text)  { $parts += "text '$($f.Text)'" }
    $total = @(Get-DOUniqueDownloads $script:All.DownloadComplete).Count
    Write-Host ("  FILTER ACTIVE: {0}  ({1} of {2} downloads)" -f ($parts -join ', '), $script:UniqueDownloads.Count, $total) -ForegroundColor Magenta
}

function ConvertTo-DOFilterTime {
    # Accepts 'yyyy-MM-dd HH:mm[:ss]' or just 'HH:mm[:ss]' (taken on the log's first day)
    param([string]$Text)
    $t = $Text.Trim()
    if ($t -eq '') { return $null }
    if ($t -match '^\d{1,2}:\d{2}(:\d{2})?$') { $t = '{0:yyyy-MM-dd} {1}' -f $script:LogStart, $t }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse($t, [ref]$d)) { return $d }
    Write-Host "  Could not read '$Text' as a time; ignored." -ForegroundColor Yellow
    return $null
}

function Set-DOFilter {
    # Interactive filter editor
    if (-not (Assert-LogsLoaded)) { return }
    Write-Header "Filter"
    Write-Host "  Log covers $($script:LogStart) → $($script:LogEnd)" -ForegroundColor Gray
    Write-Host "  The time window applies to every report. The text filter matches caller, URL, FileId," -ForegroundColor Gray
    Write-Host "  SessionId or JobId and narrows the download-related reports." -ForegroundColor Gray
    Write-Host "  Enter C to clear all filters, or leave a field empty for no limit." -ForegroundColor Gray
    $start = (Read-Host "`n  From (HH:mm or yyyy-MM-dd HH:mm)").Trim()
    if ($start -ieq 'c') { $script:DOFilter = @{ Start = $null; End = $null; Text = $null }; Set-DOView; Write-Host "  Filters cleared." -ForegroundColor Green; Pause-ForUser; return }
    $end  = (Read-Host "  To   (HH:mm or yyyy-MM-dd HH:mm)").Trim()
    $text = (Read-Host "  Text").Trim()
    $script:DOFilter = @{ Start = (ConvertTo-DOFilterTime $start); End = (ConvertTo-DOFilterTime $end); Text = $(if ($text) { $text } else { $null }) }
    Set-DOView
    Show-DOFilterStatus
    if (-not (Test-DOFilterActive)) { Write-Host "  No filter set." -ForegroundColor Gray }
    Pause-ForUser
}

function Assert-LogsLoaded {
    if ($null -eq $script:AllRaw -or @($script:AllRaw).Count -eq 0) {
        Write-Host "`n  No logs loaded. Use option 1 to load logs first." -ForegroundColor Yellow
        Pause-ForUser
        return $false
    }
    return $true
}

#endregion

#region ─── Diagnosis ─────────────────────────────────────────────────────────

function New-DOFinding {
    param([ValidateSet('Error', 'Warning', 'Info', 'OK')][string]$Severity, [string]$Area, [string]$Finding, [string]$Evidence, [string]$Action)
    [PSCustomObject]@{ Severity = $Severity; Area = $Area; Finding = $Finding; Evidence = $Evidence; Action = $Action }
}

function Get-DODiagnosis {
    # Rule-based "why is peering (not) working" assessment over the current view
    $out = [System.Collections.Generic.List[object]]::new()
    $add = { param($f) $out.Add($f) }
    $dl  = @($script:UniqueDownloads)

    if ($dl.Count -eq 0) {
        & $add (New-DOFinding Info 'Downloads' 'No completed downloads in this log (or filter).' '' 'Reproduce the download with verbose DO logging enabled, then collect the log again.')
    }

    # ── Byte sources ──────────────────────────────────────────────────────────
    $t = Get-DODownloadTotals $dl
    if ($t.P2PBytes -gt 0) {
        & $add (New-DOFinding OK 'Peering' ("{0}% of network bytes came from peers." -f $t.PeerPct) ("{0} from peers out of {1} downloaded over the network." -f (Format-Bytes $t.P2PBytes), (Format-Bytes $t.NetworkBytes)) '')
    }
    if ($t.DoincBytes -gt 0) {
        & $add (New-DOFinding OK 'Connected Cache' ("{0}% of network bytes came from a Connected Cache server." -f (Format-Pct $t.DoincBytes $t.NetworkBytes)) (Format-Bytes $t.DoincBytes) '')
    }
    $noNet = @($dl | Where-Object { $_.NetworkBytes -eq 0 })
    if ($noNet.Count -gt 0) {
        & $add (New-DOFinding Info 'Downloads' "$($noNet.Count) download(s) moved no bytes over the network during this log." `
            ("Served from local cache: {0}. DO session counter before the log: {1}." -f (Format-Bytes ($noNet | Measure-Object LcacheBytes -Sum).Sum), (Format-Bytes ($noNet | Measure-Object PreLogBytes -Sum).Sum)) `
            'The content was already in the DO cache or downloaded before the log started. Clear the DO cache and capture a fresh download to test peering.')
    }

    # ── Download mode / VPN / file size ───────────────────────────────────────
    foreach ($m in @(0, 99, 100)) {
        $hit = @($dl | Where-Object { $_.DownloadMode -eq $m })
        if ($hit.Count -eq 0) { continue }
        $srcs = ($hit | ForEach-Object { Get-DODownloadModeSrcDescription $_.DownloadModeSrc } | Sort-Object -Unique) -join ', '
        $msg, $act = switch ($m) {
            0   { 'Download mode 0 (HTTP only): peering is turned off.', 'Set DODownloadMode to 1 (LAN) or 2 (Group) where peering is wanted.' }
            99  { 'Download mode 99 (Simple): DO fell back to HTTP because its cloud services were unreachable.', 'Allow HTTPS to *.prod.do.dsp.mp.microsoft.com and *.dl.delivery.mp.microsoft.com.' }
            100 { 'Download mode 100 (Bypass): DO is bypassed and BITS is used.', 'Remove the Bypass setting; it is deprecated.' }
        }
        & $add (New-DOFinding Warning 'Download mode' "$($hit.Count) download(s): $msg" "Mode source: $srcs" $act)
    }
    $vpn = @($dl | Where-Object IsVpn)
    if ($vpn.Count -gt 0) {
        & $add (New-DOFinding Warning 'VPN' "$($vpn.Count) download(s) ran while a VPN was detected." '' 'Peering is off on VPN unless DOAllowVPNPeerCaching is enabled.')
    }
    $minCfg = $script:DOConfig | Where-Object Setting -eq 'DOMinFileSizeToCache' | Select-Object -First 1
    if ($minCfg -and "$($minCfg.Value)" -match '^\d+$') {
        $small = @($dl | Where-Object { $_.FileBytes -gt 0 -and $_.FileBytes -lt [long]$minCfg.Value })
        if ($small.Count -gt 0) {
            & $add (New-DOFinding Info 'File size' "$($small.Count) file(s) are smaller than DOMinFileSizeToCache ($(Format-Bytes ([long]$minCfg.Value))) and are not peered by design." '' 'Lower DOMinFileSizeToCache if small files should be peered.')
        }
    }

    # ── Discovery (announce) ──────────────────────────────────────────────────
    $ac      = @($script:AnnounceComplete)
    $acErr   = @($ac | Where-Object { $_.Hr -and $_.Hr -notmatch '^0+$' })
    $acOk    = @($ac | Where-Object { -not $_.Hr -or $_.Hr -match '^0+$' })
    if ($acErr.Count -gt 0) {
        $codes = ($acErr | Group-Object { Format-ErrorCode $_.Hr -AlreadyHex } | ForEach-Object {
            $d = Get-DOErrorDescription $_.Name; "$($_.Name) x$($_.Count)$(if ($d) { " ($d)" })" }) -join '; '
        $hosts = ($acErr | ForEach-Object { if ($_.ServerUrl -match '^https?://([^/]+)') { $matches[1] } } | Sort-Object -Unique) -join ', '
        $sev   = if ($acOk.Count -eq 0) { 'Error' } else { 'Warning' }
        & $add (New-DOFinding $sev 'Peer discovery' "$($acErr.Count) of $($ac.Count) announce call(s) to the discovery service failed." "$codes. Server: $hosts" `
            'Allow HTTPS (443) from the client to *.prod.do.dsp.mp.microsoft.com, including through any proxy.')
    }
    $okWithPeers = @($acOk | Where-Object { $_.NPeers -gt 0 })
    if ($acOk.Count -gt 0 -and $okWithPeers.Count -eq 0) {
        $scope = ($script:InternalAnnounce | Where-Object ScopeDesc | Select-Object -ExpandProperty ScopeDesc -Unique) -join ', '
        $grp   = ($dl | Where-Object GroupId | Select-Object -ExpandProperty GroupId -Unique) -join ', '
        $evid  = (@($(if ($scope) { "Scope: $scope" }), $(if ($grp) { "GroupId: $grp" })) | Where-Object { $_ }) -join '. '
        & $add (New-DOFinding Warning 'Peer discovery' "Discovery answered $($acOk.Count) time(s) but never returned any peers." $evid `
            'Make sure other clients in the same group (or subnet for LAN mode) have this content and use the same DownloadMode and GroupId.')
    }

    # ── Peer connections ──────────────────────────────────────────────────────
    $ownIps   = @($script:InternalAnnounce.ReportedIp | Where-Object { $_ } | Sort-Object -Unique)
    $pc       = @($script:ConnectionComplete | Where-Object Kind -eq 'Peer')
    $okConn   = @($pc | Where-Object Outcome -eq 'Connected')
    $failConn = @($pc | Where-Object Outcome -eq 'Failed')
    $selfFail = @($failConn | Where-Object { $_.ErrorHex -eq '0x80D0680E' -and $ownIps -contains $_.PeerIP })
    $dupFail  = @($failConn | Where-Object { $_.ErrorHex -eq '0x80D0680E' -and $ownIps -notcontains $_.PeerIP })
    $othFail  = @($failConn | Where-Object { $_.ErrorHex -ne '0x80D0680E' })
    if ($okWithPeers.Count -gt 0 -and $okConn.Count -eq 0) {
        & $add (New-DOFinding Error 'Peer connections' 'Discovery returned peers, but no peer connection succeeded.' ("Max peers returned: {0}. Failed connections: {1}." -f ($okWithPeers | Measure-Object NPeers -Maximum).Maximum, $failConn.Count) `
            'Check that TCP 7680 is reachable between clients (Windows Firewall, network ACLs).')
    }
    if ($selfFail.Count -gt 0) {
        & $add (New-DOFinding Info 'Peer connections' "$($selfFail.Count) connection(s) to this machine's own address were rejected (0x80D0680E)." "Address: $(($selfFail.PeerIP | Sort-Object -Unique) -join ', ')" `
            'Discovery listed this client as a peer of itself. This is harmless on its own.')
    }
    if ($dupFail.Count -gt 0) {
        & $add (New-DOFinding Error 'Peer connections' "$($dupFail.Count) connection(s) were rejected because another machine reports this machine's peer ID (0x80D0680E)." "Address: $(($dupFail.PeerIP | Sort-Object -Unique) -join ', ')" `
            'Check for cloned images or copied DO state on those machines.')
    }
    if ($othFail.Count -gt 0) {
        $codes = ($othFail | Group-Object ErrorHex | ForEach-Object { "$($_.Name) x$($_.Count)$(if ($_.Group[0].ErrorDesc) { " ($($_.Group[0].ErrorDesc))" })" }) -join '; '
        & $add (New-DOFinding Warning 'Peer connections' "$($othFail.Count) peer connection(s) failed." $codes 'Check TCP 7680 reachability and the peers'' DO state.')
    }
    $noPeerData = @($dl | Where-Object { $_.NetworkBytes -gt 0 -and $_.P2PBytes -eq 0 -and $_.DownloadMode -in 1, 2, 3 })
    if ($noPeerData.Count -gt 0) {
        $why = if ($okConn.Count -gt 0) { "Peers were connected ($($okConn.Count) connection(s)) but delivered no content." } else { 'No peer connection was established.' }
        & $add (New-DOFinding Warning 'Peering' "$($noPeerData.Count) download(s) in a peering mode got no bytes from peers." "$why CDN: $(Format-Bytes ($noPeerData | Measure-Object CdnBytes -Sum).Sum), MCC: $(Format-Bytes ($noPeerData | Measure-Object DoincBytes -Sum).Sum)." `
            'Peers may not hold the content yet, or DODelay*DownloadFromHttp is too short for peers to be tried first.')
    }

    # ── Cloud services / CDN / jobs ───────────────────────────────────────────
    $svc = @($script:ServiceErrors | Where-Object { $_.ServiceHost -notlike 'array*' })   # discovery covered above
    foreach ($g in ($svc | Group-Object ServiceHost, ErrorHex)) {
        $e = $g.Group[0]
        & $add (New-DOFinding Warning 'Cloud services' "Could not reach $($e.ServiceHost) ($($g.Count) time(s))." "$($e.ErrorHex)$(if ($e.ErrorDesc) { " $($e.ErrorDesc)" }). $($e.ErrMsg)" `
            'Allow HTTPS to *.prod.do.dsp.mp.microsoft.com. GEO and KeyValue failures can force Simple mode.')
    }
    $expired = @($script:CdnErrors | Where-Object UrlExpiredAt)
    if ($expired.Count -gt 0) {
        $exp = ($expired.UrlExpiredAt | Sort-Object -Unique) -join ', '
        & $add (New-DOFinding Warning 'HTTP source' "$($expired.Count) request(s) were rejected because the download URL had expired." "Host: $(($expired.Host | Sort-Object -Unique) -join ', '). URL expired at: $exp. $(($expired | ForEach-Object { "$($_.ErrorHex) $($_.ErrorDesc)" } | Sort-Object -Unique) -join '; ')" `
            'The caller normally fetches a fresh URL. Repeated expiries point at a long-running or resumed job, or a wrong system clock.')
    }
    foreach ($g in ($script:CdnErrors | Where-Object { -not $_.UrlExpiredAt } | Group-Object Host, ErrorHex)) {
        $e = $g.Group[0]
        & $add (New-DOFinding Warning 'HTTP source' "$($g.Count) HTTP error(s) from $($e.Host)." "$($e.ErrorHex)$(if ($e.ErrorDesc) { " $($e.ErrorDesc)" }), HTTP status $($e.HttpCode)" `
            'DO retries on other sources; repeated errors point at the cache server or proxy.')
    }
    $notDone = @($script:JobStates | Where-Object { $_.State -ne 'Completed' })
    if ($notDone.Count -gt 0) {
        $states = ($notDone | Group-Object State | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join '; '
        $errs   = ($notDone | Where-Object LastError | ForEach-Object { "$($_.LastError)$(if ($_.LastErrorDesc) { " $($_.LastErrorDesc)" })" } | Sort-Object -Unique) -join '; '
        & $add (New-DOFinding Warning 'Jobs' "$($notDone.Count) job(s) did not complete cleanly in this log." "$states$(if ($errs) { ". Errors: $errs" })" 'See Download Analysis > Failed / incomplete jobs.')
    }
    $paused = @($script:JobEvents | Where-Object { $_.Event -eq 'Paused' -and $_.ErrorHex })
    $pausedDone = @($paused | Where-Object { $j = $_.JobId; ($script:JobStates | Where-Object JobId -eq $j).State -eq 'Completed' })
    if ($pausedDone.Count -gt 0) {
        $errs = ($pausedDone | ForEach-Object { "$($_.ErrorHex)$(if ($_.ErrorDesc) { " $($_.ErrorDesc)" })" } | Sort-Object -Unique) -join '; '
        & $add (New-DOFinding Info 'Jobs' "$($pausedDone.Count) job(s) were paused with an error and later completed." $errs '')
    }

    # ── Upload side ───────────────────────────────────────────────────────────
    $inb = @($script:InboundHandshakes | Where-Object { $ownIps -notcontains $_.PeerIP })
    if ($inb.Count -gt 0) {
        & $add (New-DOFinding Info 'Uploads' "$($inb.Count) inbound peer handshake(s) from $(@($inb.PeerIP | Sort-Object -Unique).Count) other machine(s)." '' 'Other clients are asking this machine for content. See Peer / P2P Activity > Upload activity.')
    }

    $order = @{ Error = 0; Warning = 1; Info = 2; OK = 3 }
    $out | Sort-Object { $order[$_.Severity] }
}

function Show-DODiagnosis {
    param([switch]$NoPause)
    if (-not (Assert-LogsLoaded)) { return }
    Write-Header "Diagnosis"
    Show-DOFilterStatus
    $colors = @{ Error = 'Red'; Warning = 'Yellow'; Info = 'Cyan'; OK = 'Green' }
    $findings = @(Get-DODiagnosis)
    foreach ($f in $findings) {
        Write-Host ""
        Write-Host ("  [{0}] {1}: {2}" -f $f.Severity.ToUpper(), $f.Area, $f.Finding) -ForegroundColor $colors[$f.Severity]
        if ($f.Evidence) { Write-Host "      Evidence: $($f.Evidence)" -ForegroundColor Gray }
        if ($f.Action)   { Write-Host "      Action  : $($f.Action)"   -ForegroundColor DarkGray }
    }
    if (-not $NoPause) { Pause-ForUser }
}

function Show-DOConfig {
    if (-not (Assert-LogsLoaded)) { return }
    Write-Header "Delivery Optimization Configuration"
    if ($script:DOConfig.Count -gt 0) {
        Write-Host "  Settings logged with the most recent download start ($($script:DOConfig[0].LoggedAt))." -ForegroundColor Gray
        Write-Host "  'Provider' is the source id DO logged for the value." -ForegroundColor Gray
        Write-DOTable -Data $script:DOConfig -Columns @('Setting', 'Value', 'Provider') -MaxColWidth 50
    } else {
        Write-Host "  No configuration found in the log (no DownloadStarted event with setConfigs)." -ForegroundColor Yellow
    }
    if ($script:LogSource.Kind -eq 'Live' -and (Get-Command Get-DOConfig -ErrorAction SilentlyContinue)) {
        Write-SubHeader "Live configuration on $env:COMPUTERNAME (Get-DOConfig)"
        try { Get-DOConfig -Verbose 4>&1 | Out-String -Width 200 | Write-Host } catch { Write-Host "  Get-DOConfig failed: $($_.Exception.Message)" -ForegroundColor Yellow }
    }
    Pause-ForUser
}

function Show-DOJobStates {
    # Jobs that did not complete cleanly: completed with an error, paused at the end of the log, or never completed
    $bad = @($script:JobStates | Where-Object { $_.State -ne 'Completed' } | Sort-Object Started)
    Write-Header "Failed / Incomplete Jobs"
    if ($bad.Count -eq 0) {
        Write-Host "  Every job in this log completed without an error ($($script:JobStates.Count) job(s))." -ForegroundColor Green
        Pause-ForUser
        return
    }
    $bad | Group-Object State | ForEach-Object { Write-Host ("  {0,-24} : {1}" -f $_.Name, $_.Count) -ForegroundColor Yellow }
    Show-DOGrid -Data $bad -Title "Failed / incomplete jobs ($($bad.Count))" -Columns @('Started', 'State', 'Caller', 'LastProgress', 'LastError', 'LastErrorDesc', 'JobId')
}

function Show-DOUploadActivity {
    # What this machine served to other peers
    Write-Header "Upload Activity (this machine as a source)"
    $ownIps = @($script:InternalAnnounce.ReportedIp | Where-Object { $_ } | Sort-Object -Unique)
    $note   = { param($ip) if ($ownIps -contains $ip) { 'this machine' } else { '' } }
    $sent = @($script:PeerStats | Where-Object { $_.BytesSent -gt 0 } | Group-Object PeerIP | ForEach-Object {
        [PSCustomObject]@{
            PeerIP   = $_.Name
            Note     = & $note $_.Name
            Sessions = $_.Count
            SentMB   = ConvertTo-MB ($_.Group | Measure-Object BytesSent -Sum).Sum
            Sent     = Format-Bytes ($_.Group | Measure-Object BytesSent -Sum).Sum
        } } | Sort-Object SentMB -Descending)
    $totalSent = [long]($script:PeerStats | Measure-Object BytesSent -Sum).Sum
    $announced = [long]($script:InternalAnnounce | Group-Object SwarmId | ForEach-Object { ($_.Group | Measure-Object Uploaded -Maximum).Maximum } | Measure-Object -Sum).Sum
    Write-Host ("  Bytes sent to peers (TCP sessions in log) : {0}" -f (Format-Bytes $totalSent)) -ForegroundColor White
    Write-Host ("  Uploaded, as reported to discovery         : {0}" -f (Format-Bytes $announced)) -ForegroundColor White
    $inb = @($script:InboundHandshakes)
    Write-Host ("  Inbound peer handshakes                    : {0} from {1} address(es)" -f $inb.Count, @($inb.PeerIP | Sort-Object -Unique).Count) -ForegroundColor White
    $restricted = @($script:DownloadComplete | Where-Object UploadRestr)
    if ($restricted.Count -gt 0) { Write-Host "  Uploads were restricted on $($restricted.Count) job(s) (uploadRestr = 1)." -ForegroundColor Yellow }
    if ($sent.Count -gt 0) {
        Write-SubHeader "Sent per peer"
        Write-DOTable -Data $sent -Columns @('PeerIP', 'Note', 'Sessions', 'Sent')
    }
    if ($inb.Count -gt 0) {
        Write-SubHeader "Inbound handshakes per address"
        $rows = $inb | Group-Object PeerIP | Sort-Object Count -Descending | ForEach-Object {
            [PSCustomObject]@{ PeerIP = $_.Name; Note = & $note $_.Name; Handshakes = $_.Count; Swarms = @($_.Group.Swarm | Sort-Object -Unique).Count; Last = ($_.Group | Sort-Object TimeCreated)[-1].TimeCreated.ToString('HH:mm:ss') }
        }
        Write-DOTable -Data @($rows) -Columns @('PeerIP', 'Note', 'Handshakes', 'Swarms', 'Last')
    }
    Pause-ForUser
}

#endregion

#region ─── Summary Dashboard ────────────────────────────────────────────────

function Show-SummaryDashboard {
    if (-not (Assert-LogsLoaded)) { return }

    Write-Header "Summary Dashboard"
    Write-Host "  Source: $($script:LogSourceDesc)" -ForegroundColor Gray
    Write-Host "  Time range: $($script:LogStart)  →  $($script:LogEnd)" -ForegroundColor Gray
    Show-DOFilterStatus

    # Headline findings; full evidence and actions are in the Diagnosis view
    $colors = @{ Error = 'Red'; Warning = 'Yellow'; Info = 'Cyan'; OK = 'Green' }
    $top = @(Get-DODiagnosis | Where-Object { $_.Severity -ne 'Info' })
    if ($top.Count -gt 0) {
        Write-SubHeader "Key Findings"
        foreach ($f in $top) { Write-Host ("  [{0}] {1}" -f $f.Severity.ToUpper(), $f.Finding) -ForegroundColor $colors[$f.Severity] }
    }

    # Downloads — UniqueDownloads groups the per-job events by (FileId+SessionId) so FileBytes is not multiplied
    Write-SubHeader "Downloads ($($script:UniqueDownloads.Count) unique files, $($script:DownloadComplete.Count) job events)"

    if ($script:DownloadComplete.Count -gt 0) {
        $totals = Get-DODownloadTotals $script:UniqueDownloads
        Show-DOByteSourceSummary -Download $totals -TitleSuffix ' (all downloads)' -NoJobDetails

        if ($totals.DoincBytes -gt 0) {
            # Per-server X-CID type breakdown
            $mccServers = $script:DownloadComplete | Where-Object { $_.DoincBytes -gt 0 -and $_.MccHost } |
                Select-Object -ExpandProperty MccHost -Unique | Sort-Object | ForEach-Object {
                    $xcid    = if ($script:XCidByIp.ContainsKey($_)) { $script:XCidByIp[$_] } else { $null }
                    $mccType = if ($null -ne $xcid) { Get-MCCTypeDescription $xcid } else { 'type unknown (X-CID not observed)' }
                    $xcStr   = if ($null -ne $xcid) { " (X-CID=$xcid)" } else { '' }
                    "    MCC server $_${xcStr}  → $mccType"
                }
            foreach ($line in $mccServers) { Write-Host $line -ForegroundColor DarkCyan }
        }

        # By download mode
        Write-SubHeader "Download Mode Breakdown"
        Get-DOModeGroups $script:UniqueDownloads | ForEach-Object {
            $modeDesc = Get-DODownloadModeDescription $_.Group[0].DownloadMode
            Write-Host ("  Mode {0,-12} {1,-35} : {2} file(s)" -f $_.Name, "($modeDesc)", $_.Count) -ForegroundColor White
        }

        # By caller
        Write-SubHeader "Callers"
        $script:UniqueDownloads | Group-Object Caller | Sort-Object Count -Descending | ForEach-Object {
            Write-Host ("  {0,-40} : {1} file(s)" -f $_.Name, $_.Count) -ForegroundColor White
        }
    }

    # Peers
    if ($script:ConnectionComplete.Count -gt 0) {
        Show-DOPeerConnectionStats
    }

    # GEO
    if ($script:GeoResponses.Count -gt 0) {
        Write-SubHeader "Network Identity"
        $latest = $script:GeoResponses | Sort-Object TimeCreated | Select-Object -Last 1
        Write-Host "  External IP  : $($latest.ExternalIpAddress)" -ForegroundColor White
        Write-Host "  Country      : $($latest.CountryCode)" -ForegroundColor White
        if ($latest.KeyValueUri) {
            Write-Host "  KeyValue Endpoint : $($latest.KeyValueUri)" -ForegroundColor Cyan
        }
        if ($latest.Version) {
            Write-Host "  Config Ver   : $($latest.Version.Substring(0, [math]::Min(16, $latest.Version.Length)))..." -ForegroundColor DarkGray
        }
    }

    # Errors & Warnings (Level 1=Critical, Level 2=Error, Level 3=Warning)
    $errL2 = @($script:ErrorEvents | Where-Object { $_.Level -le 2 })
    $errL3 = @($script:ErrorEvents | Where-Object { $_.Level -eq 3 })
    Write-SubHeader "Errors / Warnings"
    if ($errL2.Count -eq 0 -and $errL3.Count -eq 0) {
        Write-Host "  No errors or warnings recorded." -ForegroundColor Green
    } else {
        if ($errL2.Count -gt 0) {
            Write-Host ("  Errors (Level 1/2) : {0,5} events" -f $errL2.Count) -ForegroundColor Red
            $errL2 | Group-Object Source | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
                # Collect any HRESULT codes from ErrorCode property or embedded in Message
                $codes = $_.Group | ForEach-Object {
                    if ($_.ErrorCode -and $_.ErrorCode -ne 0) {
                        $_.ErrorHex
                    } elseif ($_.Message -match '(?i)(?:error|hr)[: ]+([0-9a-fA-F]{6,8})\b') {
                        '0x' + $matches[1].ToUpper().PadLeft(8,'0')
                    }
                } | Where-Object { $_ } | Sort-Object -Unique
                $desc = if ($codes) { $codes | ForEach-Object { Get-DOErrorDescription $_ } | Where-Object { $_ } | Select-Object -First 1 } else { $null }
                $codeStr = if ($codes) { "  [$($codes -join ', ')]" } else { '' }
                $descStr = if ($desc)  { "  — $desc" }               else { '' }
                Write-Host ("    x{0,-5} {1}{2}{3}" -f $_.Count, $_.Name, $codeStr, $descStr) -ForegroundColor Red
            }
        }
        if ($errL3.Count -gt 0) {
            Write-Host ("  Warnings (Level 3) : {0,5} events" -f $errL3.Count) -ForegroundColor Yellow
            $errL3 | Group-Object Source | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
                $codes = $_.Group | Where-Object { $_.ErrorCode -and $_.ErrorCode -ne 0 } |
                    ForEach-Object { $_.ErrorHex } | Sort-Object -Unique
                $codeStr = if ($codes) { "  [$($codes -join ', ')]" } else { '' }
                Write-Host ("    x{0,-5} {1}{2}" -f $_.Count, $_.Name, $codeStr) -ForegroundColor Yellow
            }
        }
    }

    Pause-ForUser
}

#endregion

#region ─── Download Analysis ────────────────────────────────────────────────

function Select-DODownloadRows {
    # Standard GridView/console row for aggregated downloads: numeric MB columns sort correctly,
    # FileId + SessionId map a selected row back to its UniqueDownloads entry
    param([object[]]$Downloads)
    $Downloads | Select-Object TimeCreated, Caller,
        @{ N = 'FileMB';       E = { ConvertTo-MB $_.FileBytes } },
        @{ N = 'NetworkMB';    E = { ConvertTo-MB $_.NetworkBytes } },
        PeerPct,
        @{ N = 'PeerMB';       E = { ConvertTo-MB $_.P2PBytes } },
        @{ N = 'CdnMB';        E = { ConvertTo-MB $_.CdnBytes } },
        @{ N = 'MccMB';        E = { ConvertTo-MB $_.DoincBytes } },
        @{ N = 'LocalCacheMB'; E = { ConvertTo-MB $_.LcacheBytes } },
        @{ N = 'DurationSec';  E = { [math]::Round([long]$_.DurationMs / 1000, 1) } },
        @{ N = 'Mode';         E = { $_.DownloadModeDesc } },
        @{ N = 'JobEvents';    E = { $_.SegmentCount } },
        MccHost, IsVpn, CdnUrl, FileId, SessionId
}

function Select-DODownload {
    # Lets the user pick one aggregated download; returns the full UniqueDownloads object
    param([object[]]$Downloads = $script:UniqueDownloads, [string]$Title = 'Select a download')
    $Downloads = @($Downloads)
    if ($Downloads.Count -eq 0) { Write-Host "`n  No downloads in this log (or filter)." -ForegroundColor Yellow; Pause-ForUser; return }
    if ($Downloads.Count -eq 1) { return $Downloads[0] }
    $pick = Show-DOGrid -Data (Select-DODownloadRows $Downloads) -Title "$Title ($($Downloads.Count))" -Single `
        -Columns @('TimeCreated', 'Caller', 'FileMB', 'NetworkMB', 'PeerPct', 'Mode')
    if (-not $pick) { Write-Host "  No selection made." -ForegroundColor Gray; return }
    $Downloads | Where-Object { $_.FileId -eq $pick.FileId -and $_.SessionId -eq $pick.SessionId } | Select-Object -First 1
}

function Show-DownloadList {
    param([object[]]$Downloads, [string]$Title)
    Show-DOGrid -Data (Select-DODownloadRows $Downloads) -Title "$Title ($(@($Downloads).Count))" `
        -Columns @('TimeCreated', 'Caller', 'FileMB', 'NetworkMB', 'PeerPct', 'CdnMB', 'MccMB', 'Mode')
}

function Show-DownloadAnalysisMenu {
    Invoke-DOMenu -RequireLogs -Title { "Download Analysis  ($($script:UniqueDownloads.Count) files, $($script:DownloadComplete.Count) job events)" } -Items @(
        @{ Key = '1'; Label = 'All downloads (one row per file/session)';   Action = { Show-DownloadList $script:UniqueDownloads 'All downloads' } }
        @{ Key = '2'; Label = 'Downloads by caller';                        Action = { Show-DownloadsByCaller } }
        @{ Key = '3'; Label = 'Session summary (byte sources for one file)'; Action = { Invoke-SessionSummary } }
        @{ Key = '4'; Label = 'Trace one job event (full event timeline)';  Action = { Invoke-JobTrace } }
        @{ Key = '5'; Label = 'Failed / incomplete jobs';                   Action = { Show-DOJobStates } }
        @{ Key = '6'; Label = 'Downloads with peer bytes';                  Action = { Show-DownloadList @($script:UniqueDownloads | Where-Object { $_.P2PBytes -gt 0 }) 'Downloads with peer bytes' } }
        @{ Key = '7'; Label = 'Downloads via Connected Cache (MCC)';        Action = { Show-DownloadList @($script:UniqueDownloads | Where-Object { $_.DoincBytes -gt 0 }) 'Downloads via Connected Cache' } }
        @{ Key = '8'; Label = 'All job events (raw, one row per DO job)';   Action = { Show-DOGrid -Data $script:DownloadComplete -Title "DownloadComplete job events ($($script:DownloadComplete.Count))" -Columns @('TimeCreated', 'Caller', 'JobId', 'LanBytes', 'CdnBytes', 'DoincBytes', 'LcacheBytes') } }
    )
}

function Show-DownloadsByCaller {
    # Normalize null/empty/whitespace Caller to '(Unknown)' so they collapse into one group
    $callerOf = { if ([string]::IsNullOrWhiteSpace($_.Caller)) { '(Unknown)' } else { $_.Caller } }
    $callers = @($script:UniqueDownloads | Group-Object $callerOf | Sort-Object Count -Descending |
        ForEach-Object { [PSCustomObject]@{ Caller = $_.Name; Files = $_.Count; NetworkMB = ConvertTo-MB ($_.Group | Measure-Object NetworkBytes -Sum).Sum; PeerPct = (Get-DODownloadTotals $_.Group).PeerPct } })
    if ($callers.Count -eq 0) { Write-Host "`n  No callers found." -ForegroundColor Yellow; Pause-ForUser; return }

    $pick = if ($callers.Count -eq 1) { $callers[0] } else { Show-DOGrid -Data $callers -Title 'Select a caller' -Single -Columns @('Caller', 'Files', 'NetworkMB', 'PeerPct') }
    if (-not $pick) { return }
    $filtered = @($script:UniqueDownloads | Where-Object { (& $callerOf) -eq $pick.Caller })
    Show-DownloadList $filtered "Downloads by $($pick.Caller)"
}

#endregion

#region ─── Job Trace ────────────────────────────────────────────────────────

function Invoke-JobTrace {
    if ($script:DownloadComplete.Count -eq 0) {
        Write-Host "`n  No completed downloads to trace." -ForegroundColor Yellow
        Pause-ForUser
        return
    }

    # Pick the file first, then (if it has several) the job event within it
    $file = Select-DODownload -Title 'Select a download to trace'
    if (-not $file) { return }
    $jobs = @($script:DownloadComplete | Where-Object { $_.FileId -eq $file.FileId -and $_.SessionId -eq $file.SessionId } | Sort-Object TimeCreated)
    $selectedJob = if ($jobs.Count -le 1) { $jobs[0] } else {
        $rows = $jobs | Select-Object TimeCreated, JobId,
            @{ N = 'PeerMB';       E = { ConvertTo-MB ([long]$_.LanBytes + [long]$_.GroupBytes + [long]$_.InetBytes) } },
            @{ N = 'CdnMB';        E = { ConvertTo-MB $_.CdnBytes } },
            @{ N = 'MccMB';        E = { ConvertTo-MB $_.DoincBytes } },
            @{ N = 'LocalCacheMB'; E = { ConvertTo-MB $_.LcacheBytes } },
            @{ N = 'JobTimeSec';   E = { [math]::Round([long]$_.TimeMs / 1000, 1) } }, ErrorCode
        $pick = Show-DOGrid -Data $rows -Title "Select a job event ($($jobs.Count) for this file)" -Single -Columns @('TimeCreated', 'PeerMB', 'CdnMB', 'MccMB', 'LocalCacheMB', 'JobTimeSec')
        if ($pick) { $jobs | Where-Object { $_.JobId -eq $pick.JobId -and $_.TimeCreated -eq $pick.TimeCreated } | Select-Object -First 1 }
    }
    if (-not $selectedJob) {
        Write-Host "  No job selected." -ForegroundColor Gray
        return
    }

    $fileId  = $selectedJob.FileId
    $jobId   = $selectedJob.JobId
    $jobTime = $selectedJob.TimeCreated

    # Use UniqueDownloads aggregated bytes so all job events for this file/session are summed correctly
    $fileDownload = $script:UniqueDownloads | Where-Object {
        $_.FileId -eq $fileId -and $_.SessionId -eq $selectedJob.SessionId
    } | Select-Object -First 1
    $srcRef = if ($fileDownload) { $fileDownload } else { $selectedJob }

    # Time window covers the whole file download (first job event minus duration), not just this job
    $window      = Get-DOJobWindow $srcRef
    $windowStart = $window.Start
    $windowEnd   = $window.End

    Write-Header "Job Trace: $jobId"
    Write-Host "  FileId     : $fileId" -ForegroundColor Gray
    Write-Host "  Caller     : $($selectedJob.Caller)" -ForegroundColor Gray
    Write-Host "  Completed  : $jobTime" -ForegroundColor Gray
    Write-Host "  Window     : $($windowStart.ToString('HH:mm:ss')) → $($windowEnd.ToString('HH:mm:ss'))" -ForegroundColor Gray

    $corr     = Find-DOSwarmIds $srcRef
    $swarmIds = $corr.SwarmIds
    Write-Host ("  Swarm match: {0} — {1} swarm(s)" -f $corr.Method, $swarmIds.Count) -ForegroundColor $(if ($corr.Exact) { 'Green' } else { 'Yellow' })
    if (-not $corr.Exact) {
        Write-Host "  Announce and peer events below may include other downloads active in the same window." -ForegroundColor Yellow
    }

    # Build timeline — flat descriptive columns usable directly in GridView
    $timeline = [System.Collections.Generic.List[PSCustomObject]]::new()

    # AnnounceRequest events (InternalAnnounce — what DO sent to the discovery server)
    $iaEvents = $script:InternalAnnounce | Where-Object {
        $_.TimeCreated -ge $windowStart -and $_.TimeCreated -le $windowEnd -and
        ($swarmIds.Count -eq 0 -or $swarmIds -contains $_.SwarmId)
    }
    foreach ($e in $iaEvents) {
        $timeline.Add([PSCustomObject]@{
            TimeCreated = $e.TimeCreated
            EventType   = 'AnnounceRequest'
            PeerIP      = $e.ReportedIp
            SwarmId     = $e.SwarmId
            BytesRecv   = if ($e.Downloaded -gt 0) { Format-Bytes $e.Downloaded } else { '' }
            BytesSent   = if ($e.Uploaded   -gt 0) { Format-Bytes $e.Uploaded   } else { '' }
            Detail      = "Scope=$($e.ScopeDesc)  Seq=$($e.Seq)  Event=$($e.JoinRequestEventDesc)  Left=$(Format-Bytes $e.Left)"
        })
    }

    # AnnounceResponse events (AnnounceComplete — what the discovery server returned)
    $acEvents = $script:AnnounceComplete | Where-Object {
        $_.TimeCreated -ge $windowStart -and $_.TimeCreated -le $windowEnd -and
        ($swarmIds.Count -eq 0 -or $swarmIds -contains $_.SwarmId)
    }
    foreach ($e in $acEvents) {
        $timeline.Add([PSCustomObject]@{
            TimeCreated = $e.TimeCreated
            EventType   = 'AnnounceResponse'
            PeerIP      = ''
            SwarmId     = $e.SwarmId
            BytesRecv   = ''
            BytesSent   = ''
            Detail      = if ($e.FailureReason) { "FAILED: $($e.FailureReason)  Hr=$($e.Hr)" }
                          else { "NPeers=$($e.NPeers)  PeerCount=$($e.PeerCount)  Server=$($e.Server)" }
        })
    }

    # Connection outcomes (CConnMan::ConnectionComplete). These events carry no SwarmId, so they are
    # matched by time window only. 'Attempt' events are skipped; each is followed by Connected or Failed.
    $ccEvents = $script:ConnectionComplete | Where-Object {
        $_.TimeCreated -ge $windowStart -and $_.TimeCreated -le $windowEnd -and $_.Outcome -ne 'Attempt'
    }
    foreach ($e in $ccEvents) {
        $type, $target, $detail = switch ($e.Outcome) {
            'Failed'    { 'PeerConnectFail'; $(if ($e.PeerIP) { "$($e.PeerIP):$($e.Port)" } else { $e.HttpHost }); "FAILED $($e.ErrorHex)  $($e.ErrorDesc)" }
            default {
                if ($e.Kind -eq 'HTTP') { 'HttpConnected'; $e.HttpHost; 'HTTP connection (CDN / cache server)' }
                else { 'PeerConnected'; "$($e.PeerIP):$($e.Port)"; "Peer connection established  PeerId=$($e.PeerId)" }
            }
        }
        $timeline.Add([PSCustomObject]@{
            TimeCreated = $e.TimeCreated
            EventType   = $type
            PeerIP      = $target
            SwarmId     = ''
            BytesRecv   = ''
            BytesSent   = ''
            Detail      = $detail
        })
    }

    # PeerDataTransfer events (CSwarmConn::~CSwarmConn final stats — bytes per TCP session)
    $psEvents = if ($swarmIds.Count -gt 0) {
        @($script:PeerStats | Where-Object { $swarmIds -contains $_.SwarmId })
    } else {
        @($script:PeerStats | Where-Object { $_.TimeCreated -ge $windowStart -and $_.TimeCreated -le $windowEnd })
    }
    foreach ($e in $psEvents) {
        $timeline.Add([PSCustomObject]@{
            TimeCreated = $e.TimeCreated
            EventType   = 'PeerDataTransfer'
            PeerIP      = if ($e.Port) { "$($e.PeerIP):$($e.Port)" } else { $e.PeerIP }
            SwarmId     = $e.SwarmId
            BytesRecv   = if ($e.BytesRecv -gt 0) { Format-Bytes $e.BytesRecv } else { '' }
            BytesSent   = if ($e.BytesSent -gt 0) { Format-Bytes $e.BytesSent } else { '' }
            Detail      = "ConnType=$($e.ConnType)  PeerId=$($e.PeerId)"
        })
    }

    # DownloadComplete marker for the selected job event
    $jobPeerBytes = [long]$selectedJob.LanBytes + [long]$selectedJob.GroupBytes + [long]$selectedJob.InetBytes
    $timeline.Add([PSCustomObject]@{
        TimeCreated = $selectedJob.TimeCreated
        EventType   = 'DownloadComplete'
        PeerIP      = $selectedJob.CdnIp
        SwarmId     = ''
        BytesRecv   = ''
        BytesSent   = ''
        Detail      = "This job: CDN=$(Format-Bytes $selectedJob.CdnBytes)  Peers=$(Format-Bytes $jobPeerBytes)  MCC=$(Format-Bytes $selectedJob.DoincBytes)  LocalCache=$(Format-Bytes $selectedJob.LcacheBytes)  JobTime=$(Format-TimeMs $selectedJob.TimeMs)  Mode=$(Get-DODownloadModeDescription $selectedJob.DownloadMode)"
    })

    $sortedTimeline = $timeline | Sort-Object TimeCreated

    Show-JobTimelineConsole -Timeline $sortedTimeline

    # Console byte summary — use unified Show-DOByteSourceSummary
    $segNote = if ($fileDownload -and $fileDownload.SegmentCount -gt 1) { " for this file (aggregated across $($fileDownload.SegmentCount) job events)" } else { ' for this file' }
    Show-DOByteSourceSummary -Download $srcRef -TitleSuffix $segNote

    Pause-ForUser
}

function Invoke-SessionSummary {
    if ($script:UniqueDownloads.Count -eq 0) {
        Write-Host "`n  No aggregated downloads found." -ForegroundColor Yellow
        Pause-ForUser
        return
    }

    $selected = Select-DODownload -Title 'Select a file/session to summarise'
    if (-not $selected) { return }

    Write-Header "Session Summary: $($selected.FileId)"
    Write-Host "  FileId     : $($selected.FileId)"     -ForegroundColor Gray
    Write-Host "  SessionId  : $($selected.SessionId)"  -ForegroundColor Gray
    Write-Host "  Caller     : $($selected.Caller)"     -ForegroundColor Gray
    Write-Host "  Completed  : $($selected.TimeCreated)" -ForegroundColor Gray
    Write-Host "  Segments   : $($selected.SegmentCount)" -ForegroundColor Gray

    $segNote = if ($selected.SegmentCount -gt 1) { " (aggregated across $($selected.SegmentCount) job events)" } else { '' }
    Show-DOByteSourceSummary -Download $selected -TitleSuffix $segNote

    Pause-ForUser
}

#endregion

#region ─── Peer / P2P Activity ──────────────────────────────────────────────

function Show-PeerActivityMenu {
    Invoke-DOMenu -RequireLogs -Title 'Peer / P2P Activity' -Items @(
        @{ Key = '1'; Label = 'Peer efficiency report';                 Action = { Show-PeerEfficiencyReport } }
        @{ Key = '2'; Label = 'P2P activity for one download';          Action = { Show-PerJobPeerActivity } }
        @{ Key = '3'; Label = 'Peering failure analysis';               Action = { Show-PeeringFailureAnalysis } }
        @{ Key = '4'; Label = 'Upload activity (this machine as a source)'; Action = { Show-DOUploadActivity } }
        @{ Label = '-' }
        @{ Key = '5'; Label = 'Announce responses (raw)';  Action = { Show-DOGrid -Data $script:AnnounceComplete -Title "Announce responses ($($script:AnnounceComplete.Count))" -Columns @('TimeCreated', 'SwarmId', 'Hr', 'NPeers', 'FailureReason', 'Server') } }
        @{ Key = '6'; Label = 'Announce requests (raw)';   Action = { Show-DOGrid -Data $script:InternalAnnounce -Title "Announce requests ($($script:InternalAnnounce.Count))" -Columns @('TimeCreated', 'SwarmId', 'ScopeDesc', 'JoinRequestEventDesc', 'ReportedIp', 'Left') } }
        @{ Key = '7'; Label = 'Peer connections (raw)';    Action = { Show-DOGrid -Data $script:ConnectionComplete -Title "Connection events ($($script:ConnectionComplete.Count))" -Columns @('TimeCreated', 'Kind', 'Outcome', 'PeerIP', 'HttpHost', 'ErrorHex', 'ErrorDesc') } }
    )
}

function Show-PeerEfficiencyReport {
    Write-Header "Peer Efficiency Report"
    if ($script:DownloadComplete.Count -eq 0) {
        Write-Host "  No completed downloads." -ForegroundColor Yellow
        Pause-ForUser
        return
    }

    # Overall — UniqueDownloads avoids counting FileBytes once per job event
    Show-DOByteSourceSummary -Download (Get-DODownloadTotals $script:UniqueDownloads) -TitleSuffix ' (overall)' -NoJobDetails

    # By Download Mode — P2P share is of network bytes, not file size
    Write-SubHeader "By Download Mode"
    Get-DOModeGroups $script:UniqueDownloads | ForEach-Object {
        $modeDesc = Get-DODownloadModeDescription $_.Group[0].DownloadMode
        $t        = Get-DODownloadTotals $_.Group
        $pctStr   = if ($null -ne $t.PeerPct) { "$($t.PeerPct)% P2P" } else { 'no network bytes in log' }
        Write-Host ("  Mode {0,-12} {1,-35} : {2} file(s), {3} over network, {4}" -f $_.Name, "($modeDesc)", $_.Count, (Format-Bytes $t.NetworkBytes), $pctStr) -ForegroundColor White
    }

    if ($script:ConnectionComplete.Count -gt 0) {
        Show-DOPeerConnectionStats
    }
    $sent = [long]($script:PeerStats | Measure-Object BytesSent -Sum).Sum
    if ($sent -gt 0 -or $script:InboundHandshakes.Count -gt 0) {
        Write-SubHeader "Uploads"
        Write-Host ("  Sent to peers : {0}  ({1} inbound handshake(s); see Upload activity)" -f (Format-Bytes $sent), $script:InboundHandshakes.Count) -ForegroundColor White
    }

    Pause-ForUser
}

function Show-PerJobPeerActivity {
    $fullJob = Select-DODownload -Title 'Select a download for P2P analysis'
    if (-not $fullJob) { return }
    $fileId  = $fullJob.FileId
    $jobTime = $fullJob.TimeCreated

    Write-Header "P2P Activity: $($fullJob.Caller)"
    Write-Host ("  FileId     : {0}" -f $fileId)            -ForegroundColor Gray
    Write-Host ("  SessionId  : {0}" -f $fullJob.SessionId) -ForegroundColor Gray
    Write-Host ("  Job events : {0}" -f $fullJob.SegmentCount) -ForegroundColor Gray
    Write-Host ("  Completed  : {0}" -f $jobTime)           -ForegroundColor Gray
    Write-Host ("  File size  : {0}" -f (Format-Bytes $fullJob.FileBytes)) -ForegroundColor Gray
    Write-Host ("  Duration   : {0}" -f (Format-TimeMs $fullJob.DurationMs)) -ForegroundColor Gray
    Write-Host ("  Mode       : {0}" -f $fullJob.DownloadModeDesc)         -ForegroundColor Gray
    Write-Host ("  CdnUrl     : {0}" -f $fullJob.CdnUrl)   -ForegroundColor Gray

    # ── Correlate to SwarmId ──────────────────────────────────────────────────
    $window   = Get-DOJobWindow $fullJob
    $corr     = Find-DOSwarmIds $fullJob
    $swarmIds = $corr.SwarmIds
    Write-Host ("  Swarm correlation : {0} — {1} swarm(s)" -f $corr.Method, $swarmIds.Count) -ForegroundColor $(if ($corr.Exact) { 'Green' } else { 'Yellow' })

    $announceReqs  = if ($swarmIds.Count -gt 0) {
        @($script:InternalAnnounce | Where-Object { $swarmIds -contains $_.SwarmId })
    } else { @() }
    $announceResps = if ($swarmIds.Count -gt 0) {
        @($script:AnnounceComplete | Where-Object { $swarmIds -contains $_.SwarmId })
    } else { @() }

    # ── Announce Summary ──────────────────────────────────────────────────────
    Write-SubHeader "Announce Activity"
    if ($swarmIds.Count -gt 0) {
        Write-Host ("  Swarm ID(s)               : {0}" -f ($swarmIds -join ', ')) -ForegroundColor Gray
    }
    Write-Host ("  Announce requests sent    : {0}" -f $announceReqs.Count)  -ForegroundColor White
    Write-Host ("  Announce responses rcvd   : {0}" -f $announceResps.Count) -ForegroundColor White

    if ($announceResps.Count -gt 0) {
        $withPeers = @($announceResps | Where-Object { $_.NPeers -gt 0 })
        $noPeers   = @($announceResps | Where-Object { $null -eq $_.NPeers -or $_.NPeers -eq 0 })
        $withFail  = @($announceResps | Where-Object { $_.FailureReason })
        $withHrErr = @($announceResps | Where-Object { $_.Hr -and $_.Hr -notin @('0', '00000000') })
        $maxPeers  = if ($withPeers) { ($withPeers | Measure-Object NPeers -Maximum).Maximum } else { 0 }

        Write-Host ("  Responses with peers      : {0}" -f $withPeers.Count) -ForegroundColor $(if ($withPeers.Count -gt 0) { 'Green' } else { 'Yellow' })
        Write-Host ("  Responses with 0 peers    : {0}" -f $noPeers.Count)   -ForegroundColor $(if ($noPeers.Count -gt 0) { 'Yellow' } else { 'Gray' })
        Write-Host ("  Failure reason responses  : {0}" -f $withFail.Count)  -ForegroundColor $(if ($withFail.Count -gt 0) { 'Red' } else { 'Gray' })
        Write-Host ("  Non-zero HR responses     : {0}" -f $withHrErr.Count) -ForegroundColor $(if ($withHrErr.Count -gt 0) { 'Red' } else { 'Gray' })
        Write-Host ("  Peak peers seen at once   : {0}" -f $maxPeers)        -ForegroundColor $(if ($maxPeers -gt 0) { 'Green' } else { 'Yellow' })

        if ($withFail.Count -gt 0) {
            Write-SubHeader "Failure Details"
            $withFail | ForEach-Object {
                Write-Host ("  {0}  Hr={1}  Reason={2}" -f $_.TimeCreated, $_.Hr, $_.FailureReason) -ForegroundColor Red
            }
        }
        if ($withHrErr.Count -gt 0 -and $withFail.Count -eq 0) {
            Write-SubHeader "Non-zero HR Responses"
            $withHrErr | ForEach-Object {
                $hrFmt   = Format-ErrorCode $_.Hr -AlreadyHex
                $desc    = Get-DOErrorDescription $_.Hr -AlreadyHex
                $descStr = if ($desc) { "  — $desc" } else { '' }
                Write-Host ("  {0}  Hr={1}{2}" -f $_.TimeCreated, $hrFmt, $descStr) -ForegroundColor Yellow
            }
        }
    }

    # ── Byte Sources ──────────────────────────────────────────────────────────
    $segNote = if ($fullJob.SegmentCount -gt 1) { " for This Download (aggregated across $($fullJob.SegmentCount) job events)" } else { ' for This Download' }
    Show-DOByteSourceSummary -Download $fullJob -TitleSuffix $segNote -NoJobDetails

    # ── Per-Peer Data Breakdown ───────────────────────────────────────────────
    $peerStatMatches = if ($swarmIds.Count -gt 0) {
        @($script:PeerStats | Where-Object { $swarmIds -contains $_.SwarmId })
    } else {
        @($script:PeerStats | Where-Object { $_.TimeCreated -ge $window.Start -and $_.TimeCreated -le $window.End })
    }

    if ($peerStatMatches.Count -gt 0) {
        Write-SubHeader "Per-Peer Data Transfer"

        # Aggregate sessions per unique IP
        $peerGroups = $peerStatMatches | Group-Object PeerIP | ForEach-Object {
            $grp      = $_.Group
            $recvSum  = [long]($grp | Measure-Object BytesRecv -Sum).Sum
            $sentSum  = [long]($grp | Measure-Object BytesSent -Sum).Sum
            $topEntry = $grp | Sort-Object BytesRecv -Descending | Select-Object -First 1
            [PSCustomObject]@{
                PeerIP    = $_.Name
                PeerId    = $topEntry.PeerId
                Sessions  = $grp.Count
                BytesRecv = $recvSum
                BytesSent = $sentSum
            }
        } | Sort-Object BytesRecv -Descending

        # Separate actual data transfers from protocol-only (handshake, keepalive, etc.)
        $dataThreshold = 100KB
        $dataPeers     = @($peerGroups | Where-Object { $_.BytesRecv -ge $dataThreshold })
        $protoPeers    = @($peerGroups | Where-Object { $_.BytesRecv  -lt $dataThreshold })
        $totalPeerRecv = [long]($dataPeers | Measure-Object BytesRecv -Sum).Sum

        Write-Host ("  Peers that delivered data : {0}" -f $dataPeers.Count) `
            -ForegroundColor $(if ($dataPeers.Count -gt 0) { 'Green' } else { 'Yellow' })
        if ($protoPeers.Count -gt 0) {
            Write-Host ("  Protocol-only peers       : {0}  (handshake / control traffic only)" -f $protoPeers.Count) `
                -ForegroundColor Gray
        }

        foreach ($peer in $dataPeers) {
            # Reverse DNS is opt-in (-ResolvePeerNames): a synchronous lookup blocks for seconds per
            # unresolvable IP when analysing logs away from the source network. Results are cached per IP.
            $hostname = $null
            if ($script:ResolvePeerNames) {
                if (-not $script:DnsCache.ContainsKey($peer.PeerIP)) {
                    $script:DnsCache[$peer.PeerIP] = $null
                    try {
                        $task = [System.Net.Dns]::GetHostEntryAsync($peer.PeerIP)
                        if ($task.Wait(1500)) { $script:DnsCache[$peer.PeerIP] = $task.Result.HostName }
                    } catch {}
                }
                $hostname = $script:DnsCache[$peer.PeerIP]
            }

            $pct       = Format-Pct $peer.BytesRecv $totalPeerRecv
            $ipDisplay = if ($hostname -and $hostname -ne $peer.PeerIP) {
                "$($peer.PeerIP)  [$hostname]"
            } else { $peer.PeerIP }

            Write-Host ""
            Write-Host ("    Peer IP  : {0}" -f $ipDisplay)                                            -ForegroundColor Cyan
            Write-Host ("    Peer ID  : {0}" -f $peer.PeerId)                                          -ForegroundColor DarkGray
            Write-Host ("    Sessions : {0} TCP connection(s)" -f $peer.Sessions)                      -ForegroundColor White
            Write-Host ("    Received : {0}  ({1}% of P2P data)" -f (Format-Bytes $peer.BytesRecv), $pct) `
                -ForegroundColor Green
            Write-Host ("    Sent     : {0}  (upload to this peer)" -f (Format-Bytes $peer.BytesSent)) -ForegroundColor Gray
        }

        if ($protoPeers.Count -gt 0) {
            Write-Host ""
            Write-Host "  Protocol-only (no significant data transfer):" -ForegroundColor DarkGray
            foreach ($pp in ($protoPeers | Sort-Object PeerIP)) {
                Write-Host ("    {0,-20}  recv {1,-12}  sent {2}" -f $pp.PeerIP, (Format-Bytes $pp.BytesRecv), (Format-Bytes $pp.BytesSent)) `
                    -ForegroundColor DarkGray
            }
        }
    }

    # ── Announce responses (console table; GridView only when there are many) ─
    if ($announceResps.Count -gt 0) {
        $rows = @($announceResps | Sort-Object TimeCreated | Select-Object @{ N = 'Time'; E = { $_.TimeCreated.ToString('HH:mm:ss') } },
            @{ N = 'Hr'; E = { if ($_.Hr -and $_.Hr -notmatch '^0+$') { Format-ErrorCode $_.Hr -AlreadyHex } else { 'OK' } } },
            NPeers, FailureReason, Server, NextJoinTimeIntervalInMs)
        if ($rows.Count -le 20) {
            Write-SubHeader "Announce Responses for This Download"
            Write-DOTable -Data $rows -Columns @('Time', 'Hr', 'NPeers', 'FailureReason', 'Server', 'NextJoinTimeIntervalInMs')
            Pause-ForUser
        } else {
            Show-DOGrid -Data $rows -Title "Announce responses for this download ($($rows.Count))"
        }
    } elseif ($swarmIds.Count -eq 0) {
        Write-Host "`n  No SwarmId correlation — showing announce requests in the job time window." -ForegroundColor Yellow
        Show-DOGrid -Data @($script:InternalAnnounce | Where-Object { $_.TimeCreated -ge $window.Start -and $_.TimeCreated -le $window.End }) `
            -Title 'Announce requests in job window' -Columns @('TimeCreated', 'SwarmId', 'ScopeDesc', 'JoinRequestEventDesc', 'ReportedIp')
    } else {
        Pause-ForUser
    }
}

function Show-PeeringFailureAnalysis {
    Write-Header "Peering Failure Analysis"
    if ($script:DownloadComplete.Count -eq 0) {
        Write-Host "  No completed downloads." -ForegroundColor Yellow
        Pause-ForUser
        return
    }

    # ── 1. Downloads in P2P-capable mode with zero peer bytes ─────────────────
    # UniqueDownloads is already unique per (FileId + SessionId); re-downloads of the same
    # file in a different session are kept as separate rows instead of being merged together.
    $analysisDownloads = @($script:UniqueDownloads)
    $refileCount = @($analysisDownloads | Group-Object FileId | Where-Object { $_.Count -gt 1 }).Count

    $p2pModes    = @(1, 2, 3)
    $eligible    = @($analysisDownloads | Where-Object { $p2pModes -contains $_.DownloadMode -and $_.CdnUrl })
    $hadPeers    = @($eligible | Where-Object { $_.P2PBytes -gt 0 })
    # Zero peer bytes only counts as a peering miss when something was actually downloaded over the network
    $noPeerBytes = @($eligible | Where-Object { $_.P2PBytes -eq 0 -and $_.NetworkBytes -gt 0 })
    $noNetwork   = @($eligible | Where-Object { $_.NetworkBytes -eq 0 })

    Write-SubHeader "Downloads in P2P-Capable Mode (1/2/3) with CDN URL"
    Write-Host ("  DownloadComplete job events     : {0}" -f $script:DownloadComplete.Count) -ForegroundColor DarkGray
    Write-Host ("  Unique files/sessions parsed   : {0}" -f $script:UniqueDownloads.Count) -ForegroundColor DarkGray
    if ($refileCount -gt 0) {
        Write-Host ("  Files re-downloaded in multiple sessions : {0} (kept separate, not merged)" -f $refileCount) -ForegroundColor Yellow
    }
    Write-Host ("  Total eligible files      : {0}" -f $eligible.Count)    -ForegroundColor White
    Write-Host ("  Files with peer bytes     : {0}" -f $hadPeers.Count)    -ForegroundColor $(if ($hadPeers.Count    -gt 0) { 'Green'  } else { 'Yellow' })
    Write-Host ("  Files with ZERO peer bytes: {0}  (downloaded over the network without peers)" -f $noPeerBytes.Count) -ForegroundColor $(if ($noPeerBytes.Count -gt 0) { 'Red'    } else { 'Green'  })
    if ($noNetwork.Count -gt 0) {
        Write-Host ("  Files with no network bytes in this log : {0}  (served from local cache, or downloaded before the log started)" -f $noNetwork.Count) -ForegroundColor DarkYellow
    }

    # ── 2. Announce response quality ──────────────────────────────────────────
    $noPeersResps = @($script:AnnounceComplete | Where-Object { $null -ne $_.NPeers -and $_.NPeers -eq 0 })
    $failResps    = @($script:AnnounceComplete | Where-Object { $_.FailureReason })
    $hrErrResps   = @($script:AnnounceComplete | Where-Object { $_.Hr -and $_.Hr -notin @('0', '00000000') })

    Write-SubHeader "Announce Response Quality"
    Write-Host ("  Total announce responses       : {0}" -f $script:AnnounceComplete.Count) -ForegroundColor White
    Write-Host ("  Responses with 0 peers         : {0}" -f $noPeersResps.Count) -ForegroundColor $(if ($noPeersResps.Count -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host ("  Responses with FailureReason   : {0}" -f $failResps.Count)    -ForegroundColor $(if ($failResps.Count    -gt 0) { 'Red'    } else { 'Green' })
    Write-Host ("  Responses with non-zero HR     : {0}" -f $hrErrResps.Count)   -ForegroundColor $(if ($hrErrResps.Count   -gt 0) { 'Red'    } else { 'Green' })

    if ($hrErrResps.Count -gt 0) {
        $hrErrResps | Group-Object Hr | Sort-Object Count -Descending | ForEach-Object {
            $hrFmt   = Format-ErrorCode $_.Name -AlreadyHex
            $desc    = Get-DOErrorDescription $_.Name -AlreadyHex
            $descStr = if ($desc) { "  — $desc" } else { '' }
            Write-Host ("    {0,-14} x{1,-5}{2}" -f $hrFmt, $_.Count, $descStr) -ForegroundColor Red
        }
    }

    # ── 3. CAnnounceSequencer and CConnMan error events ───────────────────────
    $announceErrEvents = @($script:ErrorEvents | Where-Object { $_.Function -like 'CAnnounceSequencer*' })
    $connErrEvents = @($script:ErrorEvents | Where-Object { $_.Function -like 'CConnMan*' })

    Write-SubHeader "Peering-Related Error Events"
    Write-Host ("  CAnnounceSequencer errors/warnings : {0}" -f $announceErrEvents.Count) -ForegroundColor $(if ($announceErrEvents.Count -gt 0) { 'Red'    } else { 'Green' })
    Write-Host ("  CConnMan errors/warnings           : {0}" -f $connErrEvents.Count)     -ForegroundColor $(if ($connErrEvents.Count     -gt 0) { 'Yellow' } else { 'Green' })

    # Detect 0x80072EE2 timeouts in both ErrorCode and Message body
    $timeoutEvents = @($script:RawLogs | Where-Object {
        $msgHas = ($_.Message -match '(?i)80072ee2')
        $codeHas = $false
        if ($_.ErrorCode -and $_.ErrorCode -ne 0) {
            $codeHas = ((Format-ErrorCode $_.ErrorCode) -eq '0x80072EE2')
        }
        $msgHas -or $codeHas
    })
    $timeoutSwarmEvents = @($timeoutEvents | Where-Object { $_.Function -like 'CAnnounceSequencer*' })
    if ($timeoutEvents.Count -gt 0) {
        Write-Host ("  0x80072EE2 timeouts (all funcs)    : {0}  — ERROR_INTERNET_TIMEOUT" -f $timeoutEvents.Count) -ForegroundColor Red
        Write-Host ("  0x80072EE2 timeouts (swarm funcs)  : {0}" -f $timeoutSwarmEvents.Count) -ForegroundColor $(if ($timeoutSwarmEvents.Count -gt 0) { 'Red' } else { 'Green' })
    }
    
    if ($announceErrEvents.Count -gt 0) {
        # Extract embedded error codes: "announce error: XXXXXXXX, <description>"
        $embeddedCodes = $announceErrEvents | ForEach-Object {
            if ($_.Message -match 'announce error:\s*([0-9a-fA-F]{6,8})') {
                '0x' + $matches[1].ToUpper().PadLeft(8, '0')
            } elseif ($_.ErrorCode -and $_.ErrorCode -ne 0) {
                Format-ErrorCode $_.ErrorCode
            }
        } | Where-Object { $_ } | Group-Object | Sort-Object Count -Descending
        if ($embeddedCodes) {
            $embeddedCodes | ForEach-Object {
                $desc    = Get-DOErrorDescription $_.Name
                $descStr = if ($desc) { "  — $desc" } else { '' }
                Write-Host ("    {0,-14} x{1,-5}{2}" -f $_.Name, $_.Count, $descStr) -ForegroundColor Red
            }
        }
    }

    # ── 4. Per-swarm peer summary ─────────────────────────────────────────────
    if ($script:AnnounceComplete.Count -gt 0) {
        Write-SubHeader "Per-Swarm Peer Summary"
        $swarmSummary = $script:AnnounceComplete | Where-Object { $_.SwarmId } |
            Group-Object SwarmId | ForEach-Object {
                $validPeers = $_.Group | Where-Object { $null -ne $_.NPeers }
                $maxP  = if ($validPeers) { ($validPeers | Measure-Object NPeers -Maximum).Maximum } else { 0 }
                $fails = ($_.Group | Where-Object { $_.FailureReason }).Count
                $hrErr = ($_.Group | Where-Object { $_.Hr -and $_.Hr -notin @('0', '00000000') }).Count
                [PSCustomObject]@{
                    SwarmId          = $_.Name
                    AnnounceCount    = $_.Count
                    MaxPeersSeen     = [int]$maxP
                    FailureResponses = $fails
                    HrErrors         = $hrErr
                    Status           = if ($fails -gt 0 -or $hrErr -gt 0) { 'FAILED' }
                                       elseif ($maxP -eq 0) { 'NO PEERS' }
                                       else { 'OK' }
                }
            } | Sort-Object Status, MaxPeersSeen

        $nopeersSwarms = @($swarmSummary | Where-Object { $_.MaxPeersSeen -eq 0 })
        $failedSwarms  = @($swarmSummary | Where-Object { $_.Status -eq 'FAILED' })
        Write-Host ("  Swarms tracked            : {0}" -f $swarmSummary.Count)  -ForegroundColor White
        Write-Host ("  Swarms with no peers ever : {0}" -f $nopeersSwarms.Count) -ForegroundColor $(if ($nopeersSwarms.Count -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host ("  Swarms with failures      : {0}" -f $failedSwarms.Count)  -ForegroundColor $(if ($failedSwarms.Count  -gt 0) { 'Red'    } else { 'Green' })

        # MaxColWidth 42 so 40-character swarm IDs are shown in full and can be copied
        Write-DOTable -Data $swarmSummary -Columns @('SwarmId', 'AnnounceCount', 'MaxPeersSeen', 'FailureResponses', 'HrErrors', 'Status') -MaxColWidth 42 -RowColor {
            param($row)
            switch ($row.Status) { 'FAILED' { 'Red' } 'NO PEERS' { 'Yellow' } default { 'Green' } }
        }
    }

    # ── 5. Zero-peer eligible downloads ───────────────────────────────────────
    if ($noPeerBytes.Count -gt 0) {
        Show-DownloadList $noPeerBytes 'Peering-mode downloads with zero peer bytes'
    } else {
        Pause-ForUser
    }
}

#endregion

#region ─── Network & GEO ────────────────────────────────────────────────────

function Show-MCCAnalysisReport {
    Write-Header "Connected Cache (MCC) Analysis"
    if (-not (Assert-LogsLoaded)) { return }

    # MCC delivery bytes are tracked by the DOINC field. lcache is DO's internal local-cache
    # accounting and does NOT represent bytes received from a network Connected Cache server.
    $mccDownloads = @($script:UniqueDownloads | Where-Object { $_.DoincBytes -gt 0 })

    if ($mccDownloads.Count -eq 0) {
        Write-Host "`n  No Connected Cache (MCC) activity found in this log." -ForegroundColor Yellow
        Pause-ForUser
        return
    }

    # Percentages are of network bytes (CDN + MCC + peers), not file size
    $totalNet = [long]($script:UniqueDownloads | Measure-Object NetworkBytes -Sum).Sum
    $totalMcc = [long]($mccDownloads | Measure-Object DoincBytes -Sum).Sum
    $mccPct   = Format-Pct $totalMcc $totalNet

    Write-SubHeader "Overall MCC Activity"
    Write-Host ("  Downloads using MCC    : {0} of {1}" -f $mccDownloads.Count, $script:UniqueDownloads.Count) -ForegroundColor White
    Write-Host ("  Total bytes from MCC   : {0}  ({1}% of network bytes)" -f (Format-Bytes $totalMcc), $mccPct) -ForegroundColor Cyan

    # Per-server breakdown from the individual job events, so a download that used two
    # cache servers credits each server with its own bytes
    $byServer = @($script:DownloadComplete | Where-Object { $_.DoincBytes -gt 0 -and $_.MccHost } |
        Group-Object MccHost | ForEach-Object {
            $grp      = $_.Group
            $mccHost  = $_.Name
            $svrBytes = [long]($grp | Measure-Object DoincBytes -Sum).Sum
            $xcid     = if ($script:XCidByIp.ContainsKey($mccHost)) { $script:XCidByIp[$mccHost] } else { $null }
            $mccType  = if ($null -ne $xcid) { Get-MCCTypeDescription $xcid } else { 'Unknown (X-CID not observed)' }
            [PSCustomObject]@{
                MccHost    = $mccHost
                XCid       = if ($null -ne $xcid) { $xcid } else { '?' }
                MccType    = $mccType
                Files      = @($grp | ForEach-Object { "$($_.FileId)|$($_.SessionId)" } | Sort-Object -Unique).Count
                Bytes      = $svrBytes
                BytesHuman = Format-Bytes $svrBytes
                PctOfNet   = Format-Pct $svrBytes $totalNet
            }
        } | Sort-Object Bytes -Descending)

    if ($byServer.Count -gt 0) {
        Write-SubHeader "Per-MCC-Server Breakdown"
        Write-DOTable -Data $byServer -Columns @('MccHost', 'XCid', 'MccType', 'Files', 'BytesHuman', 'PctOfNet') -MaxColWidth 45 -RowColor {
            param($row)
            switch -Regex ($row.MccType) {
                'Distribution Point' { 'Green';  break }
                'Standalone'         { 'Cyan';   break }
                'Internet'           { 'Yellow'; break }
                'CDN'                { 'Gray';   break }
                default              { 'White' }
            }
        }
    } else {
        Write-Host "`n  MCC activity detected but the server could not be identified (cacheHost field empty in logs)." -ForegroundColor Yellow
        Write-Host ("  Total MCC bytes: {0}" -f (Format-Bytes $totalMcc)) -ForegroundColor Cyan
    }

    Show-DownloadList $mccDownloads 'Downloads with MCC activity'
}

function Show-GeoResponseHistory {
    Write-Header "GEO Response History"
    if ($script:GeoResponses.Count -eq 0) {
        Write-Host "  No GEO responses recorded in this log." -ForegroundColor Yellow
        Pause-ForUser
        return
    }
    if ($script:GeoResponses.Count -eq 1) {
        $g = $script:GeoResponses[0]
        Write-DOCard -Title "GEO Response @ $($g.TimeCreated)" -Fields ([ordered]@{
            'External IP'       = $g.ExternalIpAddress
            'Country'           = $g.CountryCode
            'Cache Id'          = $g.CacheId
            'KeyValue Endpoint' = $g.KeyValueUri
            'Version'           = $g.Version
        })
        Pause-ForUser
        return
    }
    $shaped = $script:GeoResponses | Select-Object @{ N = 'Time'; E = { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } },
        @{ N = 'ExternalIP'; E = { $_.ExternalIpAddress } }, @{ N = 'Country'; E = { $_.CountryCode } },
        @{ N = 'CacheId'; E = { $_.CacheId } }, @{ N = 'KeyValueUri'; E = { $_.KeyValueUri } }
    if ($script:GeoResponses.Count -le 20) {
        Write-DOTable -Data $shaped -Columns @('Time', 'ExternalIP', 'Country', 'CacheId', 'KeyValueUri') -MaxColWidth 60
        Pause-ForUser
    } else {
        Show-DOGrid -Data $shaped -Title "GEO responses ($($script:GeoResponses.Count))"
    }
}

function Show-DOServiceErrors {
    Write-Header "Cloud Service Connection Errors"
    if ($script:ServiceErrors.Count -eq 0) {
        Write-Host "  No failures reaching DO cloud services were logged." -ForegroundColor Green
        Pause-ForUser
        return
    }
    $rows = @($script:ServiceErrors | Group-Object ServiceHost, ErrorHex | Sort-Object Count -Descending | ForEach-Object {
        $e = $_.Group[0]
        [PSCustomObject]@{ Host = $e.ServiceHost; Error = $e.ErrorHex; Description = $e.ErrorDesc; Count = $_.Count
            First = ($_.Group | Sort-Object TimeCreated)[0].TimeCreated.ToString('HH:mm:ss'); Message = $e.ErrMsg }
    })
    Write-DOTable -Data $rows -Columns @('Host', 'Error', 'Description', 'Count', 'First', 'Message') -MaxColWidth 45 -RowColor { 'Yellow' }
    Write-Host "  DO needs HTTPS to *.prod.do.dsp.mp.microsoft.com for GEO, KeyValue and peer discovery." -ForegroundColor Gray
    Pause-ForUser
}

function Show-DOCdnErrors {
    Write-Header "HTTP Errors from CDN / Cache Servers"
    if ($script:CdnErrors.Count -eq 0) {
        Write-Host "  No CDN or cache-server HTTP errors were logged." -ForegroundColor Green
        Pause-ForUser
        return
    }
    $rows = @($script:CdnErrors | Group-Object Host, ErrorHex, HttpCode | Sort-Object Count -Descending | ForEach-Object {
        $e = $_.Group[0]
        [PSCustomObject]@{ Host = $e.Host; ServerIp = $e.ServerIp; Error = $e.ErrorHex; Description = $e.ErrorDesc; HttpStatus = $e.HttpCode; Count = $_.Count
            UrlExpiredAt = ($_.Group | Where-Object UrlExpiredAt | Select-Object -First 1).UrlExpiredAt }
    })
    Write-DOTable -Data $rows -Columns @('Host', 'ServerIp', 'Error', 'Description', 'HttpStatus', 'Count', 'UrlExpiredAt') -MaxColWidth 50 -RowColor { 'Yellow' }
    Pause-ForUser
}

function Show-NetworkGeoMenu {
    Invoke-DOMenu -RequireLogs -Title 'Network, Cache & Cloud Services' -Items @(
        @{ Key = '1'; Label = 'GEO responses / external IP history';     Action = { Show-GeoResponseHistory } }
        @{ Key = '2'; Label = 'Connected Cache (MCC) analysis';          Action = { Show-MCCAnalysisReport } }
        @{ Key = '3'; Label = "Cloud service connection errors ($($script:ServiceErrors.Count))"; Action = { Show-DOServiceErrors } }
        @{ Key = '4'; Label = "CDN / cache HTTP errors ($($script:CdnErrors.Count))";            Action = { Show-DOCdnErrors } }
        @{ Key = '5'; Label = 'HTTP source per download';                Action = {
            $rows = $script:UniqueDownloads | Where-Object { $_.CdnIp -or $_.CdnUrl } | Select-Object TimeCreated, Caller, CdnIp, MccHost,
                @{ N = 'CdnMB'; E = { ConvertTo-MB $_.CdnBytes } }, @{ N = 'MccMB'; E = { ConvertTo-MB $_.DoincBytes } },
                @{ N = 'FileMB'; E = { ConvertTo-MB $_.FileBytes } }, DownloadModeDesc, CdnUrl
            Show-DOGrid -Data $rows -Title 'HTTP source per download' -Columns @('TimeCreated', 'Caller', 'CdnIp', 'MccHost', 'CdnMB', 'MccMB', 'FileMB') } }
    )
}

#endregion

#region ─── Error Analysis ───────────────────────────────────────────────────

function Show-ErrorAnalysisMenu {
    Invoke-DOMenu -RequireLogs -Title { "Error Analysis  ($(@($script:ErrorEvents | Where-Object {$_.Level -le 2}).Count) errors, $(@($script:ErrorEvents | Where-Object {$_.Level -eq 3}).Count) warnings)" } -Items @(
        @{ Key = '1'; Label = 'Grouped by HRESULT code';        Action = { Show-ErrorsByHresult } }
        @{ Key = '2'; Label = 'Grouped by function / source';   Action = { Show-ErrorsByFunction } }
        @{ Key = '3'; Label = 'All error and warning events';   Action = { Show-DOGrid -Data $script:ErrorEvents -Title "Error events ($($script:ErrorEvents.Count))" -Columns @('TimeCreated', 'LevelName', 'Source', 'ErrorHex', 'Message') } }
        @{ Key = '4'; Label = 'Busiest functions in log (all levels)'; Action = {
            Write-Header 'Top 25 Functions by Event Count'
            $rows = $script:RawLogs | Group-Object Function | Sort-Object Count -Descending | Select-Object -First 25 |
                Select-Object Count, @{ N = 'Function'; E = { if ($_.Name) { $_.Name } else { '(none)' } } }
            Write-DOTable -Data @($rows) -Columns @('Count', 'Function') -MaxColWidth 70
            Pause-ForUser } }
    )
}

function Show-ErrorsByHresult {
    Write-Header "Errors Grouped by HRESULT"
    # Collect error codes: from ErrorCode property AND from embedded message patterns
    $codeEvents = $script:ErrorEvents | ForEach-Object {
        $code = $null
        if ($_.ErrorCode -and $_.ErrorCode -ne 0) {
            $code = $_.ErrorHex
        } elseif ($_.Message -match '(?i)(?:error|hr)[: ]+([0-9a-fA-F]{6,8})\b') {
            $code = '0x' + $matches[1].ToUpper().PadLeft(8,'0')
        }
        if ($code) { [PSCustomObject]@{ Code = $code; Function = $_.Source; Level = $_.Level } }
    }
    if (-not $codeEvents) { Write-Host '  No HRESULT codes found in error/warning events.' -ForegroundColor Gray; Pause-ForUser; return }
    $codeEvents | Group-Object Code | Sort-Object Count -Descending | ForEach-Object {
        $desc    = Get-DOErrorDescription $_.Name
        $descStr = if ($desc) { "  → $desc" } else { '' }
        $funcs   = $_.Group | Group-Object Function | Sort-Object Count -Descending | Select-Object -First 2 |
                    ForEach-Object { "$($_.Name) (x$($_.Count))" }
        $color   = if ($_.Group | Where-Object { $_.Level -le 2 }) { 'Red' } else { 'Yellow' }
        Write-Host ("  {0,-14} x{1,-5}{2}" -f $_.Name, $_.Count, $descStr) -ForegroundColor $color
        Write-Host ("      {0}" -f ($funcs -join '  |  ')) -ForegroundColor DarkGray
    }
    Pause-ForUser
}

function Show-ErrorsByFunction {
    Write-Header "Errors / Warnings Grouped by Function"
    $script:ErrorEvents | Group-Object Source | Sort-Object Count -Descending | ForEach-Object {
        $hasL2 = $_.Group | Where-Object { $_.Level -le 2 }
        $color = if ($hasL2) { 'Red' } else { 'Yellow' }
        Write-Host ("  x{0,-5} [{1}] {2}" -f $_.Count, $(if ($hasL2) { 'Error' } else { 'Warn ' }), $_.Name) -ForegroundColor $color
    }
    Pause-ForUser
}

#endregion

#region ─── Status Correlation ───────────────────────────────────────────────

function Invoke-StatusCorrelation {
    if (-not (Assert-LogsLoaded)) { return }
    Write-Header "Correlate with Get-DeliveryOptimizationStatus"

    # Get-DeliveryOptimizationStatus always describes THIS machine; warn when the logs came from elsewhere
    if ($script:LogSource.Kind -ne 'Live') {
        Write-Host "  The loaded logs came from: $($script:LogSource.Path)" -ForegroundColor Yellow
        Write-Host "  Get-DeliveryOptimizationStatus reports the jobs of THIS machine ($env:COMPUTERNAME)." -ForegroundColor Yellow
        Write-Host "  Only continue if those logs were collected here." -ForegroundColor Yellow
        if ((Read-Host "  Continue? (y/N)").Trim() -ine 'y') { return }
    }

    Write-Host "  Calling Get-DeliveryOptimizationStatus..." -ForegroundColor Yellow
    $statusEntries = $null
    try {
        $statusEntries = @(Get-DeliveryOptimizationStatus)
    } catch {
        Write-Host "  ERROR: Get-DeliveryOptimizationStatus failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  This feature requires running on the source machine with an active DO service." -ForegroundColor Gray
        Pause-ForUser
        return
    }
    if ($statusEntries.Count -eq 0) {
        Write-Host "  No active/recent DO jobs found via Get-DeliveryOptimizationStatus." -ForegroundColor Yellow
        Pause-ForUser
        return
    }
    Write-Host "  Found $($statusEntries.Count) status entries. Correlating with aggregated log downloads..." -ForegroundColor Gray

    # Raw numbers in the objects (GridView sorts them correctly); formatting happens only in the card
    $correlated = foreach ($s in $statusEntries) {
        # Most recent log download of the same file; re-downloads in other sessions are counted, not merged
        $logMatches = @($script:UniqueDownloads | Where-Object { $_.FileId -ieq $s.FileId } | Sort-Object TimeCreated)
        $logMatch   = $logMatches | Select-Object -Last 1
        [PSCustomObject]@{
            FileId                 = $s.FileId
            Status                 = $s.Status
            Priority               = $s.Priority
            DownloadMode           = $s.DownloadMode
            FileSize               = $s.FileSize
            BytesFromCDN           = $s.BytesFromCDN
            BytesFromPeers         = $s.BytesFromPeers
            BytesFromCacheHost     = $s.BytesFromCacheHost
            BytesFromGroupPeers    = $s.BytesFromGroupPeers
            BytesFromInternetPeers = $s.BytesFromInternetPeers
            PercentPeerCaching     = $s.PercentPeerCaching
            CacheHost              = if ($s.CacheHost) { $s.CacheHost } else { $null }
            LogFound               = ($null -ne $logMatch)
            LogSessions            = $logMatches.Count
            LogTime                = if ($logMatch) { $logMatch.TimeCreated } else { $null }
            LogCaller              = if ($logMatch) { $logMatch.Caller } else { $null }
            LogJobEvents           = if ($logMatch) { $logMatch.SegmentCount } else { $null }
            LogFileBytes           = if ($logMatch) { $logMatch.FileBytes } else { $null }
            LogNetworkBytes        = if ($logMatch) { $logMatch.NetworkBytes } else { $null }
            LogCdnBytes            = if ($logMatch) { $logMatch.CdnBytes } else { $null }
            LogPeerBytes           = if ($logMatch) { $logMatch.P2PBytes } else { $null }
            LogDoincBytes          = if ($logMatch) { $logMatch.DoincBytes } else { $null }
            LogPeerPct             = if ($logMatch) { $logMatch.PeerPct } else { $null }
            LogDownloadMode        = if ($logMatch) { $logMatch.DownloadModeDesc } else { $null }
            LogDurationMs          = if ($logMatch) { $logMatch.DurationMs } else { $null }
        }
    }

    $matched = @($correlated | Where-Object { $_.LogFound })
    Write-Host "  Matched $($matched.Count) of $($statusEntries.Count) status entries to log events." -ForegroundColor $(if ($matched.Count -gt 0) { 'Green' } else { 'Yellow' })

    if ($correlated.Count -eq 1) {
        $c  = $correlated[0]
        $fb = { param($v) if ($null -ne $v) { Format-Bytes $v } }
        Write-DOCard -Title "Status Correlation: $($c.FileId)" -Fields ([ordered]@{
            'Status'                    = $c.Status
            'Download Mode (live)'      = $c.DownloadMode
            'File Size'                 = & $fb $c.FileSize
            'Bytes From CDN'            = & $fb $c.BytesFromCDN
            'Bytes From Peers'          = & $fb $c.BytesFromPeers
            'Bytes From Cache Host'     = & $fb $c.BytesFromCacheHost
            '% Peer Caching'            = if ($null -ne $c.PercentPeerCaching) { "$($c.PercentPeerCaching)%" }
            'Cache Host'                = $c.CacheHost
            'Log Match Found'           = $c.LogFound
            'Log Sessions for File'     = $c.LogSessions
            'Log Caller'                = $c.LogCaller
            'Log Job Events'            = $c.LogJobEvents
            'Log File Bytes'            = & $fb $c.LogFileBytes
            'Log Network Bytes'         = & $fb $c.LogNetworkBytes
            'Log CDN Bytes'             = & $fb $c.LogCdnBytes
            'Log Peer Bytes'            = & $fb $c.LogPeerBytes
            'Log Connected Cache Bytes' = & $fb $c.LogDoincBytes
            'Log Peer %'                = if ($null -ne $c.LogPeerPct) { "$($c.LogPeerPct)%" }
            'Log Download Mode'         = $c.LogDownloadMode
            'Log Duration'              = if ($c.LogFound) { Format-TimeMs $c.LogDurationMs }
        })
        Pause-ForUser
    } else {
        Show-DOGrid -Data $correlated -Title "Status ↔ Log Correlation ($($correlated.Count) entries, $($matched.Count) matched)" `
            -Columns @('FileId', 'Status', 'DownloadMode', 'PercentPeerCaching', 'LogFound', 'LogPeerPct', 'LogDownloadMode')
    }
}

#endregion

#region ─── Export ────────────────────────────────────────────────────────────

function Get-DOExportSets {
    # Every exportable data set of the current view, in menu order
    [ordered]@{
        'Downloads'          = @{ Data = $script:UniqueDownloads;    Label = 'Downloads (one row per file/session)' }
        'DownloadJobEvents'  = @{ Data = $script:DownloadComplete;   Label = 'DownloadComplete job events (raw)' }
        'JobStates'          = @{ Data = $script:JobStates;          Label = 'Job states (started / paused / completed)' }
        'Diagnosis'          = @{ Data = @(Get-DODiagnosis);         Label = 'Diagnosis findings' }
        'Configuration'      = @{ Data = $script:DOConfig;           Label = 'DO configuration (from log)' }
        'AnnounceRequests'   = @{ Data = $script:InternalAnnounce;   Label = 'Announce requests' }
        'AnnounceResponses'  = @{ Data = $script:AnnounceComplete;   Label = 'Announce responses' }
        'Connections'        = @{ Data = $script:ConnectionComplete; Label = 'Connection events' }
        'PeerStats'          = @{ Data = $script:PeerStats;          Label = 'Per-peer transfer stats' }
        'InboundHandshakes'  = @{ Data = $script:InboundHandshakes;  Label = 'Inbound peer handshakes' }
        'ServiceErrors'      = @{ Data = $script:ServiceErrors;      Label = 'Cloud service connection errors' }
        'CdnErrors'          = @{ Data = $script:CdnErrors;          Label = 'CDN / cache HTTP errors' }
        'GeoResponses'       = @{ Data = $script:GeoResponses;       Label = 'GEO responses' }
        'ErrorEvents'        = @{ Data = $script:ErrorEvents;        Label = 'Error and warning events' }
    }
}

function Export-DOAll {
    # Writes every data set as CSV plus a plain-text report (diagnosis + dashboard) into one folder
    param([Parameter(Mandatory)][string]$Folder)
    if (-not (Test-Path -LiteralPath $Folder)) { New-Item -ItemType Directory -Path $Folder -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $count = 0
    foreach ($s in (Get-DOExportSets).GetEnumerator()) {
        $rows = @($s.Value.Data)
        if ($rows.Count -eq 0) { continue }
        $rows | Export-Csv -LiteralPath (Join-Path $Folder "DO_$($s.Key)_$stamp.csv") -NoTypeInformation -Encoding UTF8
        $count++
    }
    $prev = $script:NonInteractive
    $script:NonInteractive = $true
    try {
        $text = & { Show-DODiagnosis -NoPause; Show-SummaryDashboard } 6>&1 | Out-String -Width 200
    } finally { $script:NonInteractive = $prev }
    $header = "Delivery Optimization log report`r`nSource: $($script:LogSourceDesc)`r`nCreated: $(Get-Date)`r`n"
    Set-Content -LiteralPath (Join-Path $Folder "DO_Report_$stamp.txt") -Value ($header + $text) -Encoding UTF8
    Write-Host "  Exported $count CSV file(s) and DO_Report_$stamp.txt to: $Folder" -ForegroundColor Green
}

function Read-DOExportFolder {
    $defaultOut = Join-Path $env:TEMP 'DOLogs'
    $outFolder = (Read-Host "  Export folder (Enter = $defaultOut)").Trim().Trim('"', "'")
    if ([string]::IsNullOrWhiteSpace($outFolder)) { $outFolder = $defaultOut }
    return $outFolder
}

function Show-ExportMenu {
    $sets  = Get-DOExportSets
    $items = @(@{ Key = 'A'; Label = 'Everything (all CSVs + text report)'; Action = { Export-DOAll -Folder (Read-DOExportFolder); Pause-ForUser } })
    $i = 1
    foreach ($s in $sets.GetEnumerator()) {
        $name = $s.Key
        $items += @{ Key = "$i"; Label = "$($s.Value.Label) ($(@($s.Value.Data).Count))"; Action = [scriptblock]::Create("Export-DOReport -DatasetName '$name'") }
        $i++
    }
    Invoke-DOMenu -RequireLogs -Title 'Export (current view, CSV)' -Items $items
}

function Export-DOReport {
    param([string]$DatasetName)
    $Data = @((Get-DOExportSets)[$DatasetName].Data)
    if ($Data.Count -eq 0) {
        Write-Host "`n  No data to export." -ForegroundColor Yellow
        Pause-ForUser
        return
    }
    $outFolder = Read-DOExportFolder
    if (-not (Test-Path -LiteralPath $outFolder)) { New-Item -ItemType Directory -Path $outFolder -Force | Out-Null }
    $outFile = Join-Path $outFolder "DO_${DatasetName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $Data | Export-Csv -LiteralPath $outFile -NoTypeInformation -Encoding UTF8
    Write-Host "  Exported $($Data.Count) rows to: $outFile" -ForegroundColor Green
    Pause-ForUser
}

#endregion

#region ─── Main Menu ─────────────────────────────────────────────────────────

function Show-MainMenu {
    Invoke-DOMenu -QuitLabel 'Quit' -Title {
        if ($script:AllRaw) { "Delivery Optimization Log Analyzer`n  Loaded: $($script:LogSourceDesc)  ($(@($script:AllRaw).Count) events)" }
        else { "Delivery Optimization Log Analyzer`n  No logs loaded" }
    } -Items @(
        @{ Key = '1'; Label = 'Load / reload logs';                          Action = { $null = Initialize-DOLogs; Pause-ForUser } }
        @{ Key = '2'; Label = 'Diagnosis (why peering did or did not work)'; Action = { Show-DODiagnosis } }
        @{ Key = '3'; Label = 'Summary dashboard';                           Action = { Show-SummaryDashboard } }
        @{ Key = '4'; Label = 'Download analysis';                           Action = { Show-DownloadAnalysisMenu } }
        @{ Key = '5'; Label = 'Peer / P2P activity';                         Action = { Show-PeerActivityMenu } }
        @{ Key = '6'; Label = 'Network, cache & cloud services';             Action = { Show-NetworkGeoMenu } }
        @{ Key = '7'; Label = 'Error analysis';                              Action = { Show-ErrorAnalysisMenu } }
        @{ Key = '8'; Label = 'DO configuration';                            Action = { Show-DOConfig } }
        @{ Key = '9'; Label = 'Correlate with live DO status (this machine)'; Action = { Invoke-StatusCorrelation } }
        @{ Label = '-' }
        @{ Key = 'F'; Label = 'Filter by time or text';                      Action = { Set-DOFilter } }
        @{ Key = 'E'; Label = 'Export';                                      Action = { Show-ExportMenu } }
    )
    Write-Host "`n  Exiting.`n" -ForegroundColor Gray
}

#endregion

#region ─── Entry Point ───────────────────────────────────────────────────────

$script:LogPath          = $LogPath
$script:AllRaw           = $null
$script:RawLogs          = $null
$script:LogSourceDesc    = $null
$script:LogSource        = $null
$script:XCidByIp         = @{}
$script:DOConfig         = @()
$script:DOFilter           = @{ Start = $null; End = $null; Text = $null }
$script:ResolvePeerNames = [bool]$ResolvePeerNames
$script:NoGridView       = [bool]$NoGridView
$script:DnsCache         = @{}
$script:NonInteractive   = [bool]($Summary -or $ExportPath)

if ($script:NonInteractive -and -not $LogPath) {
    Write-Host "  -Summary and -ExportPath need -LogPath (a folder, an .etl file, or 'Live')." -ForegroundColor Red
    return
}

if ($LogPath) {
    $loaded = Initialize-DOLogs -Silent
    if ($loaded -and ($StartTime -or $EndTime -or $Filter)) {
        $script:DOFilter = @{ Start = $StartTime; End = $EndTime; Text = $(if ($Filter) { $Filter } else { $null }) }
        Set-DOView
        Show-DOFilterStatus
    }
    if ($script:NonInteractive) {
        if (-not $loaded) { return }
        if ($Summary)    { Show-DODiagnosis -NoPause; Show-SummaryDashboard }
        if ($ExportPath) { Export-DOAll -Folder $ExportPath }
        return
    }
}

Show-MainMenu

#endregion
