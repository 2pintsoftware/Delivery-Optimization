<#
.SYNOPSIS
    Interactive Delivery Optimization log analysis and troubleshooting tool.

.DESCRIPTION
    Parses DO ETL log files (or the live system log) into typed event collections,
    then exposes them through a menu-driven interface. Key capabilities:
      - Quick summary dashboard (bytes by source, P2P efficiency)
      - Per-download analysis filtered by caller, error state, download mode
      - Job Trace: follow a single download through its full event lifecycle
        (InternalAnnounce → AnnounceComplete → ConnectionComplete → DownloadComplete)
      - Peer / P2P activity views
      - Network & GEO history
      - Error analysis grouped by HRESULT and Function
      - Correlation of log events with Get-DeliveryOptimizationStatus (live system)
      - CSV export for any dataset

.PARAMETER LogPath
    Path to a folder containing dosvc*.etl files.
    If omitted you will be prompted; choose (L)ive to parse the local system log instead.

.PARAMETER ResolvePeerNames
    Reverse-resolve peer IP addresses to host names in the per-download P2P view.
    Off by default because lookups stall when the logs are analysed away from the source network.

.EXAMPLE
    .\Invoke-2PDOLogAnalyzer.ps1

.EXAMPLE
    .\Invoke-2PDOLogAnalyzer.ps1 -LogPath "C:\DOLogs\DOETLLogs_Machine_20250515"

.NOTES
    Version:        1.3
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

    Requires Windows 10/11 with the DeliveryOptimization PowerShell module.
    GridView output requires Windows PowerShell or PowerShell 7+ on Windows.
    Some features (Status Correlation) require running on the source machine.
#>
[CmdletBinding()]
param(
    [string]$LogPath,
    [switch]$ResolvePeerNames
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

function Format-Bps {
    param([long]$Bps)
    if ($Bps -ge 1000000) { return "{0:N1} Mbps" -f ($Bps / 1000000) }
    if ($Bps -ge 1000)    { return "{0:N1} Kbps" -f ($Bps / 1000) }
    return "$Bps bps"
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

    $widths = @{}
    foreach ($c in $Columns) {
        $dataLen = ($Data | ForEach-Object { "$($_.$c)".Length } | Measure-Object -Maximum).Maximum
        $widths[$c] = [math]::Min([math]::Max($c.Length, $dataLen), $MaxColWidth)
    }

    $topRule = '  +' + (($Columns | ForEach-Object { '-' * ($widths[$_] + 2) }) -join '+') + '+'
    $midRule = $topRule
    $botRule = $topRule
    $header  = '  |' + (($Columns | ForEach-Object { ' ' + $_.PadRight($widths[$_]) + ' ' }) -join '|') + '|'

    Write-Host $topRule -ForegroundColor DarkGray
    Write-Host $header  -ForegroundColor Cyan
    Write-Host $midRule -ForegroundColor DarkGray
    foreach ($row in $Data) {
        $color = if ($RowColor) { & $RowColor $row } else { 'White' }
        $cells = $Columns | ForEach-Object {
            $val = "$($row.$_)"
            if ($val.Length -gt $widths[$_]) { $val = $val.Substring(0, $widths[$_] - 1) + '.' }
            ' ' + $val.PadRight($widths[$_]) + ' '
        }
        Write-Host ('  |' + ($cells -join '|') + '|') -ForegroundColor $color
    }
    Write-Host $botRule -ForegroundColor DarkGray
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
            GroupId            = if ($msg -match 'groupId = ([\w=\-]+)') { $matches[1] } else { $null }
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

#endregion

#region ─── Log Loading ───────────────────────────────────────────────────────

function Initialize-DOLogs {
    param([switch]$Silent)

    if ($Silent -and $script:LogPath) {
        # Auto-load from -LogPath parameter — no prompt
        $choice = $script:LogPath
    } else {
        # Interactive prompt
        $defaultPath = if ($script:LogPath) { $script:LogPath } else { '' }
        Write-Host "`n  Log source options:" -ForegroundColor White
        Write-Host "    [L] Live system (Get-DeliveryOptimizationLog, no path needed)" -ForegroundColor Gray
        Write-Host "    [F] Folder containing dosvc*.etl files" -ForegroundColor Gray
        $choice = (Read-Host "`n  Enter L for live, or a folder path (default: $defaultPath)").Trim()
        if ($choice -eq '' -and $defaultPath -ne '') { $choice = $defaultPath }
    }

    Write-Host "`n  Loading logs..." -ForegroundColor Yellow

    if ($choice -ieq 'L' -or $choice -eq '') {
        Write-Host "  Parsing live system DO log..." -ForegroundColor Gray
        try {
            $script:RawLogs = Get-DeliveryOptimizationLog
            $script:LogSourceDesc = 'Live system'
        } catch {
            Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    } else {
        # Treat as folder path
        $resolvedPath = $choice
        if (-not (Test-Path $resolvedPath -PathType Container)) {
            Write-Host "  ERROR: Path not found: $resolvedPath" -ForegroundColor Red
            return $false
        }
        $etlFiles = Get-ChildItem $resolvedPath -Recurse -File -Filter 'dosvc*.etl' | Sort-Object Name
        if ($etlFiles.Count -eq 0) {
            Write-Host "  ERROR: No dosvc*.etl files found in: $resolvedPath" -ForegroundColor Red
            return $false
        }
        Write-Host "  Found $($etlFiles.Count) ETL file(s) in: $resolvedPath" -ForegroundColor Gray
        try {
            $script:RawLogs = Get-DeliveryOptimizationLog -Path $etlFiles.FullName
            $script:LogPath = $resolvedPath
            $script:LogSourceDesc = "ETL: $resolvedPath"
        } catch {
            Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    }

    $total = @($script:RawLogs).Count
    if ($total -eq 0) {
        Write-Host "  WARNING: Log returned 0 entries." -ForegroundColor Yellow
        return $false
    }
    Write-Host "  Loaded $total raw log entries. Parsing..." -ForegroundColor Gray

    $script:DownloadComplete   = @(Get-DOParsedDownloadComplete   $script:RawLogs)
    # Group the DownloadComplete events (one per DO job / byte-range request) by (FileId + SessionId)
    # into one logical download per file. FileBytes is the file size repeated on every event; the
    # per-source byte counters are per-event and disjoint, so they are summed.
    # Using SessionId as part of the key means a re-download of the same FileId gets its own entry.
    # Events with neither FileId nor SessionId parsed are kept as their own entries (keyed by JobId)
    # instead of all collapsing into one '|' group.
    $script:UniqueDownloads    = @(
        $script:DownloadComplete | Group-Object {
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
                MccHost             = $mccHosts -join '; '
            }
        }
    )
    # Build IP → X-CID lookup from all events that carry both a server IP and an X-CID header value.
    # Seen in: TraceErrorCdnComm (serverIp field), TraceDownloadPaused (cdnIP field), error header dumps.
    $script:XCidByIp = @{}
    $script:RawLogs | Where-Object { $_.Message -match '\[\d{1,3}(?:\.\d{1,3}){3}\].*X-CID:\s*\d+' } | ForEach-Object {
        if ($_.Message -match '\[(\d{1,3}(?:\.\d{1,3}){3})\].*?X-CID:\s*(\d+)') {
            $ip = $matches[1]; $xc = [int]$matches[2]
            if (-not $script:XCidByIp.ContainsKey($ip)) { $script:XCidByIp[$ip] = $xc }
        }
    }
    $script:AnnounceComplete   = @(Get-DOParsedAnnounceComplete   $script:RawLogs)
    $script:InternalAnnounce   = @(Get-DOParsedInternalAnnounce   $script:RawLogs)
    $script:ConnectionComplete = @(Get-DOParsedConnectionComplete  $script:RawLogs)
    $script:PeerStats          = @(Get-DOParsedPeerStats           $script:RawLogs)
    $script:GeoResponses       = @(Get-DOParsedGeoResponse         $script:RawLogs)
    # Level 1=Critical, 2=Error, 3=Warning, 4=Info, 5=Verbose — capture only actual problems
    # Source = Function, or the .cpp file name when Function is empty
    $script:ErrorEvents        = @($script:RawLogs | Where-Object { $_.Level -ge 1 -and $_.Level -le 3 } |
        Select-Object TimeCreated, Level, LevelName, @{ N = 'Source'; E = { Get-DOEventSource $_ } },
            Function, ErrorCode, @{ N = 'ErrorHex'; E = { if ($_.ErrorCode) { Format-ErrorCode $_.ErrorCode } } },
            Message, ProcessId, ThreadId, LineNumber)

    $timeStats = $script:RawLogs | Measure-Object TimeCreated -Minimum -Maximum
    $script:LogStart = $timeStats.Minimum
    $script:LogEnd   = $timeStats.Maximum
    $timeRange = "  $($script:LogStart)  →  $($script:LogEnd)"

    Write-Host ""
    Write-Host "  ✓ DownloadComplete events  : $($script:DownloadComplete.Count)" -ForegroundColor Green
    Write-Host "    (unique files/sessions   : $($script:UniqueDownloads.Count))" -ForegroundColor Gray
    Write-Host "  ✓ AnnounceComplete events  : $($script:AnnounceComplete.Count)" -ForegroundColor Green
    Write-Host "  ✓ InternalAnnounce events  : $($script:InternalAnnounce.Count)" -ForegroundColor Green
    Write-Host "  ✓ ConnectionComplete events: $($script:ConnectionComplete.Count)" -ForegroundColor Green
    Write-Host "  ✓ Peer stats (final) events: $($script:PeerStats.Count)" -ForegroundColor Green
    Write-Host "  ✓ GEO response events      : $($script:GeoResponses.Count)" -ForegroundColor Green
    $errCount  = @($script:ErrorEvents | Where-Object { $_.Level -le 2 }).Count
    $warnCount = @($script:ErrorEvents | Where-Object { $_.Level -eq 3 }).Count
    Write-Host "  ✓ Error events (Level 1/2) : $errCount"  -ForegroundColor $(if ($errCount  -gt 0) { 'Red'    } else { 'Green' })
    Write-Host "  ✓ Warning events (Level 3) : $warnCount" -ForegroundColor $(if ($warnCount -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  ✓ Log time range:" -ForegroundColor Green
    Write-Host $timeRange -ForegroundColor Gray

    return $true
}

function Assert-LogsLoaded {
    if ($null -eq $script:RawLogs -or @($script:RawLogs).Count -eq 0) {
        Write-Host "`n  No logs loaded. Use option 1 to load logs first." -ForegroundColor Yellow
        Pause-ForUser
        return $false
    }
    return $true
}

#endregion

#region ─── Summary Dashboard ────────────────────────────────────────────────

function Show-SummaryDashboard {
    if (-not (Assert-LogsLoaded)) { return }

    Write-Header "Quick Summary Dashboard"
    Write-Host "  Source: $($script:LogSourceDesc)" -ForegroundColor Gray

    Write-Host "  Time range: $($script:LogStart)  →  $($script:LogEnd)" -ForegroundColor Gray

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

function Show-DownloadAnalysisMenu {
    do {
        if (-not (Assert-LogsLoaded)) { return }
        Write-Header "Download Analysis  ($($script:UniqueDownloads.Count) unique files, $($script:DownloadComplete.Count) segment events)"
        Write-Host "  1. All downloads (GridView)"
        Write-Host "  2. Filter by Caller"
        Write-Host "  3. Trace individual job (full event timeline)"
        Write-Host "  4. Session summary (byte sources for a file/session)"
        Write-Host "  5. Failed / error downloads"
        Write-Host "  6. Downloads with P2P activity (GridView)"
        Write-Host "  7. Downloads via Connected Cache (MCC) (GridView)"
        Write-Host "  Q. Back"
        $sel = (Read-Host "`n  Selection").Trim().ToLower()
        switch ($sel) {
            '1' { $script:DownloadComplete | Out-GridView -Title "All Downloads ($($script:DownloadComplete.Count))" }
            '2' { Show-DownloadsByCaller }
            '3' { Invoke-JobTrace }
            '4' { Invoke-SessionSummary }
            '5' { Show-FailedDownloads }
            '6' { $script:DownloadComplete | Where-Object { ($_.LanBytes + $_.GroupBytes + $_.InetBytes) -gt 0 } | Out-GridView -Title "Downloads with P2P bytes" }
            '7' { $script:DownloadComplete | Where-Object { $_.DoincBytes -gt 0 } | Out-GridView -Title "Downloads via Connected Cache (MCC)" }
            'q' { return }
            default { Write-Host "  Invalid selection." -ForegroundColor Red; Pause-ForUser }
        }
    } while ($true)
}

function Show-DownloadsByCaller {
    # Normalize null/empty/whitespace Caller to '(Unknown)' so they collapse into one group
    $callers = @($script:DownloadComplete |
        Group-Object { if ([string]::IsNullOrWhiteSpace($_.Caller)) { '(Unknown)' } else { $_.Caller } } |
        Where-Object { $_.Count -gt 0 } |
        Sort-Object Count -Descending |
        ForEach-Object { [PSCustomObject]@{ Caller = $_.Name; Count = $_.Count } })

    if ($callers.Count -eq 0) {
        Write-Host "`n  No callers found." -ForegroundColor Yellow
        Pause-ForUser
        return
    }

    Write-Host "`n  Available callers:" -ForegroundColor White
    for ($i = 0; $i -lt $callers.Count; $i++) {
        Write-Host ("  {0}. {1} ({2} jobs)" -f $i, $callers[$i].Caller, $callers[$i].Count)
    }
    $idx = Read-Host "`n  Enter number (or type caller name)"
    if ($idx -match '^\d+$' -and [int]$idx -lt $callers.Count) {
        $callerName = $callers[[int]$idx].Caller
    } else {
        $callerName = $idx.Trim()
    }
    # '(Unknown)' maps back to null/empty Caller entries
    $filtered = if ($callerName -eq '(Unknown)') {
        @($script:DownloadComplete | Where-Object { [string]::IsNullOrWhiteSpace($_.Caller) })
    } else {
        @($script:DownloadComplete | Where-Object { $_.Caller -ieq $callerName })
    }
    if ($filtered.Count -eq 0) {
        Write-Host "  No downloads found for caller: $callerName" -ForegroundColor Yellow
        Pause-ForUser
    } else {
        $filtered | Out-GridView -Title "Downloads by $callerName ($($filtered.Count))"
    }
}

function Show-FailedDownloads {
    $failed = $script:DownloadComplete | Where-Object { $_.ErrorCode }
    if ($failed.Count -eq 0) {
        Write-Host "`n  No failed downloads found." -ForegroundColor Green
        Pause-ForUser
        return
    }
    $failed | ForEach-Object {
        $_ | Add-Member -MemberType NoteProperty -Name ErrorDescription -Value (Get-DOErrorDescription $_.ErrorCode) -PassThru -Force
    } | Out-GridView -Title "Failed Downloads ($($failed.Count))"
}

#endregion

#region ─── Job Trace ────────────────────────────────────────────────────────

function Invoke-JobTrace {
    if ($script:DownloadComplete.Count -eq 0) {
        Write-Host "`n  No completed downloads to trace." -ForegroundColor Yellow
        Pause-ForUser
        return
    }

    Write-Host "`n  Select a download to trace (GridView will open)..." -ForegroundColor Yellow
    $selectedJob = $script:DownloadComplete | Out-GridView -Title "Select a Job to Trace" -OutputMode Single

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

    Write-Host "`n  Select a file/session to summarise (GridView will open)..." -ForegroundColor Yellow
    $selected = $script:UniqueDownloads | Out-GridView -Title "Select File/Session ($($script:UniqueDownloads.Count) entries)" -OutputMode Single

    if (-not $selected) {
        Write-Host "  No selection made." -ForegroundColor Gray
        return
    }

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
    do {
        if (-not (Assert-LogsLoaded)) { return }
        Write-Header "Peer / P2P Activity"
        Write-Host "  1. All Announce responses (GridView)"
        Write-Host "  2. All InternalAnnounce requests (GridView)"
        Write-Host "  3. Peer connections (IP list, GridView)"
        Write-Host "  4. Peer efficiency report (console)"
        Write-Host "  5. P2P activity for a specific download"
        Write-Host "  6. Peering failure analysis"
        Write-Host "  Q. Back"
        $sel = (Read-Host "`n  Selection").Trim().ToLower()
        switch ($sel) {
            '1' { $script:AnnounceComplete | Out-GridView -Title "Announce Responses ($($script:AnnounceComplete.Count))" }
            '2' { $script:InternalAnnounce | Out-GridView -Title "InternalAnnounce Requests ($($script:InternalAnnounce.Count))" }
            '3' { $script:ConnectionComplete | Out-GridView -Title "Peer Connections ($($script:ConnectionComplete.Count))" }
            '4' { Show-PeerEfficiencyReport }
            '5' { Show-PerJobPeerActivity }
            '6' { Show-PeeringFailureAnalysis }
            'q' { return }
            default { Write-Host "  Invalid selection." -ForegroundColor Red; Pause-ForUser }
        }
    } while ($true)
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

    Pause-ForUser
}

function Show-PerJobPeerActivity {
    if ($script:DownloadComplete.Count -eq 0) {
        Write-Host "`n  No completed downloads." -ForegroundColor Yellow
        Pause-ForUser
        return
    }

    # Use UniqueDownloads so parallel segment jobs appear as one entry per file/session
    $jobsWithUrl = @($script:UniqueDownloads | Where-Object { $_.CdnUrl })
    if ($jobsWithUrl.Count -eq 0) {
        Write-Host "`n  No downloads with a CDN URL found." -ForegroundColor Yellow
        Pause-ForUser
        return
    }

    Write-Host "`n  Select a download (GridView — grouped by file/session)..." -ForegroundColor Yellow
    $selectedJob = $jobsWithUrl | Select-Object TimeCreated, Caller,
        @{ N = 'FileSize';     E = { Format-Bytes $_.FileBytes } },
        @{ N = 'Network';      E = { Format-Bytes $_.NetworkBytes } },
        @{ N = 'P2P_Bytes';    E = { Format-Bytes $_.P2PBytes } },
        PeerPct,
        @{ N = 'CDN_Bytes';    E = { Format-Bytes $_.CdnBytes } },
        @{ N = 'DOINC_Bytes';  E = { Format-Bytes $_.DoincBytes } },
        Peers, SegmentCount, DownloadModeDesc,
        @{ N = 'CdnUrl_Short'; E = { if ($_.CdnUrl.Length -gt 100) { $_.CdnUrl.Substring(0, 100) + '...' } else { $_.CdnUrl } } },
        SessionId, FileId |
        Out-GridView -Title "Select Download for P2P Analysis ($($jobsWithUrl.Count) unique files)" -OutputMode Single

    if (-not $selectedJob) {
        Write-Host "  No job selected." -ForegroundColor Gray
        return
    }

    $fullJob = $script:UniqueDownloads | Where-Object { $_.FileId -eq $selectedJob.FileId -and $_.SessionId -eq $selectedJob.SessionId } | Select-Object -First 1
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

    # ── GridView of announce responses ────────────────────────────────────────
    if ($announceResps.Count -gt 0) {
        $announceResps | Select-Object TimeCreated, SwarmId, NPeers, Hr, FailureReason, Server,
            PeerCount, Complete, Incomplete, NextJoinTimeIntervalInMs |
            Out-GridView -Title "Announce Responses for This Job ($($announceResps.Count))"
    } elseif ($swarmIds.Count -eq 0) {
        Write-Host "`n  No SwarmId correlation — showing InternalAnnounce events in job time window..." -ForegroundColor Yellow
        $script:InternalAnnounce | Where-Object {
            $_.TimeCreated -ge $window.Start -and $_.TimeCreated -le $window.End
        } | Out-GridView -Title "InternalAnnounce in Job Window"
    }

    Pause-ForUser
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

    # ── 5. Zero-peer eligible jobs GridView ───────────────────────────────────
    if ($noPeerBytes.Count -gt 0) {
        Write-Host ""
        Write-Host "  Opening GridView: P2P-mode downloads with zero peer bytes..." -ForegroundColor Yellow
        $noPeerBytes | Select-Object TimeCreated, Caller, CdnUrl, FileBytes, NetworkBytes,
            CdnBytes, DoincBytes, LanBytes, GroupBytes, InetBytes, Peers, SegmentCount,
            DownloadModeDesc, DownloadModeSrcDesc, IsVpn, SessionId |
            Out-GridView -Title "P2P Downloads with Zero Peer Bytes ($($noPeerBytes.Count))"
    }

    Pause-ForUser
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

    # GridView of all downloads with MCC involvement
    $mccDownloads |
        Select-Object TimeCreated, Caller,
            @{ N = 'FileSize'; E = { Format-Bytes $_.FileBytes } },
            @{ N = 'MCCBytes'; E = { Format-Bytes $_.DoincBytes } },
            @{ N = 'CDNBytes'; E = { Format-Bytes $_.CdnBytes } },
            @{ N = 'P2PBytes'; E = { Format-Bytes $_.P2PBytes } },
            MccHost, DownloadModeDesc, IsVpn |
        Out-GridView -Title "Downloads with MCC Activity ($($mccDownloads.Count))"

    Pause-ForUser
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
    } elseif ($script:GeoResponses.Count -le 20) {
        $shaped = $script:GeoResponses | Select-Object @{ N = 'Time'; E = { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } },
            @{ N = 'ExternalIP'; E = { $_.ExternalIpAddress } }, @{ N = 'Country'; E = { $_.CountryCode } },
            @{ N = 'CacheId'; E = { $_.CacheId } }, @{ N = 'KeyValueUri'; E = { $_.KeyValueUri } }
        Write-DOTable -Data $shaped -Columns @('Time', 'ExternalIP', 'Country', 'CacheId', 'KeyValueUri')
    } else {
        $script:GeoResponses | Out-GridView -Title "GEO Responses ($($script:GeoResponses.Count))"
    }
    Pause-ForUser
}

function Show-NetworkGeoMenu {
    do {
        if (-not (Assert-LogsLoaded)) { return }
        Write-Header "Network & GEO Analysis"
        Write-Host "  1. GEO service responses / External IP history"
        Write-Host "  2. Connected Cache (MCC) analysis"
        Write-Host "  3. CDN source analysis (GridView)"
        Write-Host "  Q. Back"
        $sel = (Read-Host "`n  Selection").Trim().ToLower()
        switch ($sel) {
            '1' { Show-GeoResponseHistory }
            '2' { Show-MCCAnalysisReport }
            '3' {
                $cdnData = $script:DownloadComplete | Where-Object { $_.CdnIp -or $_.CdnUrl } |
                    Select-Object TimeCreated, Caller, CdnUrl, CdnIp,
                        @{ N = 'CDN_Size'; E = { Format-Bytes $_.CdnBytes } },
                        @{ N = 'FileSize'; E = { Format-Bytes $_.FileBytes } },
                        DownloadModeDesc
                $cdnData | Out-GridView -Title "CDN Source Analysis ($($cdnData.Count))"
            }
            'q' { return }
            default { Write-Host "  Invalid selection." -ForegroundColor Red; Pause-ForUser }
        }
    } while ($true)
}

#endregion

#region ─── Error Analysis ───────────────────────────────────────────────────

function Show-ErrorAnalysisMenu {
    do {
        if (-not (Assert-LogsLoaded)) { return }
        Write-Header "Error Analysis  ($(@($script:ErrorEvents | Where-Object {$_.Level -le 2}).Count) errors, $(@($script:ErrorEvents | Where-Object {$_.Level -eq 3}).Count) warnings)"
        Write-Host "  1. All error events (GridView)"
        Write-Host "  2. Grouped by HRESULT code (console)"
        Write-Host "  3. Grouped by Function (console)"
        Write-Host "  4. Top functions in log (all levels)"
        Write-Host "  Q. Back"
        $sel = (Read-Host "`n  Selection").Trim().ToLower()
        switch ($sel) {
            '1' { $script:ErrorEvents | Out-GridView -Title "Error Events ($($script:ErrorEvents.Count))" }
            '2' { Show-ErrorsByHresult }
            '3' { Show-ErrorsByFunction }
            '4' {
                $script:RawLogs | Group-Object Function | Sort-Object Count -Descending | Select-Object -First 25 |
                    Select-Object Count, Name | Out-GridView -Title "Top 25 Functions by Event Count"
            }
            'q' { return }
            default { Write-Host "  Invalid selection." -ForegroundColor Red; Pause-ForUser }
        }
    } while ($true)
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
        Write-Host ("  {0}" -f ($funcs -join '  |  ')) -ForegroundColor DarkGray
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

    $correlated = foreach ($s in $statusEntries) {
        # Match against aggregated UniqueDownloads to correctly reflect full multi-segment job totals
        $logMatch = $script:UniqueDownloads | Where-Object { $_.FileId -ieq $s.FileId } | Select-Object -First 1
        $totalPeerBytes = if ($logMatch) { $logMatch.P2PBytes } else { $null }
        $p2pPct = if ($logMatch) { $logMatch.PeerPct } else { $null }
        # $null checks, not truthiness: DownloadMode 0 and zero byte counts are meaningful values
        [PSCustomObject]@{
            FileId                 = $s.FileId
            Status                 = $s.Status
            Priority               = $s.Priority
            DownloadMode           = $s.DownloadMode
            FileSize               = if ($null -ne $s.FileSize) { Format-Bytes $s.FileSize } else { $null }
            BytesFromCDN           = if ($null -ne $s.BytesFromCDN) { Format-Bytes $s.BytesFromCDN } else { $null }
            BytesFromPeers         = if ($null -ne $s.BytesFromPeers) { Format-Bytes $s.BytesFromPeers } else { $null }
            BytesFromCacheHost     = if ($null -ne $s.BytesFromCacheHost) { Format-Bytes $s.BytesFromCacheHost } else { $null }
            BytesFromGroupPeers    = if ($null -ne $s.BytesFromGroupPeers) { Format-Bytes $s.BytesFromGroupPeers } else { $null }
            BytesFromInternetPeers = if ($null -ne $s.BytesFromInternetPeers) { Format-Bytes $s.BytesFromInternetPeers } else { $null }
            PercentPeerCaching     = if ($null -ne $s.PercentPeerCaching) { "$($s.PercentPeerCaching)%" } else { $null }
            CacheHost              = if ($s.CacheHost) { $s.CacheHost } else { $null }
            # Log fields
            LogFound               = ($null -ne $logMatch)
            LogTime                = if ($logMatch) { $logMatch.TimeCreated } else { $null }
            LogCaller              = if ($logMatch) { $logMatch.Caller } else { $null }
            LogSegments            = if ($logMatch) { $logMatch.SegmentCount } else { $null }
            LogFileBytes           = if ($logMatch) { Format-Bytes $logMatch.FileBytes } else { $null }
            LogCdnBytes            = if ($logMatch) { Format-Bytes $logMatch.CdnBytes } else { $null }
            LogPeerBytes           = if ($null -ne $totalPeerBytes) { Format-Bytes $totalPeerBytes } else { $null }
            LogDoincBytes          = if ($logMatch) { Format-Bytes $logMatch.DoincBytes } else { $null }
            LogP2PPct              = if ($null -ne $p2pPct) { "$p2pPct%" } else { $null }
            LogDownloadMode        = if ($logMatch) { $logMatch.DownloadModeDesc } else { $null }
            LogDuration            = if ($logMatch) { Format-TimeMs $logMatch.DurationMs } else { $null }
        }
    }

    $matched = @($correlated | Where-Object { $_.LogFound })
    Write-Host "  Matched $($matched.Count) of $($statusEntries.Count) status entries to log events." -ForegroundColor $(if ($matched.Count -gt 0) { 'Green' } else { 'Yellow' })

    if ($correlated.Count -eq 1) {
        $c = $correlated[0]
        Write-DOCard -Title "Status Correlation: $($c.FileId)" -Fields ([ordered]@{
            'Status'                    = $c.Status
            'Download Mode (live)'      = $c.DownloadMode
            'File Size'                 = $c.FileSize
            'Bytes From CDN'            = $c.BytesFromCDN
            'Bytes From Peers'          = $c.BytesFromPeers
            'Bytes From Cache Host'     = $c.BytesFromCacheHost
            '% Peer Caching'            = $c.PercentPeerCaching
            'Cache Host'                = $c.CacheHost
            'Log Match Found'           = $c.LogFound
            'Log Caller'                = $c.LogCaller
            'Log Segments'              = $c.LogSegments
            'Log File Bytes'            = $c.LogFileBytes
            'Log CDN Bytes'             = $c.LogCdnBytes
            'Log Peer Bytes'            = $c.LogPeerBytes
            'Log Connected Cache Bytes' = $c.LogDoincBytes
            'Log P2P %'                 = $c.LogP2PPct
            'Log Download Mode'         = $c.LogDownloadMode
            'Log Duration'              = $c.LogDuration
        })
    } else {
        $correlated | Out-GridView -Title "Status ↔ Log Correlation ($($correlated.Count) entries, $($matched.Count) matched)"
    }
    Pause-ForUser
}

#endregion

#region ─── Export ────────────────────────────────────────────────────────────

function Show-ExportMenu {
    do {
        if (-not (Assert-LogsLoaded)) { return }
        Write-Header "Export Reports"
        Write-Host "  1. Export DownloadComplete events (all raw segments)"
        Write-Host "  2. Export UniqueDownloads (aggregated per file/session)"
        Write-Host "  3. Export InternalAnnounce events"
        Write-Host "  4. Export AnnounceComplete events"
        Write-Host "  5. Export ConnectionComplete (peer IPs)"
        Write-Host "  6. Export PeerStats (per-peer final data transfer)"
        Write-Host "  7. Export GEO responses"
        Write-Host "  8. Export all error events"
        Write-Host "  Q. Back"
        $sel = (Read-Host "`n  Selection").Trim().ToLower()

        $dataMap = @{
            '1' = @{ Data = $script:DownloadComplete;   Name = 'DownloadComplete_RawSegments' }
            '2' = @{ Data = $script:UniqueDownloads;    Name = 'UniqueDownloads_Aggregated' }
            '3' = @{ Data = $script:InternalAnnounce;   Name = 'InternalAnnounce' }
            '4' = @{ Data = $script:AnnounceComplete;   Name = 'AnnounceComplete' }
            '5' = @{ Data = $script:ConnectionComplete; Name = 'ConnectionComplete' }
            '6' = @{ Data = $script:PeerStats;          Name = 'PeerStats' }
            '7' = @{ Data = $script:GeoResponses;       Name = 'GeoResponses' }
            '8' = @{ Data = $script:ErrorEvents;        Name = 'ErrorEvents' }
        }

        if ($dataMap.ContainsKey($sel)) {
            Export-DOReport -Data $dataMap[$sel].Data -DatasetName $dataMap[$sel].Name
        } elseif ($sel -eq 'q') {
            return
        } else {
            Write-Host "  Invalid selection." -ForegroundColor Red; Pause-ForUser
        }
    } while ($true)
}

function Export-DOReport {
    param(
        [object[]]$Data,
        [string]$DatasetName
    )
    if (-not $Data -or $Data.Count -eq 0) {
        Write-Host "`n  No data to export." -ForegroundColor Yellow
        Pause-ForUser
        return
    }
    $defaultOut = "$env:TEMP\DOLogs"
    $outFolder = Read-Host "  Export folder (default: $defaultOut)"
    if ([string]::IsNullOrWhiteSpace($outFolder)) { $outFolder = $defaultOut }
    if (-not (Test-Path $outFolder)) {
        New-Item -ItemType Directory -Path $outFolder -Force | Out-Null
    }
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $outFile = Join-Path $outFolder "DO_${DatasetName}_${timestamp}.csv"
    $Data | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8
    Write-Host "  Exported $($Data.Count) rows to: $outFile" -ForegroundColor Green
    Pause-ForUser
}

#endregion

#region ─── Main Menu ─────────────────────────────────────────────────────────

function Show-MainMenu {
    do {
        $logStatus = if ($script:RawLogs) { "  Loaded: $($script:LogSourceDesc)  ($(@($script:RawLogs).Count) entries)" } else { "  No logs loaded" }
        Write-Header "Delivery Optimization Log Analyzer"
        Write-Host $logStatus -ForegroundColor $(if ($script:RawLogs) { 'Green' } else { 'Yellow' })
        Write-Host ""
        Write-Host "  1. Load / Reload Logs"
        Write-Host "  2. Quick Summary Dashboard"
        Write-Host "  3. Download Analysis"
        Write-Host "  4. Peer / P2P Activity"
        Write-Host "  5. Network & GEO Analysis"
        Write-Host "  6. Error Analysis"
        Write-Host "  7. Correlate with DO Status (live system)"
        Write-Host "  8. Export Reports"
        Write-Host "  Q. Quit"

        $sel = (Read-Host "`n  Selection").Trim().ToLower()
        switch ($sel) {
            '1' { $null = Initialize-DOLogs }
            '2' { Show-SummaryDashboard }
            '3' { Show-DownloadAnalysisMenu }
            '4' { Show-PeerActivityMenu }
            '5' { Show-NetworkGeoMenu }
            '6' { Show-ErrorAnalysisMenu }
            '7' { Invoke-StatusCorrelation }
            '8' { Show-ExportMenu }
            'q' { Write-Host "`n  Exiting.`n" -ForegroundColor Gray; return }
            default { Write-Host "  Invalid selection." -ForegroundColor Red; Pause-ForUser }
        }
    } while ($true)
}

#endregion

#region ─── Entry Point ───────────────────────────────────────────────────────

# Store passed-in path for pre-population in prompts
$script:LogPath = $LogPath
$script:RawLogs = $null
$script:LogSourceDesc = $null
$script:XCidByIp = @{}
$script:ResolvePeerNames = [bool]$ResolvePeerNames
$script:DnsCache = @{}

# Auto-load if path provided — skip interactive prompt
if ($LogPath) {
    $null = Initialize-DOLogs -Silent
}

Show-MainMenu

#endregion
