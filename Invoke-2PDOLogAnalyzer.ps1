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

.EXAMPLE
    .\Invoke-2PDOLogAnalyzer.ps1

.EXAMPLE
    .\Invoke-2PDOLogAnalyzer.ps1 -LogPath "C:\DOLogs\DOETLLogs_Machine_20250515"

.NOTES
    Version:        1.1
    Author:         Mattias Benninge @ 2Pint Software
    Creation Date:  2026-05-15
    Purpose/Change: Comprehensive update for DO API spec alignment, error lookup fixes,
                    expanded protocol enums, and improved multi-segment correlation.

    Requires Windows 10/11 with the DeliveryOptimization PowerShell module.
    GridView output requires Windows PowerShell or PowerShell 7+ on Windows.
    Some features (Status Correlation) require running on the source machine.
#>
[CmdletBinding()]
param(
    [string]$LogPath
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
    param([long]$Ms)
    if ($Ms -ge 60000) { return "{0:N1} min" -f ($Ms / 60000) }
    if ($Ms -ge 1000)  { return "{0:N1} sec" -f ($Ms / 1000) }
    return "$Ms ms"
}

function Get-DODownloadModeDescription {
    param([int]$Mode)
    if ($script:DODownloadModeNames.ContainsKey($Mode)) { return $script:DODownloadModeNames[$Mode] }
    return "Unknown ($Mode)"
}

function Get-DODownloadModeSrcDescription {
    param([int]$Src)
    if ($script:DODownloadModeSrcNames.ContainsKey($Src)) { return $script:DODownloadModeSrcNames[$Src] }
    return "Unknown ($Src)"
}

function Format-ErrorCode {
    # Formats any error code representation (signed int, long, hex string, decimal string) as '0xHHHHHHHH'
    param($Code)
    if ($null -eq $Code) { return $null }
    try {
        if ($Code -is [int] -or $Code -is [long]) {
            $u = [System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes([int]$Code), 0)
            return '0x{0:X8}' -f $u
        }
        if ($Code -is [string]) {
            $str = $Code.Trim()
            if ([string]::IsNullOrEmpty($str)) { return $null }
            if ($str -match '^-?\d+$') {
                $intVal = [int]([long]::Parse($str))
                $u = [System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes($intVal), 0)
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
    param($Code)
    if ($null -eq $Code) { return $null }
    try {
        $hex = Format-ErrorCode $Code
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
    param(
        [PSCustomObject]$Download,
        [string]$TitleSuffix = ''
    )
    Write-SubHeader "Byte Source Summary$TitleSuffix"
    $total = $Download.FileBytes
    $lanDoSvcBytes = [math]::Max(0, [long]$Download.LanBytes - [long]$Download.LinkLocalBytes)
    $sources = [ordered]@{
        'CDN'                       = $Download.CdnBytes
        'Connected Cache (MCC)'     = $Download.DoincBytes
        'LAN peers (DO service)'    = $lanDoSvcBytes
        'Link-local peers (DNS-SD)' = $Download.LinkLocalBytes
        'Group peers'               = $Download.GroupBytes
        'Internet peers'            = $Download.InetBytes
        'Local cache'               = $Download.LcacheBytes
    }
    foreach ($src in $sources.GetEnumerator()) {
        if ($src.Value -gt 0) {
            $pct = if ($total -gt 0) { [math]::Round(($src.Value / $total) * 100, 1) } else { 0 }
            Write-Host ("  {0,-25} : {1,10}  ({2}%)" -f $src.Key, (Format-Bytes $src.Value), $pct) -ForegroundColor White
        }
    }
    $knownBytes = [long]$Download.CdnBytes + [long]$Download.DoincBytes + [long]$Download.LanBytes +
                  [long]$Download.GroupBytes + [long]$Download.InetBytes + [long]$Download.LcacheBytes
    if ($total -gt 0 -and $knownBytes -lt $total) {
        $gap    = $total - $knownBytes
        $gapPct = [math]::Round(($gap / $total) * 100, 1)
        Write-Host ("  {0,-25} : {1,10}  ({2}%)  (segments not captured in this log)" -f '(unaccounted)', (Format-Bytes $gap), $gapPct) -ForegroundColor DarkGray
    }
    $durationMs = if ($Download.SessionTimeMs -and $Download.SessionTimeMs -gt 0) { $Download.SessionTimeMs } else { $Download.TimeMs }
    $speedBps = if ($Download.DownBps -and $Download.DownBps -gt 0) {
        $Download.DownBps
    } elseif ($total -gt 0 -and $durationMs -gt 0) {
        [long]($total / ($durationMs / 1000.0))
    } else { 0 }
    Write-Host ("  {0,-25} : {1,10}" -f 'Total file size', (Format-Bytes $total)) -ForegroundColor Cyan
    Write-Host ("  {0,-25} : {1}" -f 'Duration', (Format-TimeMs $durationMs)) -ForegroundColor Cyan
    if ($speedBps -gt 0) {
        Write-Host ("  {0,-25} : {1}/s" -f 'Avg Download Speed', (Format-Bytes $speedBps)) -ForegroundColor Cyan
    }
    Write-Host ("  {0,-25} : {1}  ({2})" -f 'Download Mode', $Download.DownloadMode, (Get-DODownloadModeDescription $Download.DownloadMode)) -ForegroundColor Cyan
    Write-Host ("  {0,-25} : {1}  ({2})" -f 'Mode Source', $Download.DownloadModeSrc, (Get-DODownloadModeSrcDescription $Download.DownloadModeSrc)) -ForegroundColor Cyan
    if ($Download.IsVpn)       { Write-Host "  VPN was active during this download" -ForegroundColor Yellow }
    if ($Download.IsThrottled) { Write-Host "  Download was throttled"              -ForegroundColor Yellow }
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
            CdnIp              = if ($msg -match 'cdnIp = (.+?)(?:,|\s|$)') {
                ($matches[1] -replace '\[([^\]]+)\]', '$1').TrimEnd(';')
            } else { $null }
            CacheHost          = if ($msg -match 'cacheHost = ([^,]*)') { $matches[1] } else { $null }
            MccIp              = if ($msg -match 'cacheHost = (?:\w+:)?(\d{1,3}(?:\.\d{1,3}){3})') { $matches[1] } else { $null }
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
            TimeMs             = if ($msg -match 'timeMs: (\d+)') { [int]$matches[1] } else { $null }
            SessionTimeMs      = if ($msg -match 'sessionTimeMs: (\d+)') { [int]$matches[1] } else { $null }
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
    param([object[]]$RawLogs)
    $RawLogs | Where-Object { $_.Function -eq 'CConnMan::ConnectionComplete' } |
    Select-Object TimeCreated, Level, LevelName, ErrorCode,
        @{ N = 'PeerIP'; E = {
            $ips = ($_.Message | Select-String -Pattern '(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4})' -AllMatches).Matches.Value
            if ($ips) { $ips -join ', ' } else { $null }
        }},
        @{ N = 'Message'; E = { $_.Message }}
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
            CacheHost            = if ($geo) { $geo.CacheHost } else { $null }
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
    # Group parallel segment jobs by (FileId + SessionId) into one logical download per file.
    # FileBytes is the total file size repeated on every segment; per-source byte counters are per-segment.
    # Using SessionId as part of the key means a re-download of the same FileId gets its own entry.
    $script:UniqueDownloads    = @(
        $script:DownloadComplete | Group-Object { "$($_.FileId)|$($_.SessionId)" } | ForEach-Object {
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
            $sessionMsMax = [long]($grp | Measure-Object SessionTimeMs   -Maximum).Maximum
            $timeMsMax    = [long]($grp | Measure-Object TimeMs          -Maximum).Maximum
            $downBpsMax   = [long]($grp | Measure-Object DownBps         -Maximum).Maximum
            $upBpsMax     = [long]($grp | Measure-Object UpBps           -Maximum).Maximum
            $mccIp        = ($grp | Where-Object { $_.MccIp } | Select-Object -Last 1).MccIp
            [PSCustomObject]@{
                TimeCreated         = $rep.TimeCreated
                FileId              = $rep.FileId
                SessionId           = $rep.SessionId
                SegmentCount        = $grp.Count
                Caller              = $rep.Caller
                CdnUrl              = $rep.CdnUrl
                CdnIp               = $rep.CdnIp
                CacheHost           = $rep.CacheHost
                FileBytes           = if ($fileBytesMax -gt 0) { $fileBytesMax } else { $rep.FileBytes }
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
                DownloadMode        = $rep.DownloadMode
                DownloadModeDesc    = $rep.DownloadModeDesc
                DownloadModeSrc     = $rep.DownloadModeSrc
                DownloadModeSrcDesc = $rep.DownloadModeSrcDesc
                GroupId             = $rep.GroupId
                Background          = $rep.Background
                IsVpn               = $rep.IsVpn
                IsThrottled         = $rep.IsThrottled
                MccIp               = $mccIp
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
    $script:ErrorEvents        = @($script:RawLogs | Where-Object { $_.Level -ge 1 -and $_.Level -le 3 })

    $timeRange = if ($script:RawLogs) {
        $sorted = $script:RawLogs | Sort-Object TimeCreated
        "  $($sorted[0].TimeCreated)  →  $($sorted[-1].TimeCreated)"
    } else { '  (none)' }

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

    # Time range
    $sorted = $script:RawLogs | Sort-Object TimeCreated
    Write-Host "  Time range: $($sorted[0].TimeCreated)  →  $($sorted[-1].TimeCreated)" -ForegroundColor Gray

    # Downloads — UniqueDownloads groups parallel segments by (FileId+SessionId) so FileBytes is not multiplied
    Write-SubHeader "Downloads ($($script:UniqueDownloads.Count) unique files, $($script:DownloadComplete.Count) segment events)"

    if ($script:DownloadComplete.Count -gt 0) {
        $totalFile   = ($script:UniqueDownloads | Measure-Object -Property FileBytes   -Sum).Sum
        $totalCdn    = ($script:UniqueDownloads | Measure-Object -Property CdnBytes    -Sum).Sum
        $totalDoinc  = ($script:UniqueDownloads | Measure-Object -Property DoincBytes  -Sum).Sum
        $totalMcc    = $totalDoinc
        $totalLan    = ($script:UniqueDownloads | Measure-Object -Property LanBytes    -Sum).Sum
        $totalGroup  = ($script:UniqueDownloads | Measure-Object -Property GroupBytes  -Sum).Sum
        $totalInet   = ($script:UniqueDownloads | Measure-Object -Property InetBytes   -Sum).Sum
        $totalP2P    = $totalLan + $totalGroup + $totalInet
        $p2pPct      = if ($totalFile -gt 0) { [math]::Round(($totalP2P / $totalFile) * 100, 1) } else { 0 }
        $mccPct      = if ($totalFile -gt 0) { [math]::Round(($totalMcc  / $totalFile) * 100, 1) } else { 0 }
        $cdnPct      = if ($totalFile -gt 0) { [math]::Round(($totalCdn  / $totalFile) * 100, 1) } else { 0 }

        Write-Host "  Total data delivered  : $(Format-Bytes $totalFile)" -ForegroundColor White
        Write-Host "    CDN                 : $(Format-Bytes $totalCdn) ($cdnPct%)" -ForegroundColor $(if ($cdnPct -gt 80) { 'Yellow' } else { 'Gray' })
        Write-Host "    Connected Cache     : $(Format-Bytes $totalMcc) ($mccPct%)" -ForegroundColor Cyan
        if ($totalMcc -gt 0) {
            # Show per-server X-CID type breakdown
            $mccServers = $script:UniqueDownloads | Where-Object { $_.MccIp } |
                Select-Object -ExpandProperty MccIp -Unique | Sort-Object | ForEach-Object {
                    $xcid    = if ($script:XCidByIp -and $script:XCidByIp.ContainsKey($_)) { $script:XCidByIp[$_] } else { $null }
                    $mccType = Get-MCCTypeDescription $xcid
                    $xcStr   = if ($null -ne $xcid) { " (X-CID=$xcid)" } else { '' }
                    "      $_${xcStr}  → $mccType"
                }
            foreach ($line in $mccServers) { Write-Host $line -ForegroundColor DarkCyan }
        }
        Write-Host "    LAN peers           : $(Format-Bytes $totalLan)" -ForegroundColor Green
        Write-Host "    Group peers         : $(Format-Bytes $totalGroup)" -ForegroundColor Green
        Write-Host "    Internet peers      : $(Format-Bytes $totalInet)" -ForegroundColor Green
        Write-Host "  P2P efficiency        : $p2pPct% of bytes from peers" -ForegroundColor $(if ($p2pPct -gt 30) { 'Green' } elseif ($p2pPct -gt 0) { 'Yellow' } else { 'Red' })

        # By download mode
        Write-SubHeader "Download Mode Breakdown"
        $script:UniqueDownloads | Group-Object DownloadMode | Sort-Object Name | ForEach-Object {
            $modeDesc = Get-DODownloadModeDescription ([int]$_.Name)
            Write-Host ("  Mode {0,-3} {1,-35} : {2} file(s)" -f $_.Name, "($modeDesc)", $_.Count) -ForegroundColor White
        }

        # By caller
        Write-SubHeader "Callers"
        $script:UniqueDownloads | Group-Object Caller | Sort-Object Count -Descending | ForEach-Object {
            Write-Host ("  {0,-40} : {1} file(s)" -f $_.Name, $_.Count) -ForegroundColor White
        }
    }

    # Peers
    if ($script:ConnectionComplete.Count -gt 0) {
        Write-SubHeader "Peer Connections"
        Write-Host "  Connection events: $($script:ConnectionComplete.Count)" -ForegroundColor White
        $uniquePeers = $script:ConnectionComplete.PeerIP | Where-Object { $_ } | Sort-Object -Unique
        Write-Host "  Unique peer IPs : $($uniquePeers.Count)" -ForegroundColor White
    }

    # GEO
    if ($script:GeoResponses.Count -gt 0) {
        Write-SubHeader "Network Identity"
        $latest = $script:GeoResponses | Sort-Object TimeCreated | Select-Object -Last 1
        Write-Host "  External IP  : $($latest.ExternalIpAddress)" -ForegroundColor White
        Write-Host "  Country      : $($latest.CountryCode)" -ForegroundColor White
        if ($latest.CacheHost) {
            Write-Host "  Cache Host   : $($latest.CacheHost)" -ForegroundColor Cyan
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
            $errL2 | Group-Object Function | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
                # Collect any HRESULT codes from ErrorCode property or embedded in Message
                $codes = $_.Group | ForEach-Object {
                    if ($_.ErrorCode -and $_.ErrorCode -ne 0) {
                        Format-ErrorCode $_.ErrorCode
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
            $errL3 | Group-Object Function | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
                $codes = $_.Group | Where-Object { $_.ErrorCode -and $_.ErrorCode -ne 0 } |
                    ForEach-Object { Format-ErrorCode $_.ErrorCode } | Sort-Object -Unique
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
    $failed = $script:DownloadComplete | Where-Object { $_.ErrorCode -and $_.ErrorCode -ne '0' -and $_.ErrorCode -ne '' }
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

    $fileId      = $selectedJob.FileId
    $jobId       = $selectedJob.JobId
    $jobTime     = $selectedJob.TimeCreated
    $windowStart = $jobTime.AddMinutes(-30)
    $windowEnd   = $jobTime.AddMinutes(5)

    # Use UniqueDownloads aggregated bytes so parallel segment jobs are summed correctly
    $fileDownload = $script:UniqueDownloads | Where-Object {
        $_.FileId -eq $fileId -and $_.SessionId -eq $selectedJob.SessionId
    } | Select-Object -First 1
    $srcRef = if ($fileDownload) { $fileDownload } else { $selectedJob }

    Write-Header "Job Trace: $jobId"
    Write-Host "  FileId     : $fileId" -ForegroundColor Gray
    Write-Host "  Caller     : $($selectedJob.Caller)" -ForegroundColor Gray
    Write-Host "  Completed  : $jobTime" -ForegroundColor Gray

    # Find SwarmIds — Strategy 1: ContentId in FileId
    $swarmIds = @($script:InternalAnnounce | Where-Object {
        $_.TimeCreated -ge $windowStart -and $_.TimeCreated -le $windowEnd -and
        $_.ContentId -and $fileId -and ($fileId -like "*$($_.ContentId)*" -or $_.ContentId -like "*$fileId*")
    } | Select-Object -ExpandProperty SwarmId | Where-Object { $_ } | Sort-Object -Unique)

    # Strategy 2: Match AltCatalogId (URL) stripped of query parameters
    if ($swarmIds.Count -eq 0 -and $selectedJob.CdnUrl) {
        $cleanUrl = $selectedJob.CdnUrl.Split('?')[0].TrimEnd('/')
        $swarmIds = @($script:InternalAnnounce | Where-Object {
            $_.TimeCreated -ge $windowStart -and $_.TimeCreated -le $windowEnd -and
            $_.AltCatalogId -and ($_.AltCatalogId.Split('?')[0].TrimEnd('/') -eq $cleanUrl)
        } | Select-Object -ExpandProperty SwarmId | Where-Object { $_ } | Sort-Object -Unique)
    }

    # Strategy 3: Fall back to all SwarmIds in time window
    if ($swarmIds.Count -eq 0) {
        $swarmIds = @($script:InternalAnnounce | Where-Object {
            $_.TimeCreated -ge $windowStart -and $_.TimeCreated -le $windowEnd -and
            $_.SwarmId -and $_.SwarmId -ne ''
        } | Select-Object -ExpandProperty SwarmId | Where-Object { $_ } | Sort-Object -Unique)
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

    # PeerConnected events (CConnMan::ConnectionComplete — TCP session opened)
    $ccEvents = $script:ConnectionComplete | Where-Object {
        $_.TimeCreated -ge $windowStart -and $_.TimeCreated -le $windowEnd
    }
    foreach ($e in $ccEvents) {
        $timeline.Add([PSCustomObject]@{
            TimeCreated = $e.TimeCreated
            EventType   = 'PeerConnected'
            PeerIP      = $e.PeerIP
            SwarmId     = ''
            BytesRecv   = ''
            BytesSent   = ''
            Detail      = 'TCP connection established'
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

    # DownloadComplete marker
    $peerBytes = [long]$srcRef.LanBytes + [long]$srcRef.GroupBytes + [long]$srcRef.InetBytes
    $timeline.Add([PSCustomObject]@{
        TimeCreated = $selectedJob.TimeCreated
        EventType   = 'DownloadComplete'
        PeerIP      = $selectedJob.CdnIp
        SwarmId     = ''
        BytesRecv   = Format-Bytes $srcRef.FileBytes
        BytesSent   = ''
        Detail      = "Caller=$($selectedJob.Caller)  Mode=$(Get-DODownloadModeDescription $selectedJob.DownloadMode)  CDN=$(Format-Bytes $srcRef.CdnBytes)  Peers=$(Format-Bytes $peerBytes)  MCC=$(Format-Bytes $srcRef.DoincBytes)  Dur=$(Format-TimeMs $srcRef.TimeMs)"
    })

    $sortedTimeline = $timeline | Sort-Object TimeCreated

    # Display timeline in GridView
    $sortedTimeline | Out-GridView -Title "Job Timeline: $jobId  [$($sortedTimeline.Count) events]"

    # Console byte summary — use unified Show-DOByteSourceSummary
    $segNote = if ($fileDownload -and $fileDownload.SegmentCount -gt 1) { " for this Job (aggregated across $($fileDownload.SegmentCount) segments)" } else { ' for this Job' }
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

    $segNote = if ($selected.SegmentCount -gt 1) { " (aggregated across $($selected.SegmentCount) segments)" } else { '' }
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

    # Overall — use UniqueDownloads to avoid counting FileBytes once per parallel segment event
    $allTotal = ($script:UniqueDownloads | Measure-Object FileBytes -Sum).Sum
    $allP2P   = ($script:UniqueDownloads | ForEach-Object { [long]$_.LanBytes + [long]$_.GroupBytes + [long]$_.InetBytes } | Measure-Object -Sum).Sum
    $allDoinc = ($script:UniqueDownloads | Measure-Object DoincBytes -Sum).Sum
    $allCdn   = ($script:UniqueDownloads | Measure-Object CdnBytes   -Sum).Sum

    Write-SubHeader "Overall"
    Write-Host ("  Total bytes delivered : {0}" -f (Format-Bytes $allTotal)) -ForegroundColor White
    Write-Host ("  From CDN              : {0} ({1}%)" -f (Format-Bytes $allCdn),   [math]::Round($allCdn   / [math]::Max($allTotal,1) * 100,1)) -ForegroundColor Gray
    Write-Host ("  From peers (P2P)      : {0} ({1}%)" -f (Format-Bytes $allP2P),  [math]::Round($allP2P   / [math]::Max($allTotal,1) * 100,1)) -ForegroundColor Green
    Write-Host ("  From Connected Cache  : {0} ({1}%)" -f (Format-Bytes $allDoinc),[math]::Round($allDoinc / [math]::Max($allTotal,1) * 100,1)) -ForegroundColor Cyan

    # By Download Mode
    Write-SubHeader "By Download Mode"
    $script:UniqueDownloads | Group-Object DownloadMode | Sort-Object Name | ForEach-Object {
        $modeDesc = Get-DODownloadModeDescription ([int]$_.Name)
        $grpTotal = ($_.Group | Measure-Object FileBytes -Sum).Sum
        $grpP2P   = ($_.Group | ForEach-Object { [long]$_.LanBytes + [long]$_.GroupBytes + [long]$_.InetBytes } | Measure-Object -Sum).Sum
        $pct      = [math]::Round($grpP2P / [math]::Max($grpTotal,1) * 100, 1)
        Write-Host ("  Mode {0} ({1,-30}) : {2} file(s), {3} total, {4}% P2P" -f $_.Name, $modeDesc, $_.Count, (Format-Bytes $grpTotal), $pct) -ForegroundColor White
    }

    # Unique peers
    if ($script:ConnectionComplete.Count -gt 0) {
        $uniquePeers = $script:ConnectionComplete.PeerIP | Where-Object { $_ } | Sort-Object -Unique
        Write-SubHeader "Peer Connections"
        Write-Host "  Total connection events : $($script:ConnectionComplete.Count)" -ForegroundColor White
        Write-Host "  Unique peer IPs         : $($uniquePeers.Count)" -ForegroundColor White
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
        @{ N = 'P2P_Bytes';    E = { Format-Bytes ($_.LanBytes + $_.GroupBytes + $_.InetBytes) } },
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
    Write-Host ("  Segments   : {0} parallel job(s)" -f $fullJob.SegmentCount) -ForegroundColor Gray
    Write-Host ("  Completed  : {0}" -f $jobTime)           -ForegroundColor Gray
    Write-Host ("  File size  : {0}" -f (Format-Bytes $fullJob.FileBytes)) -ForegroundColor Gray
    Write-Host ("  Duration   : {0}" -f (Format-TimeMs ($fullJob.SessionTimeMs -or $fullJob.TimeMs))) -ForegroundColor Gray
    Write-Host ("  Mode       : {0}" -f $fullJob.DownloadModeDesc)         -ForegroundColor Gray
    Write-Host ("  CdnUrl     : {0}" -f $fullJob.CdnUrl)   -ForegroundColor Gray

    # ── Correlate to SwarmId ──────────────────────────────────────────────────
    # Strategy 1: ContentId appears in FileId (reliable for Windows Update)
    $matchedIA = @($script:InternalAnnounce | Where-Object {
        $_.ContentId -and $fileId -and (
            $fileId      -like "*$($_.ContentId)*" -or
            $_.ContentId -like "*$fileId*"
        )
    })
    $swarmIds    = @($matchedIA.SwarmId | Where-Object { $_ } | Sort-Object -Unique)
    $matchMethod = 'ContentId'

    # Strategy 2: Match AltCatalogId (URL) stripped of query parameters
    if ($swarmIds.Count -eq 0 -and $fullJob.CdnUrl) {
        $cleanUrl = $fullJob.CdnUrl.Split('?')[0].TrimEnd('/')
        $matchedIA = @($script:InternalAnnounce | Where-Object {
            $_.AltCatalogId -and ($_.AltCatalogId.Split('?')[0].TrimEnd('/') -eq $cleanUrl)
        })
        $swarmIds = @($matchedIA.SwarmId | Where-Object { $_ } | Sort-Object -Unique)
        if ($swarmIds.Count -gt 0) { $matchMethod = 'AltCatalogId (Source URL)' }
    }

    # Strategy 3: Estimate time window from job duration
    if ($swarmIds.Count -eq 0) {
        $durationMs     = [math]::Max($fullJob.TimeMs, 0)
        $estimatedStart = $jobTime.AddMilliseconds(-$durationMs).AddMinutes(-2)
        $windowEnd      = $jobTime.AddMinutes(2)
        $iaInWindow     = @($script:InternalAnnounce | Where-Object {
            $_.TimeCreated -ge $estimatedStart -and $_.TimeCreated -le $windowEnd
        })
        $swarmIds    = @($iaInWindow.SwarmId | Where-Object { $_ } | Sort-Object -Unique)
        $matchMethod = 'TimeWindow (approximate)'
    }

    $matchColor = if ($matchMethod -in @('ContentId', 'AltCatalogId (Source URL)')) { 'Green' } else { 'Yellow' }
    Write-Host ("  Swarm correlation : {0} — {1} swarm(s)" -f $matchMethod, $swarmIds.Count) -ForegroundColor $matchColor

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
                $hrFmt   = Format-ErrorCode $_.Hr
                $desc    = Get-DOErrorDescription $_.Hr
                $descStr = if ($desc) { "  — $desc" } else { '' }
                Write-Host ("  {0}  Hr={1}{2}" -f $_.TimeCreated, $hrFmt, $descStr) -ForegroundColor Yellow
            }
        }
    }

    # ── Byte Sources ──────────────────────────────────────────────────────────
    # Aggregate all parallel segments for this (FileId+SessionId) so bytes are not under-reported
    $fileDownload = $script:UniqueDownloads | Where-Object { $_.FileId -eq $fileId -and $_.SessionId -eq $fullJob.SessionId } | Select-Object -First 1
    $srcRef       = if ($fileDownload) { $fileDownload } else { $fullJob }
    $segNote      = if ($fileDownload -and $fileDownload.SegmentCount -gt 1) { " (aggregated across $($fileDownload.SegmentCount) parallel segments)" } else { '' }
    Write-SubHeader "Byte Sources for This Download$segNote"
    $totalP2P = $srcRef.LanBytes + $srcRef.GroupBytes + $srcRef.InetBytes
    $pct      = if ($srcRef.FileBytes -gt 0) { [math]::Round($totalP2P / $srcRef.FileBytes * 100, 1) } else { 0 }
    Write-Host ("  LAN peers           : {0}" -f (Format-Bytes $srcRef.LanBytes))   -ForegroundColor $(if ($srcRef.LanBytes   -gt 0) { 'Green' } else { 'Gray' })
    Write-Host ("  Group peers         : {0}" -f (Format-Bytes $srcRef.GroupBytes)) -ForegroundColor $(if ($srcRef.GroupBytes -gt 0) { 'Green' } else { 'Gray' })
    Write-Host ("  Internet peers      : {0}" -f (Format-Bytes $srcRef.InetBytes))  -ForegroundColor $(if ($srcRef.InetBytes  -gt 0) { 'Green' } else { 'Gray' })
    Write-Host ("  CDN                 : {0}" -f (Format-Bytes $srcRef.CdnBytes))   -ForegroundColor Gray
    Write-Host ("  Connected Cache     : {0}" -f (Format-Bytes $srcRef.DoincBytes)) -ForegroundColor Cyan
    Write-Host ("  P2P total           : {0} ({1}% of download)" -f (Format-Bytes $totalP2P), $pct) `
        -ForegroundColor $(if ($pct -gt 0) { 'Green' } else { 'Yellow' })

    # ── Per-Peer Data Breakdown ───────────────────────────────────────────────
    $peerStatMatches = if ($swarmIds.Count -gt 0) {
        @($script:PeerStats | Where-Object { $swarmIds -contains $_.SwarmId })
    } elseif ($script:PeerStats.Count -gt 0) {
        # Fall back to time-window correlation
        $durationMs2    = [math]::Max($fullJob.TimeMs, 0)
        $estStart2      = $jobTime.AddMilliseconds(-$durationMs2).AddMinutes(-2)
        $estEnd2        = $jobTime.AddMinutes(2)
        @($script:PeerStats | Where-Object { $_.TimeCreated -ge $estStart2 -and $_.TimeCreated -le $estEnd2 })
    } else { @() }

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
            # Try DNS reverse-lookup for the peer IP
            $hostname = $null
            try {
                $entry    = [System.Net.Dns]::GetHostEntry($peer.PeerIP)
                $hostname = $entry.HostName
            } catch {}

            $pct       = if ($totalPeerRecv -gt 0) { [math]::Round($peer.BytesRecv / $totalPeerRecv * 100, 1) } else { 0 }
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
        $durationMs     = [math]::Max($fullJob.TimeMs, 0)
        $estimatedStart = $jobTime.AddMilliseconds(-$durationMs).AddMinutes(-2)
        $windowEnd      = $jobTime.AddMinutes(2)
        $script:InternalAnnounce | Where-Object {
            $_.TimeCreated -ge $estimatedStart -and $_.TimeCreated -le $windowEnd
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
    $analysisDownloads = @($script:UniqueDownloads)
    $fileIdDupes = @($analysisDownloads | Group-Object FileId | Where-Object { $_.Count -gt 1 })
    if ($fileIdDupes.Count -gt 0) {
        $analysisDownloads = @(
            $analysisDownloads | Group-Object FileId | ForEach-Object {
                $grp = $_.Group | Sort-Object TimeCreated
                $rep = $grp | Select-Object -Last 1
                [PSCustomObject]@{
                    TimeCreated         = $rep.TimeCreated
                    FileId              = $rep.FileId
                    SessionId           = ($grp.SessionId | Where-Object { $_ } | Sort-Object -Unique) -join ','
                    SegmentCount        = [int]($grp | Measure-Object SegmentCount -Sum).Sum
                    Caller              = $rep.Caller
                    CdnUrl              = $rep.CdnUrl
                    CdnIp               = $rep.CdnIp
                    CacheHost           = $rep.CacheHost
                    FileBytes           = [long]($grp | Measure-Object FileBytes -Maximum).Maximum
                    CdnBytes            = [long]($grp | Measure-Object CdnBytes -Sum).Sum
                    DoincBytes          = [long]($grp | Measure-Object DoincBytes -Sum).Sum
                    LanBytes            = [long]($grp | Measure-Object LanBytes -Sum).Sum
                    LinkLocalBytes      = [long]($grp | Measure-Object LinkLocalBytes -Sum).Sum
                    GroupBytes          = [long]($grp | Measure-Object GroupBytes -Sum).Sum
                    InetBytes           = [long]($grp | Measure-Object InetBytes -Sum).Sum
                    Peers               = [int]($grp | Measure-Object Peers -Maximum).Maximum
                    DownBps             = [long]($grp | Measure-Object DownBps -Maximum).Maximum
                    UpBps               = [long]($grp | Measure-Object UpBps -Maximum).Maximum
                    TimeMs              = [long]($grp | Measure-Object TimeMs -Maximum).Maximum
                    SessionTimeMs       = [long]($grp | Measure-Object SessionTimeMs -Maximum).Maximum
                    DownloadMode        = $rep.DownloadMode
                    DownloadModeDesc    = $rep.DownloadModeDesc
                    DownloadModeSrc     = $rep.DownloadModeSrc
                    DownloadModeSrcDesc = $rep.DownloadModeSrcDesc
                    GroupId             = $rep.GroupId
                    Background          = $rep.Background
                    IsVpn               = $rep.IsVpn
                    IsThrottled         = $rep.IsThrottled
                }
            }
        )
    }

    $p2pModes    = @(1, 2, 3)
    $eligible    = @($analysisDownloads | Where-Object { $p2pModes -contains $_.DownloadMode -and $_.CdnUrl })
    $hadPeers    = @($eligible | Where-Object { ($_.LanBytes + $_.GroupBytes + $_.InetBytes) -gt 0 })
    $noPeerBytes = @($eligible | Where-Object { ($_.LanBytes + $_.GroupBytes + $_.InetBytes) -eq 0 })

    Write-SubHeader "Downloads in P2P-Capable Mode (1/2/3) with CDN URL"
    Write-Host ("  Segment DownloadComplete events : {0}" -f $script:DownloadComplete.Count) -ForegroundColor DarkGray
    Write-Host ("  Unique files/sessions parsed   : {0}" -f $script:UniqueDownloads.Count) -ForegroundColor DarkGray
    if ($fileIdDupes.Count -gt 0) {
        Write-Host ("  FileId duplicate groups found  : {0} (extra collapse applied)" -f $fileIdDupes.Count) -ForegroundColor Yellow
    }
    Write-Host ("  Total eligible files      : {0}" -f $eligible.Count)    -ForegroundColor White
    Write-Host ("  Files with peer bytes     : {0}" -f $hadPeers.Count)    -ForegroundColor $(if ($hadPeers.Count    -gt 0) { 'Green'  } else { 'Yellow' })
    Write-Host ("  Files with ZERO peer bytes: {0}" -f $noPeerBytes.Count) -ForegroundColor $(if ($noPeerBytes.Count -gt 0) { 'Red'    } else { 'Green'  })

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
            $hrFmt   = Format-ErrorCode $_.Name
            $desc    = Get-DOErrorDescription $_.Name
            $descStr = if ($desc) { "  — $desc" } else { '' }
            Write-Host ("    {0,-14} x{1,-5}{2}" -f $hrFmt, $_.Count, $descStr) -ForegroundColor Red
        }
    }

    # ── 3. CAnnounceSequencer and CConnMan error events ───────────────────────
    $announceErrEvents = @($script:RawLogs | Where-Object {
        $_.Function -like 'CAnnounceSequencer*' -and $_.Level -le 3
    })
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

        $swarmSummary | Out-GridView -Title "Per-Swarm Peer Summary ($($swarmSummary.Count) swarms)"
    }

    # ── 5. Zero-peer eligible jobs GridView ───────────────────────────────────
    if ($noPeerBytes.Count -gt 0) {
        Write-Host ""
        Write-Host "  Opening GridView: P2P-mode downloads with zero peer bytes..." -ForegroundColor Yellow
        $noPeerBytes | Select-Object TimeCreated, Caller, CdnUrl,
            @{ N = 'FileSize'; E = { Format-Bytes $_.FileBytes } },
            LanBytes, GroupBytes, InetBytes, Peers, SegmentCount,
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

    $totalAll = [long]($script:UniqueDownloads | Measure-Object FileBytes -Sum).Sum
    $totalMcc = [long]($mccDownloads | Measure-Object DoincBytes -Sum).Sum
    $mccPct   = if ($totalAll -gt 0) { [math]::Round($totalMcc / $totalAll * 100, 1) } else { 0 }

    Write-SubHeader "Overall MCC Activity"
    Write-Host ("  Downloads using MCC    : {0} of {1}" -f $mccDownloads.Count, $script:UniqueDownloads.Count) -ForegroundColor White
    Write-Host ("  Total bytes from MCC   : {0}  ({1}% of all downloaded data)" -f (Format-Bytes $totalMcc), $mccPct) -ForegroundColor Cyan

    # Per-server breakdown grouped by MCC IP
    $byServer = @($mccDownloads | Where-Object { $_.MccIp } |
        Group-Object MccIp | ForEach-Object {
            $grp      = $_.Group
            $mccIp    = $_.Name
            $svrBytes = [long]($grp | Measure-Object DoincBytes -Sum).Sum
            $xcid     = if ($script:XCidByIp -and $script:XCidByIp.ContainsKey($mccIp)) { $script:XCidByIp[$mccIp] } else { $null }
            $mccType  = if ($null -ne $xcid) { Get-MCCTypeDescription $xcid } else { 'Unknown (X-CID not observed)' }
            [PSCustomObject]@{
                MccIP      = $mccIp
                XCid       = if ($null -ne $xcid) { $xcid } else { '?' }
                MccType    = $mccType
                Downloads  = $grp.Count
                Bytes      = $svrBytes
                BytesHuman = Format-Bytes $svrBytes
                PctOfTotal = if ($totalAll -gt 0) { [math]::Round($svrBytes / $totalAll * 100, 1) } else { 0 }
            }
        } | Sort-Object Bytes -Descending)

    if ($byServer.Count -gt 0) {
        Write-SubHeader "Per-MCC-Server Breakdown"
        foreach ($svr in $byServer) {
            $typeColor = if ($svr.MccType -match 'Distribution Point') { 'Green'  }
                         elseif ($svr.MccType -match 'Standalone')      { 'Cyan'   }
                         elseif ($svr.MccType -match 'Internet')        { 'Yellow' }
                         elseif ($svr.MccType -match 'CDN')             { 'Gray'   }
                         else                                            { 'White'  }
            Write-Host ""
            Write-Host ("  Server  : {0}" -f $svr.MccIP)                                               -ForegroundColor White
            Write-Host ("  X-CID   : {0}" -f $svr.XCid)                                               -ForegroundColor White
            Write-Host ("  Type    : {0}" -f $svr.MccType)                                             -ForegroundColor $typeColor
            Write-Host ("  Files   : {0} download(s)" -f $svr.Downloads)                              -ForegroundColor White
            Write-Host ("  Bytes   : {0}  ({1}% of total data)" -f $svr.BytesHuman, $svr.PctOfTotal) -ForegroundColor Cyan
        }
        Write-Host ""
        $byServer | Select-Object MccIP, XCid, MccType, Downloads, BytesHuman, PctOfTotal |
            Out-GridView -Title "MCC Server Breakdown ($($byServer.Count) server(s))"
    } else {
        Write-Host "`n  MCC activity detected but server IP could not be resolved (cacheHost field empty in logs)." -ForegroundColor Yellow
        Write-Host ("  Total MCC bytes: {0}" -f (Format-Bytes $totalMcc)) -ForegroundColor Cyan
    }

    # GridView of all downloads with MCC involvement
    $mccDownloads |
        Select-Object TimeCreated, Caller,
            @{ N = 'FileSize'; E = { Format-Bytes $_.FileBytes } },
            @{ N = 'MCCBytes'; E = { Format-Bytes $_.DoincBytes } },
            @{ N = 'CDNBytes'; E = { Format-Bytes $_.CdnBytes } },
            @{ N = 'P2PBytes'; E = { Format-Bytes ([long]$_.LanBytes + [long]$_.GroupBytes + [long]$_.InetBytes) } },
            MccIp, DownloadModeDesc, IsVpn |
        Out-GridView -Title "Downloads with MCC Activity ($($mccDownloads.Count))"

    Pause-ForUser
}

function Show-NetworkGeoMenu {
    do {
        if (-not (Assert-LogsLoaded)) { return }
        Write-Header "Network & GEO Analysis"
        Write-Host "  1. GEO service responses / External IP history (GridView)"
        Write-Host "  2. Connected Cache (MCC) analysis"
        Write-Host "  3. CDN source analysis (GridView)"
        Write-Host "  Q. Back"
        $sel = (Read-Host "`n  Selection").Trim().ToLower()
        switch ($sel) {
            '1' { $script:GeoResponses | Out-GridView -Title "GEO Responses ($($script:GeoResponses.Count))" }
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
            $code = Format-ErrorCode $_.ErrorCode
        } elseif ($_.Message -match '(?i)(?:error|hr)[: ]+([0-9a-fA-F]{6,8})\b') {
            $code = '0x' + $matches[1].ToUpper().PadLeft(8,'0')
        }
        if ($code) { [PSCustomObject]@{ Code = $code; Function = $_.Function; Level = $_.Level } }
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
    $script:ErrorEvents | Where-Object { $_.Function } | Group-Object Function | Sort-Object Count -Descending | ForEach-Object {
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
        $totalPeerBytes = if ($logMatch) { [long]$logMatch.LanBytes + [long]$logMatch.GroupBytes + [long]$logMatch.InetBytes } else { $null }
        $p2pPct = if ($logMatch -and $logMatch.FileBytes -gt 0 -and $null -ne $totalPeerBytes) {
            [math]::Round(($totalPeerBytes / $logMatch.FileBytes) * 100, 1)
        } else { $null }
        [PSCustomObject]@{
            FileId                 = $s.FileId
            Status                 = $s.Status
            Priority               = if ($s.Priority) { $s.Priority } else { $null }
            DownloadMode           = if ($s.DownloadMode) { $s.DownloadMode } else { $null }
            FileSize               = if ($s.FileSize) { Format-Bytes $s.FileSize } else { $null }
            BytesFromCDN           = if ($s.BytesFromCDN) { Format-Bytes $s.BytesFromCDN } else { $null }
            BytesFromPeers         = if ($s.BytesFromPeers) { Format-Bytes $s.BytesFromPeers } else { $null }
            BytesFromCacheHost     = if ($s.BytesFromCacheHost) { Format-Bytes $s.BytesFromCacheHost } else { $null }
            BytesFromGroupPeers    = if ($s.BytesFromGroupPeers) { Format-Bytes $s.BytesFromGroupPeers } else { $null }
            BytesFromInternetPeers = if ($s.BytesFromInternetPeers) { Format-Bytes $s.BytesFromInternetPeers } else { $null }
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
            LogDuration            = if ($logMatch) { Format-TimeMs ($logMatch.SessionTimeMs -or $logMatch.TimeMs) } else { $null }
        }
    }

    $matched = @($correlated | Where-Object { $_.LogFound })
    Write-Host "  Matched $($matched.Count) of $($statusEntries.Count) status entries to log events." -ForegroundColor $(if ($matched.Count -gt 0) { 'Green' } else { 'Yellow' })

    $correlated | Out-GridView -Title "Status ↔ Log Correlation ($($correlated.Count) entries, $($matched.Count) matched)"
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

# Auto-load if path provided — skip interactive prompt
if ($LogPath) {
    $null = Initialize-DOLogs -Silent
}

Show-MainMenu

#endregion
