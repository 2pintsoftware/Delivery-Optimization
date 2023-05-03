#monitors all active DO downloads
#V1.0.0.0
#wait for a download to start
while (-not(get-deliveryoptimizationstatus  | Where-object {$_.status -eq "Downloading"}))
{cls
write-host "No Jobs Downloading yet..."
sleep 3}
# then display download stats every 3 secs until there's no more in 'downloading' state..
do {
    clear-host
    get-deliveryoptimizationstatus  | Where-object {$_.status -eq "Downloading"} | `
    select-object  Predefinedcallerapplication, @{L='File (MB)';E={“{0:N2}” -f ($_.FileSize /1MB)}}, Status, Priority, @{L='Downloaded (MB)';E={“{0:N2}” -f ($_.Totalbytesdownloaded /1MB)}},  @{L='LAN Peers (MB)';E={“{0:N2}” -f ($_.BytesFromLANPeers /1MB)}},  @{L='Group Peers (MB)';E={“{0:N2}” -f ($_.BytesFromGroupPeers /1MB)}},@{L='MCC (MB)';E={“{0:N2}” -f ($_.BytesFromCacheServer /1MB)}}, DownloadDuration | ft
       Sleep 3} until (-not(get-deliveryoptimizationstatus  | Where-object {$_.status -eq "Downloading"}))
       Write-host "No More Downloads Dude - go and get a beer"
