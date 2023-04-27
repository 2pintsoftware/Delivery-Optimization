#scriptlet to pin all files in the DO cache...

$culture = [Globalization.CultureInfo]::InvariantCulture
$expiry=[DateTime]::ParseExact('12-31-2023 00:00:00', 'MM-dd-yyyy HH:mm:ss', $culture)

$Content = get-deliveryoptimizationStatus  | where-object {$_.Status -eq "Caching" -AND $_.IsPinned -eq $false} | select fileID, IsPinned

write-host "We have "$Content.count" new files to pin!"

Foreach ($file in $Content){
$filetopin = $file.fileid

set-deliveryoptimizationstatus -Pin $true -FileId $file.fileid -ExpireOn $expiry -ErrorAction SilentlyContinue
Write-host "Pinning FileID $filetopin "
}
