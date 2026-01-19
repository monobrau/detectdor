<#
.SYNOPSIS
    Test script to verify GitHub execution works
#>

Write-Host "Testing GitHub download..." -ForegroundColor Cyan

$GitHubUrl = "https://raw.githubusercontent.com/monobrau/detectdor/main/Invoke-ADDiscovery.ps1"

try {
    # Ensure TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    Write-Host "Downloading from: $GitHubUrl" -ForegroundColor Yellow
    
    # Add cache-busting parameter to force fresh download
    $separator = if ($GitHubUrl -match '\?') { '&' } else { '?' }
    $cacheBustUrl = "$GitHubUrl$separator`_=$([DateTimeOffset]::Now.ToUnixTimeMilliseconds())"
    
    # Test download with cache-busting headers
    $headers = @{
        'Cache-Control' = 'no-cache, no-store, must-revalidate'
        'Pragma' = 'no-cache'
        'Expires' = '0'
    }
    
    $script = Invoke-WebRequest -Uri $cacheBustUrl -Headers $headers -UseBasicParsing
    Write-Host "Successfully downloaded $($script.Content.Length) characters (fresh copy)" -ForegroundColor Green
    
    Write-Host "`nTo execute the script with cache-busting, use:" -ForegroundColor Cyan
    Write-Host "`$url = '$GitHubUrl'; `$cb = if (`$url -match '\?') { '&' } else { '?' }; iex (iwr -UseBasicParsing \"`$url`$cb`_=`$([DateTimeOffset]::Now.ToUnixTimeMilliseconds())\" -Headers @{'Cache-Control'='no-cache'}).Content" -ForegroundColor White
    
    Write-Host "`nOr use the helper script:" -ForegroundColor Cyan
    Write-Host ".\run-from-github.ps1" -ForegroundColor White
    
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
}
