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
    
    # Test download
    $script = Invoke-WebRequest -Uri $GitHubUrl -UseBasicParsing
    Write-Host "Successfully downloaded $($script.Content.Length) characters" -ForegroundColor Green
    
    Write-Host "`nTo execute the script, use:" -ForegroundColor Cyan
    Write-Host "iex (iwr -UseBasicParsing $GitHubUrl).Content" -ForegroundColor White
    
    Write-Host "`nOr copy-paste this one-liner:" -ForegroundColor Cyan
    Write-Host "iex (iwr -UseBasicParsing https://raw.githubusercontent.com/monobrau/detectdor/main/Invoke-ADDiscovery.ps1).Content" -ForegroundColor White
    
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
}
