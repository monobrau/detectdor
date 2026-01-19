<#
.SYNOPSIS
    Helper script to execute Invoke-ADDiscovery.ps1 from GitHub
.DESCRIPTION
    Simple wrapper to execute the AD Discovery script from GitHub
    Update the $GitHubUrl variable with your repository details
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$GitHubUrl = "https://raw.githubusercontent.com/USERNAME/REPO/BRANCH/Invoke-ADDiscovery.ps1"
)

Write-Host "Downloading and executing AD Discovery script from GitHub..." -ForegroundColor Cyan
Write-Host "URL: $GitHubUrl`n" -ForegroundColor Gray

try {
    # Ensure TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    # Add cache-busting parameter to force fresh download
    $separator = if ($GitHubUrl -match '\?') { '&' } else { '?' }
    $cacheBustUrl = "$GitHubUrl$separator`_=$([DateTimeOffset]::Now.ToUnixTimeMilliseconds())"
    
    # Download with cache-busting headers
    $headers = @{
        'Cache-Control' = 'no-cache, no-store, must-revalidate'
        'Pragma' = 'no-cache'
        'Expires' = '0'
    }
    
    Write-Host "Downloading fresh copy (cache-busting enabled)..." -ForegroundColor DarkGray
    $script = Invoke-WebRequest -Uri $cacheBustUrl -Headers $headers -UseBasicParsing
    Invoke-Expression $script.Content
} catch {
    Write-Host "Error executing script: $_" -ForegroundColor Red
    Write-Host "Make sure to update the GitHubUrl parameter with your repository details" -ForegroundColor Yellow
}
