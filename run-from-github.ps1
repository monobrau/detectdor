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
    
    # Download and execute
    $script = Invoke-WebRequest -Uri $GitHubUrl -UseBasicParsing
    Invoke-Expression $script.Content
} catch {
    Write-Host "Error executing script: $_" -ForegroundColor Red
    Write-Host "Make sure to update the GitHubUrl parameter with your repository details" -ForegroundColor Yellow
}
