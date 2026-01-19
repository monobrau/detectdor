<#
.SYNOPSIS
    Active Directory Discovery Script - Runs entirely in memory
.DESCRIPTION
    Discovers all AD Domain Controllers, DHCP servers, DNS servers, and identifies Entra AD Connect installations
    Designed to be downloaded and executed directly from GitHub
    
    GitHub Raw URL Format:
    https://raw.githubusercontent.com/USERNAME/REPO/BRANCH/Invoke-ADDiscovery.ps1
    
    Execute via:
    iex (iwr -UseBasicParsing https://raw.githubusercontent.com/USERNAME/REPO/BRANCH/Invoke-ADDiscovery.ps1).Content
    
.NOTES
    Author: AD Discovery Tool
    Version: 1.0
#>

[CmdletBinding()]
param()

# Ensure TLS 1.2 for GitHub connections
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Suppress errors for cleaner output
$ErrorActionPreference = 'SilentlyContinue'

# Initialize results hashtable
$Results = @{
    DomainControllers = @()
    DHCPServers = @()
    DNSServers = @()
    EntraADConnect = @()
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

Write-Host "`n=== Active Directory Discovery Script ===" -ForegroundColor Cyan
Write-Host "Started: $($Results.Timestamp)`n" -ForegroundColor Gray

# Function to discover Domain Controllers
function Get-DomainControllers {
    Write-Host "[*] Discovering Domain Controllers..." -ForegroundColor Yellow
    
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $dcs = $domain.FindAllDomainControllers()
        
        foreach ($dc in $dcs) {
            $dcInfo = @{
                Name = $dc.Name
                IPAddress = $dc.IPAddress
                SiteName = $dc.SiteName
                Forest = $dc.Forest
                Domain = $dc.Domain
                OSVersion = $null
                Roles = @()
            }
            
            # Try to get OS version via WMI/CIM
            try {
                $os = Get-CimInstance -ComputerName $dc.Name -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
                if ($os) {
                    $dcInfo.OSVersion = $os.Caption
                }
            } catch {}
            
            # Check for AD roles
            try {
                $roles = Get-CimInstance -ComputerName $dc.Name -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
                if ($roles) {
                    $dcInfo.Roles = $roles.Roles
                }
            } catch {}
            
            $Results.DomainControllers += $dcInfo
            Write-Host "  [+] Found DC: $($dc.Name) ($($dc.IPAddress))" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [!] Error discovering DCs: $_" -ForegroundColor Red
    }
}

# Function to discover DHCP servers
function Get-DHCPServers {
    Write-Host "`n[*] Discovering DHCP Servers..." -ForegroundColor Yellow
    
    try {
        # Method 1: Query AD for DHCP servers
        $searcher = [adsisearcher]"(&(objectClass=dhcpClass)(cn=dhcpRoot))"
        $searcher.SearchRoot = [adsi]"LDAP://$([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry().distinguishedName)"
        $dhcpServers = $searcher.FindAll()
        
        foreach ($dhcpServer in $dhcpServers) {
            $dhcpInfo = @{
                Name = $dhcpServer.Properties['cn'][0]
                DN = $dhcpServer.Path
            }
            $Results.DHCPServers += $dhcpInfo
            Write-Host "  [+] Found DHCP Server: $($dhcpInfo.Name)" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [!] Error querying AD for DHCP: $_" -ForegroundColor Red
    }
    
    # Method 2: Check for DHCP service on known servers
    Write-Host "  [*] Checking Domain Controllers for DHCP service..." -ForegroundColor Gray
    foreach ($dc in $Results.DomainControllers) {
        try {
            $dhcpService = Get-CimInstance -ComputerName $dc.Name -ClassName Win32_Service -Filter "Name='DHCPServer'" -ErrorAction SilentlyContinue
            if ($dhcpService) {
                $dhcpInfo = @{
                    Name = $dc.Name
                    Status = $dhcpService.State
                    StartMode = $dhcpService.StartMode
                }
                if ($Results.DHCPServers | Where-Object { $_.Name -eq $dc.Name }) {
                    # Already in list, skip
                } else {
                    $Results.DHCPServers += $dhcpInfo
                    Write-Host "  [+] Found DHCP on: $($dc.Name) (Status: $($dhcpService.State))" -ForegroundColor Green
                }
            }
        } catch {}
    }
}

# Function to discover DNS servers
function Get-DNSServers {
    Write-Host "`n[*] Discovering DNS Servers..." -ForegroundColor Yellow
    
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        
        # Get DNS servers from domain
        foreach ($dc in $domain.DomainControllers) {
            $dnsInfo = @{
                Name = $dc.Name
                IPAddress = $dc.IPAddress
                SiteName = $dc.SiteName
            }
            $Results.DNSServers += $dnsInfo
            Write-Host "  [+] Found DNS Server: $($dc.Name) ($($dc.IPAddress))" -ForegroundColor Green
        }
        
        # Also check for DNS service on all DCs
        Write-Host "  [*] Verifying DNS service on Domain Controllers..." -ForegroundColor Gray
        foreach ($dc in $Results.DomainControllers) {
            try {
                $dnsService = Get-CimInstance -ComputerName $dc.Name -ClassName Win32_Service -Filter "Name='DNS'" -ErrorAction SilentlyContinue
                if ($dnsService) {
                    $dnsInfo = @{
                        Name = $dc.Name
                        Status = $dnsService.State
                        StartMode = $dnsService.StartMode
                    }
                    Write-Host "    [+] DNS service confirmed on: $($dc.Name)" -ForegroundColor Gray
                }
            } catch {}
        }
    } catch {
        Write-Host "  [!] Error discovering DNS servers: $_" -ForegroundColor Red
    }
}

# Function to discover Entra AD Connect (Azure AD Connect)
function Get-EntraADConnect {
    Write-Host "`n[*] Discovering Entra AD Connect installations..." -ForegroundColor Yellow
    
    $serversToCheck = @()
    
    # Add all discovered servers
    foreach ($dc in $Results.DomainControllers) {
        $serversToCheck += $dc.Name
    }
    
    # Also check current machine
    $serversToCheck += $env:COMPUTERNAME
    
    # Quick check first - if nothing found, skip detailed checks
    $quickCheckFound = $false
    
    foreach ($server in $serversToCheck) {
        # Quick check: ADSync service (fastest method)
        try {
            $adsyncService = Get-CimInstance -ComputerName $server -ClassName Win32_Service -Filter "Name='ADSync'" -ErrorAction SilentlyContinue
            if ($adsyncService) {
                $quickCheckFound = $true
                break
            }
        } catch {}
        
        # Quick check: Registry (local only, fast)
        try {
            if ($server -eq $env:COMPUTERNAME) {
                $regPath = "HKLM:\SOFTWARE\Microsoft\Azure AD Connect"
                if (Test-Path $regPath) {
                    $quickCheckFound = $true
                    break
                }
            }
        } catch {}
    }
    
    # If quick check found nothing, skip detailed checks
    if (-not $quickCheckFound) {
        Write-Host "  [-] No Entra AD Connect installations found (skipped detailed checks)" -ForegroundColor Gray
        return
    }
    
    # Detailed checks only if quick check found something
    foreach ($server in $serversToCheck) {
        $entraInfo = @{
            Server = $server
            Found = $false
            Methods = @()
            Details = @{}
        }
        
        # Method 1: Check Registry for Azure AD Connect
        try {
            if ($server -eq $env:COMPUTERNAME) {
                $regPath = "HKLM:\SOFTWARE\Microsoft\Azure AD Connect"
                if (Test-Path $regPath) {
                    $entraInfo.Found = $true
                    $entraInfo.Methods += "Registry"
                    $regValues = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                    if ($regValues) {
                        $entraInfo.Details.Registry = $regValues | ConvertTo-Json -Compress
                    }
                }
            } else {
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $server)
                $adConnectKey = $reg.OpenSubKey('SOFTWARE\Microsoft\Azure AD Connect')
                if ($adConnectKey) {
                    $entraInfo.Found = $true
                    $entraInfo.Methods += "Registry"
                    $entraInfo.Details.Registry = "Present"
                    $adConnectKey.Close()
                }
                $reg.Close()
            }
        } catch {}
        
        # Method 2: Check for ADSync service
        try {
            $adsyncService = Get-CimInstance -ComputerName $server -ClassName Win32_Service -Filter "Name='ADSync'" -ErrorAction SilentlyContinue
            if ($adsyncService) {
                $entraInfo.Found = $true
                $entraInfo.Methods += "Service"
                $entraInfo.Details.Service = @{
                    Status = $adsyncService.State
                    StartMode = $adsyncService.StartMode
                    DisplayName = $adsyncService.DisplayName
                    PathName = $adsyncService.PathName
                }
            }
        } catch {}
        
        # Method 3: Check for ADSync process
        try {
            $adsyncProcess = Get-CimInstance -ComputerName $server -ClassName Win32_Process -Filter "Name='ADSync.exe' OR Name='miiserver.exe'" -ErrorAction SilentlyContinue
            if ($adsyncProcess) {
                $entraInfo.Found = $true
                $entraInfo.Methods += "Process"
                $entraInfo.Details.Process = @{
                    Name = $adsyncProcess.Name
                    ProcessId = $adsyncProcess.ProcessId
                    CommandLine = $adsyncProcess.CommandLine
                }
            }
        } catch {}
        
        # Method 4: Check installed programs
        try {
            $programs = Get-CimInstance -ComputerName $server -ClassName Win32_Product -Filter "Name LIKE '%Azure AD Connect%' OR Name LIKE '%Entra%'" -ErrorAction SilentlyContinue
            if ($programs) {
                $entraInfo.Found = $true
                $entraInfo.Methods += "InstalledProgram"
                $entraInfo.Details.InstalledPrograms = @()
                foreach ($prog in $programs) {
                    $entraInfo.Details.InstalledPrograms += @{
                        Name = $prog.Name
                        Version = $prog.Version
                        InstallDate = $prog.InstallDate
                    }
                }
            }
        } catch {}
        
        # Method 5: Check for ADSync installation directory (common locations)
        try {
            $commonPaths = @(
                "C:\Program Files\Microsoft Azure AD Sync",
                "C:\Program Files\Microsoft Azure Active Directory Connect",
                "C:\Program Files\Microsoft Entra Connect"
            )
            
            foreach ($path in $commonPaths) {
                if ($server -eq $env:COMPUTERNAME) {
                    if (Test-Path $path) {
                        $entraInfo.Found = $true
                        $entraInfo.Methods += "Directory"
                        $entraInfo.Details.InstallPath = $path
                        break
                    }
                } else {
                    $testPath = "\\$server\C$\Program Files\Microsoft Azure AD Sync"
                    if (Test-Path $testPath) {
                        $entraInfo.Found = $true
                        $entraInfo.Methods += "Directory"
                        $entraInfo.Details.InstallPath = $path
                        break
                    }
                }
            }
        } catch {}
        
        if ($entraInfo.Found) {
            $Results.EntraADConnect += $entraInfo
            Write-Host "  [+] Entra AD Connect FOUND on: $server (Methods: $($entraInfo.Methods -join ', '))" -ForegroundColor Green
        }
    }
    
    if ($Results.EntraADConnect.Count -eq 0) {
        Write-Host "  [-] No Entra AD Connect installations found" -ForegroundColor Yellow
    }
}

# Main execution
try {
    Get-DomainControllers
    Get-DHCPServers
    Get-DNSServers
    Get-EntraADConnect
    
    # Output summary
    Write-Host "`n=== Discovery Summary ===" -ForegroundColor Cyan
    Write-Host "Domain Controllers: $($Results.DomainControllers.Count)" -ForegroundColor White
    Write-Host "DHCP Servers: $($Results.DHCPServers.Count)" -ForegroundColor White
    Write-Host "DNS Servers: $($Results.DNSServers.Count)" -ForegroundColor White
    Write-Host "Entra AD Connect Installations: $($Results.EntraADConnect.Count)" -ForegroundColor White
    
    # Output detailed results as JSON
    Write-Host "`n=== Detailed Results (JSON) ===" -ForegroundColor Cyan
    $Results | ConvertTo-Json -Depth 10
    
    # Return results object
    return $Results
    
} catch {
    Write-Host "`n[!] Fatal Error: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    return $null
}
