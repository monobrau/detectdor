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
param(
    [Parameter(Mandatory=$false)]
    [switch]$OutputJson
)

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
    FSMORoles = @{}
    DomainInfo = @{}
    Trusts = @()
    ADSites = @()
    ExchangeServers = @()
    SQLServers = @()
    FileServers = @()
    CertificateAuthorities = @()
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
    # Check local registry first (fastest, no network)
    $quickCheckFound = $false
    
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Azure AD Connect"
        if (Test-Path $regPath) {
            $quickCheckFound = $true
        }
    } catch {}
    
    # If local check found nothing, do quick remote service checks
    if (-not $quickCheckFound) {
        foreach ($server in $serversToCheck) {
            # Skip local machine (already checked)
            if ($server -eq $env:COMPUTERNAME) { continue }
            
            # Quick check: ADSync service (fastest remote method)
            try {
                $adsyncService = Get-CimInstance -ComputerName $server -ClassName Win32_Service -Filter "Name='ADSync'" -ErrorAction SilentlyContinue
                if ($adsyncService) {
                    $quickCheckFound = $true
                    break
                }
            } catch {}
        }
    }
    
    # If quick check found nothing, skip detailed checks
    if (-not $quickCheckFound) {
        Write-Host "  [-] No Entra AD Connect installations found" -ForegroundColor Gray
        return
    }
    
    # Detailed checks only if quick check found something
    Write-Host "  [*] Entra AD Connect detected, performing detailed checks..." -ForegroundColor Gray
    foreach ($server in $serversToCheck) {
        Write-Host "    [*] Checking $server..." -ForegroundColor DarkGray
        
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

# Function to discover FSMO Roles
function Get-FSMORoles {
    Write-Host "`n[*] Discovering FSMO Roles..." -ForegroundColor Yellow
    
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $forest = $domain.Forest
        
        $Results.FSMORoles = @{
            SchemaMaster = $forest.SchemaRoleOwner.Name
            DomainNamingMaster = $forest.NamingRoleOwner.Name
            PDCEmulator = $domain.PdcRoleOwner.Name
            RIDMaster = $domain.RidRoleOwner.Name
            InfrastructureMaster = $domain.InfrastructureRoleOwner.Name
        }
        
        Write-Host "  [+] Schema Master: $($Results.FSMORoles.SchemaMaster)" -ForegroundColor Green
        Write-Host "  [+] Domain Naming Master: $($Results.FSMORoles.DomainNamingMaster)" -ForegroundColor Green
        Write-Host "  [+] PDC Emulator: $($Results.FSMORoles.PDCEmulator)" -ForegroundColor Green
        Write-Host "  [+] RID Master: $($Results.FSMORoles.RIDMaster)" -ForegroundColor Green
        Write-Host "  [+] Infrastructure Master: $($Results.FSMORoles.InfrastructureMaster)" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Error discovering FSMO roles: $_" -ForegroundColor Red
    }
}

# Function to discover Domain and Forest Information
function Get-DomainInfo {
    Write-Host "`n[*] Discovering Domain and Forest Information..." -ForegroundColor Yellow
    
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $forest = $domain.Forest
        
        $Results.DomainInfo = @{
            DomainName = $domain.Name
            DomainNetBIOSName = $domain.GetDirectoryEntry().Properties['name'].Value
            DomainSID = $domain.GetDirectoryEntry().Properties['objectSid'].Value
            DomainFunctionalLevel = $domain.DomainMode.ToString()
            ForestName = $forest.Name
            ForestFunctionalLevel = $forest.ForestMode.ToString()
            DomainControllersCount = $domain.DomainControllers.Count
            DomainsInForest = @()
            SitesInForest = @()
        }
        
        # Get all domains in forest
        foreach ($dom in $forest.Domains) {
            $Results.DomainInfo.DomainsInForest += $dom.Name
        }
        
        # Get all sites
        foreach ($site in $forest.Sites) {
            $Results.DomainInfo.SitesInForest += $site.Name
        }
        
        Write-Host "  [+] Domain: $($Results.DomainInfo.DomainName)" -ForegroundColor Green
        Write-Host "  [+] Domain Functional Level: $($Results.DomainInfo.DomainFunctionalLevel)" -ForegroundColor Green
        Write-Host "  [+] Forest: $($Results.DomainInfo.ForestName)" -ForegroundColor Green
        Write-Host "  [+] Forest Functional Level: $($Results.DomainInfo.ForestFunctionalLevel)" -ForegroundColor Green
        Write-Host "  [+] Domains in Forest: $($Results.DomainInfo.DomainsInForest.Count)" -ForegroundColor Green
        Write-Host "  [+] Sites in Forest: $($Results.DomainInfo.SitesInForest.Count)" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Error discovering domain info: $_" -ForegroundColor Red
    }
}

# Function to discover Trusts
function Get-Trusts {
    Write-Host "`n[*] Discovering Domain and Forest Trusts..." -ForegroundColor Yellow
    
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $forest = $domain.Forest
        
        # Domain trusts
        foreach ($trust in $domain.GetAllTrustRelationships()) {
            $trustInfo = @{
                TrustedDomain = $trust.TargetName
                TrustType = $trust.TrustType.ToString()
                TrustDirection = $trust.TrustDirection.ToString()
                SourceName = $trust.SourceName
            }
            $Results.Trusts += $trustInfo
            Write-Host "  [+] Trust: $($trustInfo.SourceName) -> $($trustInfo.TrustedDomain) ($($trustInfo.TrustType), $($trustInfo.TrustDirection))" -ForegroundColor Green
        }
        
        # Forest trusts
        foreach ($trust in $forest.GetAllTrustRelationships()) {
            $trustInfo = @{
                TrustedDomain = $trust.TargetName
                TrustType = "Forest"
                TrustDirection = $trust.TrustDirection.ToString()
                SourceName = $trust.SourceName
            }
            $Results.Trusts += $trustInfo
            Write-Host "  [+] Forest Trust: $($trustInfo.SourceName) -> $($trustInfo.TrustedDomain) ($($trustInfo.TrustDirection))" -ForegroundColor Green
        }
        
        if ($Results.Trusts.Count -eq 0) {
            Write-Host "  [-] No trusts found" -ForegroundColor Gray
        }
    } catch {
        Write-Host "  [!] Error discovering trusts: $_" -ForegroundColor Red
    }
}

# Function to discover AD Sites
function Get-ADSites {
    Write-Host "`n[*] Discovering AD Sites..." -ForegroundColor Yellow
    
    try {
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        
        foreach ($site in $forest.Sites) {
            $siteInfo = @{
                Name = $site.Name
                Subnets = @()
                DomainControllers = @()
            }
            
            # Get subnets
            foreach ($subnet in $site.Subnets) {
                $siteInfo.Subnets += $subnet.Name
            }
            
            # Get DCs in site
            foreach ($dc in $site.Servers) {
                $siteInfo.DomainControllers += $dc.Name
            }
            
            $Results.ADSites += $siteInfo
            Write-Host "  [+] Site: $($siteInfo.Name) (Subnets: $($siteInfo.Subnets.Count), DCs: $($siteInfo.DomainControllers.Count))" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [!] Error discovering AD sites: $_" -ForegroundColor Red
    }
}

# Function to discover Exchange Servers
function Get-ExchangeServers {
    Write-Host "`n[*] Discovering Exchange Servers..." -ForegroundColor Yellow
    
    try {
        $searcher = [adsisearcher]"(&(objectClass=msExchExchangeServer))"
        $searcher.SearchRoot = [adsi]"LDAP://$([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry().distinguishedName)"
        $exchangeServers = $searcher.FindAll()
        
        foreach ($exServer in $exchangeServers) {
            $exInfo = @{
                Name = $exServer.Properties['name'][0]
                Version = $null
                Roles = @()
            }
            
            # Try to get version
            if ($exServer.Properties['serialNumber']) {
                $exInfo.Version = $exServer.Properties['serialNumber'][0]
            }
            
            # Try to get server roles
            if ($exServer.Properties['msExchServerSite']) {
                $exInfo.Roles += "Mailbox"
            }
            
            $Results.ExchangeServers += $exInfo
            Write-Host "  [+] Exchange Server: $($exInfo.Name)" -ForegroundColor Green
        }
        
        if ($Results.ExchangeServers.Count -eq 0) {
            Write-Host "  [-] No Exchange servers found" -ForegroundColor Gray
        }
    } catch {
        Write-Host "  [-] No Exchange servers found (or Exchange schema not present)" -ForegroundColor Gray
    }
}

# Function to discover SQL Servers
function Get-SQLServers {
    Write-Host "`n[*] Discovering SQL Servers..." -ForegroundColor Yellow
    
    try {
        # Method 1: Check for SQL Server service on discovered servers
        $serversToCheck = @()
        foreach ($dc in $Results.DomainControllers) {
            $serversToCheck += $dc.Name
        }
        $serversToCheck += $env:COMPUTERNAME
        
        foreach ($server in $serversToCheck) {
            try {
                # Check for SQL Server services
                $sqlServices = Get-CimInstance -ComputerName $server -ClassName Win32_Service -Filter "Name LIKE 'MSSQL%' OR Name LIKE 'SQLServer%' OR DisplayName LIKE '%SQL Server%'" -ErrorAction SilentlyContinue
                if ($sqlServices) {
                    foreach ($svc in $sqlServices) {
                        $sqlInfo = @{
                            Server = $server
                            ServiceName = $svc.Name
                            DisplayName = $svc.DisplayName
                            Status = $svc.State
                            InstanceName = $null
                        }
                        
                        # Extract instance name from service name
                        if ($svc.Name -match 'MSSQL\$(\w+)') {
                            $sqlInfo.InstanceName = $matches[1]
                        } elseif ($svc.Name -eq 'MSSQLSERVER') {
                            $sqlInfo.InstanceName = 'Default'
                        }
                        
                        $Results.SQLServers += $sqlInfo
                        Write-Host "  [+] SQL Server: $server ($($sqlInfo.InstanceName))" -ForegroundColor Green
                    }
                }
            } catch {}
        }
        
        if ($Results.SQLServers.Count -eq 0) {
            Write-Host "  [-] No SQL servers found" -ForegroundColor Gray
        }
    } catch {
        Write-Host "  [!] Error discovering SQL servers: $_" -ForegroundColor Red
    }
}

# Function to discover File Servers (DFS)
function Get-FileServers {
    Write-Host "`n[*] Discovering File Servers (DFS)..." -ForegroundColor Yellow
    
    try {
        # Check for DFS namespaces
        $searcher = [adsisearcher]"(&(objectClass=msDFS-Namespace))"
        $searcher.SearchRoot = [adsi]"LDAP://CN=System,$([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry().distinguishedName)"
        $dfsNamespaces = $searcher.FindAll()
        
        foreach ($namespace in $dfsNamespaces) {
            $dfsInfo = @{
                Name = $namespace.Properties['name'][0]
                Type = "DFS Namespace"
            }
            $Results.FileServers += $dfsInfo
            Write-Host "  [+] DFS Namespace: $($dfsInfo.Name)" -ForegroundColor Green
        }
        
        # Check for file server role on discovered servers
        foreach ($dc in $Results.DomainControllers) {
            try {
                $fileServerRole = Get-CimInstance -ComputerName $dc.Name -ClassName Win32_SystemServices -Filter "Name='LanmanServer'" -ErrorAction SilentlyContinue
                if ($fileServerRole) {
                    $fsInfo = @{
                        Name = $dc.Name
                        Type = "File Server"
                        Roles = "Domain Controller, File Server"
                    }
                    $Results.FileServers += $fsInfo
                    Write-Host "  [+] File Server: $($fsInfo.Name)" -ForegroundColor Green
                }
            } catch {}
        }
        
        if ($Results.FileServers.Count -eq 0) {
            Write-Host "  [-] No file servers or DFS namespaces found" -ForegroundColor Gray
        }
    } catch {
        Write-Host "  [-] No DFS namespaces found" -ForegroundColor Gray
    }
}

# Function to discover Certificate Authorities
function Get-CertificateAuthorities {
    Write-Host "`n[*] Discovering Certificate Authorities..." -ForegroundColor Yellow
    
    try {
        $searcher = [adsisearcher]"(&(objectClass=pKIEnrollmentService))"
        $searcher.SearchRoot = [adsi]"LDAP://CN=Configuration,$([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry().distinguishedName)"
        $caServers = $searcher.FindAll()
        
        foreach ($ca in $caServers) {
            $caInfo = @{
                Name = $ca.Properties['dNSHostName'][0]
                CommonName = $ca.Properties['cn'][0]
                CertificateTemplates = @()
            }
            
            # Get certificate templates
            if ($ca.Properties['certificateTemplates']) {
                $caInfo.CertificateTemplates = $ca.Properties['certificateTemplates']
            }
            
            $Results.CertificateAuthorities += $caInfo
            Write-Host "  [+] CA: $($caInfo.Name) ($($caInfo.CommonName))" -ForegroundColor Green
        }
        
        if ($Results.CertificateAuthorities.Count -eq 0) {
            Write-Host "  [-] No Certificate Authorities found" -ForegroundColor Gray
        }
    } catch {
        Write-Host "  [-] No Certificate Authorities found (or AD CS not present)" -ForegroundColor Gray
    }
}

# Main execution
try {
    Get-DomainControllers
    Get-DHCPServers
    Get-DNSServers
    Get-EntraADConnect
    Get-FSMORoles
    Get-DomainInfo
    Get-Trusts
    Get-ADSites
    Get-ExchangeServers
    Get-SQLServers
    Get-FileServers
    Get-CertificateAuthorities
    
    # Output summary
    Write-Host "`n=== Discovery Summary ===" -ForegroundColor Cyan
    Write-Host "Domain Controllers: $($Results.DomainControllers.Count)" -ForegroundColor White
    Write-Host "DHCP Servers: $($Results.DHCPServers.Count)" -ForegroundColor White
    Write-Host "DNS Servers: $($Results.DNSServers.Count)" -ForegroundColor White
    Write-Host "Entra AD Connect Installations: $($Results.EntraADConnect.Count)" -ForegroundColor White
    Write-Host "AD Sites: $($Results.ADSites.Count)" -ForegroundColor White
    Write-Host "Domain Trusts: $($Results.Trusts.Count)" -ForegroundColor White
    Write-Host "Exchange Servers: $($Results.ExchangeServers.Count)" -ForegroundColor White
    Write-Host "SQL Servers: $($Results.SQLServers.Count)" -ForegroundColor White
    Write-Host "File Servers/DFS: $($Results.FileServers.Count)" -ForegroundColor White
    Write-Host "Certificate Authorities: $($Results.CertificateAuthorities.Count)" -ForegroundColor White
    
    # Output detailed results as JSON only if requested
    if ($OutputJson) {
        Write-Host "`n=== Detailed Results (JSON) ===" -ForegroundColor Cyan
        $Results | ConvertTo-Json -Depth 20
    }
    
    # Return results object
    return $Results
    
} catch {
    Write-Host "`n[!] Fatal Error: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    return $null
}
