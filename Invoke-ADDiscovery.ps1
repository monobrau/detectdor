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
    [switch]$OutputJson,
    
    [Parameter(Mandatory=$false)]
    [switch]$UseNmap
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
    Virtualization = @()
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

# Function to discover Virtualization Platforms
function Get-VirtualizationPlatforms {
    param(
        [switch]$UseNmap
    )
    
    Write-Host "`n[*] Discovering Virtualization Platforms..." -ForegroundColor Yellow
    
    # Helper function to execute CIM queries with timeout (optimized for speed)
    function Invoke-CimQueryWithTimeout {
        param(
            [string]$ComputerName,
            [string]$ClassName,
            [string]$Filter = $null,
            [int]$TimeoutSeconds = 2
        )
        
        # Skip localhost - use direct calls
        if ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq 'localhost' -or $ComputerName -eq '.') {
            try {
                if ($Filter) {
                    return Get-CimInstance -ClassName $ClassName -Filter $Filter -ErrorAction SilentlyContinue
                } else {
                    return Get-CimInstance -ClassName $ClassName -ErrorAction SilentlyContinue
                }
            } catch {
                return $null
            }
        }
        
        # For remote hosts, use job with timeout to prevent hanging
        $queryJob = Start-Job -ScriptBlock {
            param($compName, $class, $filt, $timeout)
            try {
                $sessOpt = New-CimSessionOption -OperationTimeoutSec $timeout -TimeoutSec $timeout
                $sess = New-CimSession -ComputerName $compName -SessionOption $sessOpt -ErrorAction SilentlyContinue
                if ($sess) {
                    if ($filt) {
                        $res = Get-CimInstance -CimSession $sess -ClassName $class -Filter $filt -ErrorAction SilentlyContinue
                    } else {
                        $res = Get-CimInstance -CimSession $sess -ClassName $class -ErrorAction SilentlyContinue
                    }
                    Remove-CimSession -CimSession $sess -ErrorAction SilentlyContinue
                    return $res
                }
            } catch {
                return $null
            }
            return $null
        } -ArgumentList $ComputerName, $ClassName, $Filter, $TimeoutSeconds
        
        try {
            $result = Wait-Job -Job $queryJob -Timeout ($TimeoutSeconds + 1) | Receive-Job
            return $result
        } catch {
            return $null
        } finally {
            Stop-Job -Job $queryJob -ErrorAction SilentlyContinue
            Remove-Job -Job $queryJob -ErrorAction SilentlyContinue
        }
    }
    
    $serversToCheck = @()
    
    # Add all discovered servers
    foreach ($dc in $Results.DomainControllers) {
        $serversToCheck += $dc.Name
    }
    
    # Also check current machine
    $serversToCheck += $env:COMPUTERNAME
    
    # Search AD for potential hypervisor hosts
    Write-Host "  [*] Searching Active Directory for hypervisor hosts..." -ForegroundColor Gray
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $searcher = [adsisearcher]"(&(objectClass=computer)(|(name=*esx*)(name=*vcenter*)(name=*vmware*)(name=*hyperv*)(name=*hvhost*)(name=*xen*)(name=*citrix*)))"
        $searcher.SearchRoot = [adsi]"LDAP://$($domain.GetDirectoryEntry().distinguishedName)"
        $searcher.PageSize = 1000
        $hypervisorHosts = $searcher.FindAll()
        
        foreach ($hostObj in $hypervisorHosts) {
            $hostName = $hostObj.Properties['name'][0]
            if ($hostName -and $hostName -notin $serversToCheck) {
                $serversToCheck += $hostName
                Write-Host "    [+] Found potential hypervisor host: $hostName" -ForegroundColor DarkGray
            }
        }
    } catch {
        Write-Host "    [-] Could not query AD for hypervisor hosts: $_" -ForegroundColor DarkGray
    }
    
    # Also check for Hyper-V hosts via AD (Windows Server with Hyper-V role)
    try {
        $searcher = [adsisearcher]"(&(objectClass=computer)(operatingSystem=Windows Server*))"
        $searcher.SearchRoot = [adsi]"LDAP://$($domain.GetDirectoryEntry().distinguishedName)"
        $searcher.PageSize = 1000
        $windowsServers = $searcher.FindAll()
        
        # Sample a subset to check for Hyper-V (check first 50 to avoid too many checks)
        $sampleSize = [Math]::Min(50, $windowsServers.Count)
        $sampledServers = $windowsServers | Select-Object -First $sampleSize
        
        foreach ($serverObj in $sampledServers) {
            $serverName = $serverObj.Properties['dNSHostName'][0]
            if (-not $serverName) {
                $serverName = $serverObj.Properties['name'][0]
            }
            if ($serverName -and $serverName -notin $serversToCheck) {
                # Quick check for Hyper-V service with fast timeout
                try {
                    $hypervService = Invoke-CimQueryWithTimeout -ComputerName $serverName -ClassName Win32_Service -Filter "Name='vmms'" -TimeoutSeconds 1
                    if ($hypervService) {
                        $serversToCheck += $serverName
                        Write-Host "    [+] Found Hyper-V host: $serverName" -ForegroundColor DarkGray
                    }
                } catch {}
            }
        }
    } catch {}
    
    # Scan non-AD IPs from discovered subnets
    Write-Host "  [*] Scanning subnets for non-AD virtualization hosts..." -ForegroundColor Gray
    $subnetIPs = @()
    
    # Extract IP ranges from AD Site subnets
    foreach ($site in $Results.ADSites) {
        foreach ($subnet in $site.Subnets) {
            # Subnet format is typically "192.168.1.0/24" (CIDR) or "192.168.1.0/255.255.255.0" (subnet mask)
            $prefixLength = $null
            $subnetIP = $null
            
            # Try CIDR notation first (e.g., "192.168.1.0/24")
            if ($subnet -match '(\d+\.\d+\.\d+\.\d+)/(\d+)') {
                $subnetIP = $matches[1]
                $prefixLength = [int]$matches[2]
            }
            # Try subnet mask format (e.g., "192.168.1.0/255.255.255.0")
            elseif ($subnet -match '(\d+\.\d+\.\d+\.\d+)/(\d+\.\d+\.\d+\.\d+)') {
                $subnetIP = $matches[1]
                $subnetMask = $matches[2]
                # Convert subnet mask to prefix length
                $prefixLength = Convert-SubnetMaskToPrefixLength -SubnetMask $subnetMask
            }
            
            if ($subnetIP -and $prefixLength) {
                # Only scan /24 or smaller subnets (avoid scanning huge ranges)
                if ($prefixLength -ge 24 -and $prefixLength -le 32) {
                    try {
                        # Generate IPs to scan (sample first 10 and last 10 IPs, plus common hypervisor IPs)
                        $ipsToScan = Get-SubnetIPsToScan -Subnet $subnetIP -PrefixLength $prefixLength
                        $subnetIPs += $ipsToScan
                        Write-Host "    [*] Found subnet $subnet, will scan $($ipsToScan.Count) IPs" -ForegroundColor DarkGray
                    } catch {
                        Write-Host "    [-] Error processing subnet $subnet : $_" -ForegroundColor DarkGray
                    }
                }
            }
        }
    }
    
    # Also scan common hypervisor management IP ranges if no subnets found
    if ($subnetIPs.Count -eq 0) {
        Write-Host "    [*] No AD subnets found, scanning common management IP ranges..." -ForegroundColor DarkGray
        # Common management ranges: .1, .10, .100, .200, .254
        $localSubnet = Get-LocalSubnet
        if ($localSubnet) {
            $commonIPs = @(
                "$localSubnet.1",
                "$localSubnet.10",
                "$localSubnet.100",
                "$localSubnet.200",
                "$localSubnet.254"
            )
            $subnetIPs += $commonIPs
        }
    }
    
    # Scan discovered IPs for virtualization
    foreach ($ip in $subnetIPs) {
        if ($ip -notin $serversToCheck) {
            # Quick ping check
            try {
                $pingJob = Start-Job -ScriptBlock {
                    param($ipAddr)
                    Test-Connection -ComputerName $ipAddr -Count 1 -Quiet -ErrorAction SilentlyContinue
                } -ArgumentList $ip
                
                $pingResult = Wait-Job -Job $pingJob -Timeout 1 | Receive-Job
                Stop-Job -Job $pingJob -ErrorAction SilentlyContinue
                Remove-Job -Job $pingJob -ErrorAction SilentlyContinue
                
                if ($pingResult) {
                    # Host is alive, check for virtualization
                    $serversToCheck += $ip
                    Write-Host "    [+] Found alive host: $ip" -ForegroundColor DarkGray
                }
            } catch {}
        }
    }
    
    foreach ($server in $serversToCheck) {
        Write-Host "  [*] Checking $server for virtualization..." -ForegroundColor DarkGray
        
        # Quick connectivity check - skip if host is unreachable (very fast timeout)
        if ($server -ne $env:COMPUTERNAME) {
            try {
                # Use async ping with very short timeout
                $pingJob = Start-Job -ScriptBlock {
                    param($hostName)
                    Test-Connection -ComputerName $hostName -Count 1 -Quiet -ErrorAction SilentlyContinue
                } -ArgumentList $server
                
                $pingResult = Wait-Job -Job $pingJob -Timeout 1 | Receive-Job
                Stop-Job -Job $pingJob -ErrorAction SilentlyContinue
                Remove-Job -Job $pingJob -ErrorAction SilentlyContinue
                
                if (-not $pingResult) {
                    Write-Host "    [-] $server is unreachable, skipping..." -ForegroundColor DarkGray
                    continue
                }
            } catch {
                Write-Host "    [-] $server is unreachable, skipping..." -ForegroundColor DarkGray
                continue
            }
        }
        
        $vmInfo = @{
            Server = $server
            IsVirtual = $false
            Platform = @()
            Details = @{}
        }
        
        # Method 1: Check BIOS/System Manufacturer (most reliable) - with fast timeout
        # This is the fastest check, if it fails quickly, skip other checks
        $quickCheckPassed = $false
        try {
            $computerSystem = Invoke-CimQueryWithTimeout -ComputerName $server -ClassName Win32_ComputerSystem -TimeoutSeconds 2
            if ($computerSystem) {
                $quickCheckPassed = $true
                $manufacturer = $computerSystem.Manufacturer
                $model = $computerSystem.Model
                
                # VMware detection
                if ($manufacturer -match 'VMware|VMware, Inc.' -or $model -match 'VMware') {
                    $vmInfo.IsVirtual = $true
                    $vmInfo.Platform += "VMware"
                    $vmInfo.Details.Manufacturer = $manufacturer
                    $vmInfo.Details.Model = $model
                }
                
                # Microsoft Hyper-V detection
                if ($manufacturer -match 'Microsoft Corporation' -and $model -match 'Virtual Machine') {
                    $vmInfo.IsVirtual = $true
                    $vmInfo.Platform += "Hyper-V"
                    $vmInfo.Details.Manufacturer = $manufacturer
                    $vmInfo.Details.Model = $model
                }
                
                # Citrix XenServer detection
                if ($manufacturer -match 'Xen' -or $model -match 'Xen') {
                    $vmInfo.IsVirtual = $true
                    $vmInfo.Platform += "Citrix XenServer"
                    $vmInfo.Details.Manufacturer = $manufacturer
                    $vmInfo.Details.Model = $model
                }
                
                # VirtualBox detection
                if ($manufacturer -match 'innotek|Oracle' -or $model -match 'VirtualBox') {
                    $vmInfo.IsVirtual = $true
                    $vmInfo.Platform += "VirtualBox"
                    $vmInfo.Details.Manufacturer = $manufacturer
                    $vmInfo.Details.Model = $model
                }
                
                # QEMU/KVM detection
                if ($manufacturer -match 'QEMU' -or $model -match 'QEMU|KVM') {
                    $vmInfo.IsVirtual = $true
                    $vmInfo.Platform += "QEMU/KVM"
                    $vmInfo.Details.Manufacturer = $manufacturer
                    $vmInfo.Details.Model = $model
                }
                
                # AWS EC2 detection
                if ($model -match 'Amazon EC2|ec2') {
                    $vmInfo.IsVirtual = $true
                    $vmInfo.Platform += "AWS EC2"
                    $vmInfo.Details.Manufacturer = $manufacturer
                    $vmInfo.Details.Model = $model
                }
                
                # Azure VM detection
                if ($model -match 'Virtual Machine' -and $manufacturer -match 'Microsoft') {
                    # Could be Hyper-V or Azure, check further
                    if (-not ($vmInfo.Platform -contains "Hyper-V")) {
                        $vmInfo.Platform += "Azure VM"
                    }
                }
            }
        } catch {}
        
        # If quick check failed (host unreachable), skip remaining checks
        if ($server -ne $env:COMPUTERNAME -and -not $quickCheckPassed) {
            Write-Host "    [-] $server not accessible via CIM, skipping detailed checks..." -ForegroundColor DarkGray
            continue
        }
        
        # Method 2: Check for virtualization services - with fast timeout
        try {
            $services = Invoke-CimQueryWithTimeout -ComputerName $server -ClassName Win32_Service -TimeoutSeconds 2
            if ($services) {
                # VMware Tools
                $vmwareServices = $services | Where-Object { $_.Name -match 'VMTools|vmware|VMware' -or $_.DisplayName -match 'VMware' }
                if ($vmwareServices) {
                    $vmInfo.IsVirtual = $true
                    if (-not ($vmInfo.Platform -contains "VMware")) {
                        $vmInfo.Platform += "VMware"
                    }
                    $vmInfo.Details.VMwareServices = @()
                    foreach ($svc in $vmwareServices) {
                        $vmInfo.Details.VMwareServices += @{
                            Name = $svc.Name
                            DisplayName = $svc.DisplayName
                            Status = $svc.State
                        }
                    }
                }
                
                # Hyper-V Integration Services
                $hypervServices = $services | Where-Object { $_.Name -match 'vmickvpexchange|vmicheartbeat|vmicshutdown|vmictimesync|vmicvss' }
                if ($hypervServices) {
                    $vmInfo.IsVirtual = $true
                    if (-not ($vmInfo.Platform -contains "Hyper-V")) {
                        $vmInfo.Platform += "Hyper-V"
                    }
                    $vmInfo.Details.HyperVServices = @()
                    foreach ($svc in $hypervServices) {
                        $vmInfo.Details.HyperVServices += @{
                            Name = $svc.Name
                            DisplayName = $svc.DisplayName
                            Status = $svc.State
                        }
                    }
                }
                
                # VirtualBox Guest Additions
                $vboxServices = $services | Where-Object { $_.Name -match 'VBoxService|VBoxGuest' }
                if ($vboxServices) {
                    $vmInfo.IsVirtual = $true
                    if (-not ($vmInfo.Platform -contains "VirtualBox")) {
                        $vmInfo.Platform += "VirtualBox"
                    }
                    $vmInfo.Details.VirtualBoxServices = @()
                    foreach ($svc in $vboxServices) {
                        $vmInfo.Details.VirtualBoxServices += @{
                            Name = $svc.Name
                            DisplayName = $svc.DisplayName
                            Status = $svc.State
                        }
                    }
                }
                
                # Citrix XenServer Tools
                $xenServices = $services | Where-Object { $_.Name -match 'xenservice|Xen' }
                if ($xenServices) {
                    $vmInfo.IsVirtual = $true
                    if (-not ($vmInfo.Platform -contains "Citrix XenServer")) {
                        $vmInfo.Platform += "Citrix XenServer"
                    }
                }
            }
        } catch {}
        
        # Method 3: Check network adapters for virtualization signatures - with fast timeout
        try {
            $adapters = Invoke-CimQueryWithTimeout -ComputerName $server -ClassName Win32_NetworkAdapter -TimeoutSeconds 2
            if ($adapters) {
                # VMware network adapters
                $vmwareAdapters = $adapters | Where-Object { $_.Name -match 'VMware|vmxnet' }
                if ($vmwareAdapters) {
                    $vmInfo.IsVirtual = $true
                    if (-not ($vmInfo.Platform -contains "VMware")) {
                        $vmInfo.Platform += "VMware"
                    }
                }
                
                # Hyper-V network adapters
                $hypervAdapters = $adapters | Where-Object { $_.Name -match 'Hyper-V|vEthernet' }
                if ($hypervAdapters) {
                    $vmInfo.IsVirtual = $true
                    if (-not ($vmInfo.Platform -contains "Hyper-V")) {
                        $vmInfo.Platform += "Hyper-V"
                    }
                }
                
                # VirtualBox network adapters
                $vboxAdapters = $adapters | Where-Object { $_.Name -match 'VirtualBox' }
                if ($vboxAdapters) {
                    $vmInfo.IsVirtual = $true
                    if (-not ($vmInfo.Platform -contains "VirtualBox")) {
                        $vmInfo.Platform += "VirtualBox"
                    }
                }
            }
        } catch {}
        
        # Method 4: Check registry for virtualization indicators
        try {
            if ($server -eq $env:COMPUTERNAME) {
                # VMware registry keys
                $vmwareRegPaths = @(
                    "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools",
                    "HKLM:\SYSTEM\CurrentControlSet\Services\vmware"
                )
                foreach ($regPath in $vmwareRegPaths) {
                    if (Test-Path $regPath) {
                        $vmInfo.IsVirtual = $true
                        if (-not ($vmInfo.Platform -contains "VMware")) {
                            $vmInfo.Platform += "VMware"
                        }
                        break
                    }
                }
                
                # VirtualBox registry keys
                $vboxRegPath = "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions"
                if (Test-Path $vboxRegPath) {
                    $vmInfo.IsVirtual = $true
                    if (-not ($vmInfo.Platform -contains "VirtualBox")) {
                        $vmInfo.Platform += "VirtualBox"
                    }
                }
            } else {
                # Remote registry check with timeout
                try {
                    # Use a job with timeout for registry access
                    $regJob = Start-Job -ScriptBlock {
                        param($serverName)
                        try {
                            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $serverName)
                            $result = @{}
                            
                            # VMware
                            $vmwareKey = $reg.OpenSubKey('SOFTWARE\VMware, Inc.\VMware Tools')
                            if ($vmwareKey) {
                                $result.VMware = $true
                                $vmwareKey.Close()
                            }
                            
                            # VirtualBox
                            $vboxKey = $reg.OpenSubKey('SOFTWARE\Oracle\VirtualBox Guest Additions')
                            if ($vboxKey) {
                                $result.VirtualBox = $true
                                $vboxKey.Close()
                            }
                            
                            $reg.Close()
                            return $result
                        } catch {
                            return $null
                        }
                    } -ArgumentList $server
                    
                    $regResult = Wait-Job -Job $regJob -Timeout 3 | Receive-Job
                    Stop-Job -Job $regJob -ErrorAction SilentlyContinue
                    Remove-Job -Job $regJob -ErrorAction SilentlyContinue
                    
                    if ($regResult) {
                        if ($regResult.VMware) {
                            $vmInfo.IsVirtual = $true
                            if (-not ($vmInfo.Platform -contains "VMware")) {
                                $vmInfo.Platform += "VMware"
                            }
                        }
                        if ($regResult.VirtualBox) {
                            $vmInfo.IsVirtual = $true
                            if (-not ($vmInfo.Platform -contains "VirtualBox")) {
                                $vmInfo.Platform += "VirtualBox"
                            }
                        }
                    }
                } catch {}
            }
        } catch {}
        
        # Method 5: Check for cloud-specific indicators
        try {
            # AWS EC2 metadata service check (if accessible)
            if ($server -eq $env:COMPUTERNAME) {
                try {
                    $awsMetadata = Invoke-WebRequest -Uri "http://169.254.169.254/latest/meta-data/instance-id" -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue
                    if ($awsMetadata.StatusCode -eq 200) {
                        $vmInfo.IsVirtual = $true
                        if (-not ($vmInfo.Platform -contains "AWS EC2")) {
                            $vmInfo.Platform += "AWS EC2"
                        }
                        $vmInfo.Details.AWSInstanceId = $awsMetadata.Content
                    }
                } catch {}
                
                # Azure VM metadata check
                try {
                    $azureMetadata = Invoke-WebRequest -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01" -Headers @{"Metadata"="true"} -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue
                    if ($azureMetadata.StatusCode -eq 200) {
                        $vmInfo.IsVirtual = $true
                        if (-not ($vmInfo.Platform -contains "Azure VM")) {
                            $vmInfo.Platform += "Azure VM"
                        }
                        $vmInfo.Details.AzureMetadata = "Present"
                    }
                } catch {}
            }
        } catch {}
        
        # Method 6: Check disk controllers for virtualization signatures - with fast timeout
        try {
            $diskControllers = Invoke-CimQueryWithTimeout -ComputerName $server -ClassName Win32_SCSIController -TimeoutSeconds 2
            if ($diskControllers) {
                # VMware SCSI controllers
                $vmwareControllers = $diskControllers | Where-Object { $_.Name -match 'VMware|LSI Logic' }
                if ($vmwareControllers) {
                    $vmInfo.IsVirtual = $true
                    if (-not ($vmInfo.Platform -contains "VMware")) {
                        $vmInfo.Platform += "VMware"
                    }
                }
                
                # VirtualBox controllers
                $vboxControllers = $diskControllers | Where-Object { $_.Name -match 'VirtualBox' }
                if ($vboxControllers) {
                    $vmInfo.IsVirtual = $true
                    if (-not ($vmInfo.Platform -contains "VirtualBox")) {
                        $vmInfo.Platform += "VirtualBox"
                    }
                }
            }
        } catch {}
        
        # Method 7: Check for Docker (containerization) - with fast timeout
        try {
            $dockerService = Invoke-CimQueryWithTimeout -ComputerName $server -ClassName Win32_Service -Filter "Name='com.docker.service' OR Name='docker'" -TimeoutSeconds 2
            if ($dockerService) {
                $vmInfo.IsVirtual = $true
                if (-not ($vmInfo.Platform -contains "Docker")) {
                    $vmInfo.Platform += "Docker"
                }
                $vmInfo.Details.DockerService = @{
                    Status = $dockerService.State
                    StartMode = $dockerService.StartMode
                }
            }
        } catch {}
        
        # Check if this is a hypervisor host (not just a VM)
        $isHypervisorHost = $false
        $hypervisorType = $null
        
        # Check for VMware ESXi/vCenter - with fast timeout
        try {
            # ESXi hosts typically have SSH or hostd service
            $vmwareHostd = Invoke-CimQueryWithTimeout -ComputerName $server -ClassName Win32_Service -Filter "Name='hostd' OR Name='vmware-hostd'" -TimeoutSeconds 2
            if ($vmwareHostd) {
                $isHypervisorHost = $true
                $hypervisorType = "VMware ESXi"
                $vmInfo.Details.HypervisorHost = $true
                $vmInfo.Details.HypervisorType = "VMware ESXi"
            }
            
            # Check for vCenter (vpxd service)
            $vcenterService = Invoke-CimQueryWithTimeout -ComputerName $server -ClassName Win32_Service -Filter "Name='vpxd' OR DisplayName LIKE '%vCenter%'" -TimeoutSeconds 2
            if ($vcenterService) {
                $isHypervisorHost = $true
                $hypervisorType = "VMware vCenter"
                $vmInfo.Details.HypervisorHost = $true
                $vmInfo.Details.HypervisorType = "VMware vCenter"
            }
        } catch {}
        
        # Check for Hyper-V host (vmms service) - with fast timeout
        try {
            $vmmsService = Invoke-CimQueryWithTimeout -ComputerName $server -ClassName Win32_Service -Filter "Name='vmms'" -TimeoutSeconds 2
            if ($vmmsService) {
                $isHypervisorHost = $true
                $hypervisorType = "Hyper-V Host"
                $vmInfo.Details.HypervisorHost = $true
                $vmInfo.Details.HypervisorType = "Hyper-V Host"
                $vmInfo.Details.HyperVService = @{
                    Status = $vmmsService.State
                    StartMode = $vmmsService.StartMode
                }
            }
        } catch {}
        
        # Check for Citrix XenServer - with fast timeout
        try {
            $xenService = Invoke-CimQueryWithTimeout -ComputerName $server -ClassName Win32_Service -Filter "Name LIKE '%xen%' OR DisplayName LIKE '%XenServer%'" -TimeoutSeconds 2
            if ($xenService) {
                $isHypervisorHost = $true
                $hypervisorType = "Citrix XenServer"
                $vmInfo.Details.HypervisorHost = $true
                $vmInfo.Details.HypervisorType = "Citrix XenServer"
            }
        } catch {}
        
        # Only add to results if virtualization was detected (VM or hypervisor host)
        if ($vmInfo.IsVirtual -or $isHypervisorHost) {
            if ($isHypervisorHost) {
                $vmInfo.IsVirtual = $true  # Mark as virtualized system
                if (-not ($vmInfo.Platform -contains $hypervisorType)) {
                    $vmInfo.Platform += $hypervisorType
                }
            }
            
            # Optional: Use nmap for additional details if requested and available
            if ($UseNmap -and ($isHypervisorHost -or $vmInfo.IsVirtual)) {
                $nmapDetails = Get-NmapDetails -Server $server -Platform $vmInfo.Platform
                if ($nmapDetails) {
                    $vmInfo.Details.NmapScan = $nmapDetails
                }
            }
            
            $Results.Virtualization += $vmInfo
            $platformStr = if ($vmInfo.Platform.Count -gt 0) { $vmInfo.Platform -join ', ' } else { "Unknown" }
            $hostType = if ($isHypervisorHost) { " (Hypervisor Host)" } else { "" }
            Write-Host "  [+] Virtualization detected on $server : $platformStr$hostType" -ForegroundColor Green
        }
    }
    
    if ($Results.Virtualization.Count -eq 0) {
        Write-Host "  [-] No virtualization platforms detected" -ForegroundColor Gray
    } else {
        $vmCount = ($Results.Virtualization | Where-Object { $_.Details.HypervisorHost -ne $true }).Count
        $hypervisorCount = ($Results.Virtualization | Where-Object { $_.Details.HypervisorHost -eq $true }).Count
        Write-Host "  [+] Total virtualized systems: $($Results.Virtualization.Count) (VMs: $vmCount, Hypervisor Hosts: $hypervisorCount)" -ForegroundColor Green
    }
}

# Function to get nmap details for virtualization platforms
function Get-NmapDetails {
    param(
        [string]$Server,
        [array]$Platform
    )
    
    # Check if nmap is available
    $nmapPath = $null
    try {
        $nmapPath = Get-Command nmap -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
        if (-not $nmapPath) {
            # Try common installation paths
            $commonPaths = @(
                "C:\Program Files (x86)\Nmap\nmap.exe",
                "C:\Program Files\Nmap\nmap.exe",
                "$env:ProgramFiles\Nmap\nmap.exe",
                "$env:ProgramFiles(x86)\Nmap\nmap.exe"
            )
            foreach ($path in $commonPaths) {
                if (Test-Path $path) {
                    $nmapPath = $path
                    break
                }
            }
        }
    } catch {
        return $null
    }
    
    if (-not $nmapPath) {
        return $null
    }
    
    # Determine ports to scan based on platform
    $portsToScan = @()
    foreach ($p in $Platform) {
        switch ($p) {
            "VMware ESXi" {
                $portsToScan += "443,902,5988,5989"  # HTTPS, ESXi, CIM, CIM SSL
            }
            "VMware vCenter" {
                $portsToScan += "443,902,8080,8443"  # HTTPS, ESXi, HTTP, HTTPS alt
            }
            "Hyper-V Host" {
                $portsToScan += "5985,5986,135,445"  # WinRM HTTP/HTTPS, RPC, SMB
            }
            "Citrix XenServer" {
                $portsToScan += "80,443,5900"  # HTTP, HTTPS, VNC
            }
            default {
                # Default virtualization ports
                $portsToScan += "443,5985,5986"
            }
        }
    }
    
    # Remove duplicates and join
    $uniquePorts = ($portsToScan | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Sort-Object -Unique) -join ','
    
    if (-not $uniquePorts) {
        $uniquePorts = "443,5985,5986,902"  # Default ports
    }
    
    try {
        Write-Host "    [*] Running nmap scan on $server (ports: $uniquePorts)..." -ForegroundColor DarkGray
        
        # Run nmap with version detection and service detection
        $nmapArgs = @(
            "-p", $uniquePorts
            "-sV"  # Version detection
            "-sC"  # Default scripts
            "--open"  # Only show open ports
            "-T4"  # Aggressive timing
            "--host-timeout", "10s"  # Timeout per host
            $server
        )
        
        $nmapOutput = & $nmapPath $nmapArgs 2>&1
        
        # Parse nmap output
        $nmapResult = @{
            Ports = @()
            Services = @()
            OS = $null
            RawOutput = ($nmapOutput -join "`n")
        }
        
        $currentPort = $null
        foreach ($line in $nmapOutput) {
            # Parse port lines: "443/tcp   open  https     VMware ESXi httpd"
            if ($line -match '(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)') {
                $port = $matches[1]
                $protocol = $matches[2]
                $service = $matches[3]
                $version = $matches[4].Trim()
                
                $nmapResult.Ports += @{
                    Port = $port
                    Protocol = $protocol
                    State = "open"
                    Service = $service
                    Version = $version
                }
                
                if ($version) {
                    $nmapResult.Services += "$service ($port/$protocol): $version"
                } else {
                    $nmapResult.Services += "$service ($port/$protocol)"
                }
            }
            # Parse OS detection: "OS details: VMware ESXi 6.7.0"
            elseif ($line -match 'OS details:\s*(.+)') {
                $nmapResult.OS = $matches[1].Trim()
            }
            # Parse OS CPE: "OS CPE: cpe:/o:vmware:esxi:6.7"
            elseif ($line -match 'OS CPE:\s*(.+)') {
                if (-not $nmapResult.OS) {
                    $nmapResult.OS = $matches[1].Trim()
                }
            }
        }
        
        if ($nmapResult.Ports.Count -gt 0) {
            Write-Host "    [+] Nmap found $($nmapResult.Ports.Count) open port(s)" -ForegroundColor DarkGreen
            return $nmapResult
        }
    } catch {
        Write-Host "    [-] Nmap scan failed: $_" -ForegroundColor DarkGray
    }
    
    return $null
}

# Helper function to convert subnet mask to prefix length
function Convert-SubnetMaskToPrefixLength {
    param([string]$SubnetMask)
    
    try {
        $maskParts = $SubnetMask -split '\.'
        $binaryMask = ""
        foreach ($part in $maskParts) {
            $binaryMask += [Convert]::ToString([int]$part, 2).PadLeft(8, '0')
        }
        return ($binaryMask -replace '0', '').Length
    } catch {
        return $null
    }
}

# Helper function to get local subnet
function Get-LocalSubnet {
    try {
        $adapters = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -notlike "127.*" }
        if ($adapters) {
            $adapter = $adapters | Select-Object -First 1
            $ipParts = $adapter.IPAddress -split '\.'
            return "$($ipParts[0]).$($ipParts[1]).$($ipParts[2])"
        }
    } catch {}
    return $null
}

# Helper function to get IPs to scan from a subnet
function Get-SubnetIPsToScan {
    param(
        [string]$Subnet,
        [int]$PrefixLength
    )
    
    $ipsToScan = @()
    
    try {
        # Parse subnet
        $subnetParts = $Subnet -split '\.'
        $baseIP = "$($subnetParts[0]).$($subnetParts[1]).$($subnetParts[2])"
        
        # Calculate host range based on prefix length
        $hostBits = 32 - $PrefixLength
        $hostCount = [Math]::Pow(2, $hostBits)
        
        # For /24 subnets, scan common hypervisor IPs and a sample
        if ($PrefixLength -eq 24) {
            # Common hypervisor management IPs
            $commonIPs = @(1, 10, 50, 100, 150, 200, 254)
            foreach ($lastOctet in $commonIPs) {
                if ($lastOctet -lt $hostCount) {
                    $ipsToScan += "$baseIP.$lastOctet"
                }
            }
            
            # Also sample first and last few IPs
            for ($i = 2; $i -le 10; $i++) {
                if ($i -lt $hostCount) {
                    $ipsToScan += "$baseIP.$i"
                }
            }
            for ($i = [Math]::Max(245, $hostCount - 10); $i -lt $hostCount; $i++) {
                $ipsToScan += "$baseIP.$i"
            }
        }
        # For larger subnets (/16, /8), just scan common IPs
        elseif ($PrefixLength -le 16) {
            $commonThirdOctets = @(0, 1, 10, 50, 100, 200, 254)
            foreach ($thirdOctet in $commonThirdOctets) {
                foreach ($lastOctet in @(1, 10, 100, 254)) {
                    if ($PrefixLength -eq 16) {
                        $ipsToScan += "$baseIP.$thirdOctet.$lastOctet"
                    } elseif ($PrefixLength -eq 8) {
                        $ipsToScan += "$baseIP.$thirdOctet.1.$lastOctet"
                    }
                }
            }
        }
        
        # Remove duplicates
        $ipsToScan = $ipsToScan | Select-Object -Unique
    } catch {
        Write-Host "    [-] Error parsing subnet $Subnet : $_" -ForegroundColor DarkGray
    }
    
    return $ipsToScan
}

# Main execution function (allows parameter passing when executed from GitHub)
function Invoke-ADDiscovery {
    param(
        [Parameter(Mandatory=$false)]
        [switch]$OutputJson,
        
        [Parameter(Mandatory=$false)]
        [switch]$UseNmap
    )
    
    # Use script-level parameters if function parameters not provided
    if (-not $PSBoundParameters.ContainsKey('OutputJson')) {
        $OutputJson = $script:OutputJson
    }
    if (-not $PSBoundParameters.ContainsKey('UseNmap')) {
        $UseNmap = $script:UseNmap
    }
    
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
        Get-VirtualizationPlatforms -UseNmap:$UseNmap
    
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
    Write-Host "Virtualized Systems: $($Results.Virtualization.Count)" -ForegroundColor White
    
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
}

# Store script-level parameters for function access
$script:OutputJson = $OutputJson
$script:UseNmap = $UseNmap

# Auto-execute if run as script (not when called as function)
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-ADDiscovery -OutputJson:$OutputJson -UseNmap:$UseNmap
}
