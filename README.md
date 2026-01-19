# AD Discovery Script

PowerShell script for discovering Active Directory infrastructure components, designed to run entirely in memory and be downloaded/executed directly from GitHub.

## Quick Start (GitHub)

Replace `USERNAME`, `REPO`, and `BRANCH` with your GitHub details:

```powershell
# One-liner to execute directly from GitHub
iex (iwr -UseBasicParsing https://raw.githubusercontent.com/USERNAME/REPO/BRANCH/Invoke-ADDiscovery.ps1).Content
```

### Example GitHub Execution

```powershell
# Example with actual GitHub repo
iex (iwr -UseBasicParsing https://raw.githubusercontent.com/yourusername/detectdor/main/Invoke-ADDiscovery.ps1).Content

# Save results to variable
$results = iex (iwr -UseBasicParsing https://raw.githubusercontent.com/yourusername/detectdor/main/Invoke-ADDiscovery.ps1).Content

# Export results to JSON file
iex (iwr -UseBasicParsing https://raw.githubusercontent.com/yourusername/detectdor/main/Invoke-ADDiscovery.ps1).Content | ConvertTo-Json -Depth 10 | Out-File discovery-results.json
```

## Features

- **Domain Controller Discovery**: Identifies all AD Domain Controllers with IP addresses, sites, and OS information
- **DHCP Server Discovery**: Finds DHCP servers via AD queries and service checks
- **DNS Server Discovery**: Identifies DNS servers in the domain
- **Entra AD Connect Detection**: Multiple detection methods to find Azure AD Connect/Entra AD Connect installations
- **Virtualization Detection**: Detects common virtualization platforms (VMware, Hyper-V, Citrix XenServer, VirtualBox, QEMU/KVM, Docker, AWS EC2, Azure VM)
- **In-Memory Execution**: Runs entirely in memory, no disk writes required
- **GitHub Optimized**: Designed for direct execution from GitHub raw URLs

## Local Usage

If you've cloned the repository:

```powershell
# Run locally
.\Invoke-ADDiscovery.ps1

# Save results to variable
$results = .\Invoke-ADDiscovery.ps1

# Export results to JSON file
.\Invoke-ADDiscovery.ps1 | ConvertTo-Json -Depth 10 | Out-File discovery-results.json
```

## Requirements

- PowerShell 3.0 or higher
- Domain-joined machine or appropriate credentials
- Active Directory PowerShell module (usually pre-installed on domain controllers)
- Appropriate permissions to query AD and remote servers
- Internet access (for GitHub download)

## Detection Methods for Entra AD Connect

The script uses multiple methods to detect Entra AD Connect installations:

1. **Registry Check**: `HKLM:\SOFTWARE\Microsoft\Azure AD Connect`
2. **Service Check**: ADSync service detection
3. **Process Check**: ADSync.exe and miiserver.exe processes
4. **Installed Programs**: Checks Windows installed programs
5. **Directory Check**: Common installation paths

## Detection Methods for Virtualization Platforms

The script uses multiple methods to detect virtualization platforms:

1. **BIOS/System Manufacturer**: Checks Win32_ComputerSystem for virtualization signatures
2. **Service Detection**: Identifies virtualization-specific services (VMware Tools, Hyper-V Integration Services, VirtualBox Guest Additions, etc.)
3. **Network Adapter Signatures**: Detects virtualization-specific network adapters
4. **Registry Keys**: Checks for virtualization software registry entries
5. **Cloud Metadata Services**: Queries AWS EC2 and Azure VM metadata endpoints
6. **Disk Controller Signatures**: Identifies virtualization-specific SCSI controllers
7. **Container Detection**: Detects Docker services

Supported platforms:
- VMware (vSphere/ESXi)
- Microsoft Hyper-V
- Citrix XenServer
- Oracle VirtualBox
- QEMU/KVM
- Docker
- AWS EC2
- Microsoft Azure VM

## Output

The script outputs:
- Console summary with color-coded results
- JSON-formatted detailed results
- Returns a PowerShell object with all discovered information

## Example Output

```
=== Active Directory Discovery Script ===
Started: 2026-01-19 16:00:00

[*] Discovering Domain Controllers...
  [+] Found DC: DC01.contoso.com (192.168.1.10)
  [+] Found DC: DC02.contoso.com (192.168.1.11)

[*] Discovering DHCP Servers...
  [+] Found DHCP Server: DHCP01

[*] Discovering DNS Servers...
  [+] Found DNS Server: DC01.contoso.com (192.168.1.10)

[*] Discovering Entra AD Connect installations...
  [+] Entra AD Connect FOUND on: DC01 (Methods: Service, Registry)

[*] Discovering Virtualization Platforms...
  [+] Virtualization detected on DC01 : VMware
  [+] Virtualization detected on SQL01 : Hyper-V
  [+] Total virtualized systems: 2

=== Discovery Summary ===
Domain Controllers: 2
DHCP Servers: 1
DNS Servers: 2
Entra AD Connect Installations: 1
Virtualized Systems: 2
```

## GitHub Setup

To use this script from GitHub:

1. Push this repository to GitHub
2. Get the raw URL format: `https://raw.githubusercontent.com/USERNAME/REPO/BRANCH/Invoke-ADDiscovery.ps1`
3. Replace:
   - `USERNAME` with your GitHub username
   - `REPO` with your repository name (e.g., `detectdor`)
   - `BRANCH` with your branch name (usually `main` or `master`)

## Security Notes

- This script is designed for authorized security assessments and IT administration
- Ensure you have proper authorization before running discovery scripts
- The script uses standard Windows APIs and does not perform any malicious activities
- All operations are read-only discovery operations
- When downloading from GitHub, ensure you trust the repository source
- The script enforces TLS 1.2 for secure GitHub connections

## License

Use responsibly and only in authorized environments.
