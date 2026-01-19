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

=== Discovery Summary ===
Domain Controllers: 2
DHCP Servers: 1
DNS Servers: 2
Entra AD Connect Installations: 1
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
