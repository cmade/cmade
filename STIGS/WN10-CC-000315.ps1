 <#
.SYNOPSIS
   The PowerShell script disables the Windows Installer policy that allows users to install with elevated privileges — which poses a significant security risk.

.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-04
    Last Modified   : 2025-07-04
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000315

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-CC-000315.ps1 
#>
# Must be run as Administrator

# Define both registry paths
$paths = @(
    "HKLM:\Software\Policies\Microsoft\Windows\Installer",  # Computer Configuration
    "HKCU:\Software\Policies\Microsoft\Windows\Installer"   # User Configuration
)

foreach ($path in $paths) {
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }

    # Set AlwaysInstallElevated to 0 (disabled)
    Set-ItemProperty -Path $path -Name "AlwaysInstallElevated" -Value 0 -Type DWord
}

Write-Host "`n✅ STIG WN10-CC-000315 enforced: 'Always install with elevated privileges' is now disabled in both HKLM and HKCU." -ForegroundColor Green
 
