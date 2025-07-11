  <#
.SYNOPSIS
   The PowerShell script can efficiently audit and remediate the WN10-CC-000205 security control across Windows 10 environments, ensuring compliance with telemetry data collection policies.

.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-11
    Last Modified   : 2025-07-11
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000205

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-CC-000205.ps1 
#>
# Path to the registry key
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$regValueName = "AllowTelemetry"
$compliantValue = 1 # Set to 0 for Security, 1 for Basic, or 2 for Enhanced

try {
    # Check if the registry path exists, and create it if it doesn't
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    # Set the 'AllowTelemetry' registry value
    Set-ItemProperty -Path $regPath -Name $regValueName -Value $compliantValue -Type DWord -Force

    Write-Host "Enforced: 'Allow Telemetry' has been set to '$compliantValue'."
}
catch {
    Write-Host "An error occurred while enforcing the setting: $_"
} 
