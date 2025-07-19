 <#
.SYNOPSIS
   The PowerShell script prevents unauthenticated users from listing shared folders on the system, reducing the information available to potential attackers.
.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-19
    Last Modified   : 2025-07-19
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000150

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-SO-000150.ps1 
#>

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$regValueName = "RestrictAnonymous"
$enforcedValue = 1

try {
    # Set the required registry value. This creates the value if it's missing.
    Set-ItemProperty -Path $regPath -Name $regValueName -Value $enforcedValue -Type DWord -Force
    
    Write-Host "✅ Successfully enforced WN10-SO-000150."
    Write-Host "Anonymous share enumeration is now restricted."
}
catch {
    Write-Host "❗ An error occurred. Please ensure you are running this script with administrative privileges."
    Write-Host "Error details: $($_.Exception.Message)"
} 
