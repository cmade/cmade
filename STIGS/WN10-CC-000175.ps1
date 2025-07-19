  <#
.SYNOPSIS
   The PowerShell script creates the necessary registry path if it doesn't exist and then sets the DisableInventory value to 1, which disables the Application Compatibility Program Inventory data collection.
.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-19
    Last Modified   : 2025-07-19
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000175

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-CC-000175.ps1 
#>

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
$regValueName = "DisableInventory"
$enforcedValue = 1

try {
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name $regValueName -Value $enforcedValue -Type DWord -Force
    Write-Host "Successfully enforced WN10-CC-000175. The Application Compatibility Program Inventory is now disabled."
}
catch {
    Write-Host "An error occurred. Please ensure you are running this script with administrative privileges."
} 
