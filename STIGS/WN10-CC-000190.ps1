  <#
.SYNOPSIS
   The PowerShell script directly remediates WN10-CC-000190 by disabling AutoPlay for all drives at the machine level.

.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-09
    Last Modified   : 2025-07-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000190

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-CC-000190.ps1 
#>
# Define the registry path and the name of the property to be set
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$propertyName = "NoDriveTypeAutoRun"
$propertyValue = 255 # This is the decimal equivalent of 0xFF

# Check if the registry path exists. If not, create it.
if (-not (Test-Path $registryPath)) {
  New-Item -Path $registryPath -Force | Out-Null
}

# Set the registry value to disable AutoPlay on all drives
Set-ItemProperty -Path $registryPath -Name $propertyName -Value $propertyValue -Type DWord -Force

Write-Host "AutoPlay has been disabled for all drives." 
