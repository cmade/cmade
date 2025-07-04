  <#
.SYNOPSIS
    This PowerShell script ensures that AutoRun commands are prevented, you need to configure the relevant registry setting to disable AutoRun behavior on all drives.

.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-03
    Last Modified   : 2025-07-03
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000185

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-CC-000185.ps1 
#>
# Requires: Administrator privileges

$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$valueName = "NoAutoRun"
$desiredValue = 1

# Create the registry path if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Set the NoAutoRun value
$currentValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue

if ($currentValue.$valueName -ne $desiredValue) {
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $desiredValue
    Write-Host "NoAutoRun set to $desiredValue (AutoRun disabled)."
} else {
    Write-Host "NoAutoRun is already set to $desiredValue. No change needed."
}
 
