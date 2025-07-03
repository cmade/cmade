  <#
.SYNOPSIS
    This PowerShell script ensures that if an account gets locked out (due to failed logon attempts), it will stay locked for at least 15 minutes, deterring brute-force attacks.

.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-03
    Last Modified   : 2025-07-03
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000005

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-AC-000005.ps1 
#>
# Ensure account lockout duration is 15 minutes or greater
$desiredDuration = 15

# Get current lockout duration
$currentDuration = (net accounts | Where-Object { $_ -match "Lockout duration" }) -replace "[^\d]", ""

if ([int]$currentDuration -lt $desiredDuration) {
    Write-Host "Current lockout duration is $currentDuration minutes. Setting it to $desiredDuration minutes..."
    net accounts /lockoutduration:$desiredDuration
} else {
    Write-Host "Lockout duration is already $currentDuration minutes. No change needed."
}
 
