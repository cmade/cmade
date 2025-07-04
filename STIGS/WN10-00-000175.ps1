 <#
.SYNOPSIS
    This PowerShell script disables the Secondary Logon service (seclogon) to prevent privilege escalation via "Run as" functionality.
    
.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-04
    Last Modified   : 2025-07-04
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000175

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-00-000175.ps1 
#>
# Must run as Administrator

$serviceName = "seclogon"

# Check current status
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if ($null -eq $service) {
    Write-Host "❌ Service '$serviceName' not found. This system may not support it." -ForegroundColor Red
} else {
    # Disable the service
    Set-Service -Name $serviceName -StartupType Disabled

    # Stop the service if it's currently running
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force
    }

    Write-Host "✅ Secondary Logon service (seclogon) has been disabled and stopped." -ForegroundColor Green
}
 
