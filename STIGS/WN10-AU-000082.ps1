 <#
.SYNOPSIS
   The PowerShell script logs an event each time a user successfully accesses a shared file, which is crucial for monitoring and investigating activity on network shares. 
.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-19
    Last Modified   : 2025-07-19
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000082

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-AU-000082.ps1 
#>

$subcategory = "File Share"

try {
    auditpol /set /subcategory:"$subcategory" /success:enable
    Write-Host "✅ Successfully enforced WN10-AU-000082."
    Write-Host "Auditing for '$subcategory' successes is now enabled."
}
catch {
    Write-Host "❗ An error occurred. Please ensure you are running this script with administrative privileges."
} 
