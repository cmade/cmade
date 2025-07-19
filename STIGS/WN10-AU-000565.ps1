 <#
.SYNOPSIS
   The PowerShell script uses the native auditpol.exe utility, which is the standard method for managing advanced audit policies in Windows. 
.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-19
    Last Modified   : 2025-07-19
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000565

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-AU-000565.ps1 
#>

$subcategory = "Other Logon/Logoff Events"

try {
    auditpol /set /subcategory:"$subcategory" /failure:enable
    Write-Host "✅ Successfully enforced WN10-AU-000565."
    Write-Host "Auditing for '$subcategory' failures is now enabled."
}
catch {
    Write-Host "❗ An error occurred. Please ensure you are running this script with administrative privileges."
} 
