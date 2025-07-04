  <#
.SYNOPSIS
   The PowerShell script ensures that Windows 10 logs failed user account management events, making the system compliant with STIG WN10-AU-000035 and passing Tenable scans.

.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-04
    Last Modified   : 2025-07-04
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000035

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-AU-000035.ps1 
#>
# Must run as Administrator

# Subcategory name exactly as shown in auditpol
$auditSubcategory = "User Account Management"

# Enable auditing for Failure (and optionally Success)
AuditPol /Set /SubCategory:"$auditSubcategory" /Failure:Enable

# Optional: also enable Success if required by your policy
# AuditPol /Set /SubCategory:"$auditSubcategory" /Success:Enable

# Confirm result
Write-Host "`n🔍 Verifying 'User Account Management' audit policy:"
AuditPol /Get /Category:"Account Management" | Where-Object { $_ -match "User Account Management" }
 
