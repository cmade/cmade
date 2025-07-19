 <#
.SYNOPSIS
   The PowerShell script setting ensures that a specific title is displayed on the legal notice banner that users see before logging on.
.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-19
    Last Modified   : 2025-07-19
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000080

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-SO-000080.ps1 
#>

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$regValueName = "LegalNoticeCaption"

# ---------------------------------------------------------------------
# IMPORTANT: Replace the text below with your organization's approved
# legal notice title.
# ---------------------------------------------------------------------
$enforcedValue = "DoD Notice and Consent Banner"

try {
    # Set the required registry value. This creates the value if it's missing.
    Set-ItemProperty -Path $regPath -Name $regValueName -Value $enforcedValue -Type String -Force
    
    Write-Host "✅ Successfully enforced WN10-SO-000080."
    Write-Host "The legal banner title has been set to: '$enforcedValue'"
}
catch {
    Write-Host "❗ An error occurred. Please ensure you are running this script with administrative privileges."
    Write-Host "Error details: $($_.Exception.Message)"
} 
