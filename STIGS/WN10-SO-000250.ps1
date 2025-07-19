 <#
.SYNOPSIS
   The PowerShell script is critical for security as it presents elevation prompts in a protected area of memory (the secure desktop), which prevents malicious software from spoofing the prompt and capturing credentials.
.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-19
    Last Modified   : 2025-07-19
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000250

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-SO-000250.ps1 
#>

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$regValueName = "ConsentPromptBehaviorAdmin"
# Enforce by setting to '2' for "Prompt for consent on the secure desktop".
$enforcedValue = 2

try {
    # Set the required registry value. This creates the value if it's missing.
    Set-ItemProperty -Path $regPath -Name $regValueName -Value $enforcedValue -Type DWord -Force
    
    Write-Host "✅ Successfully enforced WN10-SO-000250."
    Write-Host "UAC is now configured to 'Prompt for consent on the secure desktop'."
}
catch {
    Write-Host "❗ An error occurred. Please ensure you are running this script with administrative privileges."
    Write-Host "Error details: $($_.Exception.Message)"
} 
