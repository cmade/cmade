 <#
.SYNOPSIS
   The PowerShell script enhances security by ensuring that voice commands cannot be used to interact with applications when the device is locked.
.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-19
    Last Modified   : 2025-07-19
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000365

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-CC-000365.ps1 
#>

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$regValueName = "LetAppsActivateWithVoiceAboveLock"
# Set value to '2' to enforce "Disabled" / "Force Deny".
$enforcedValue = 2

try {
    # Create the registry path if it doesn't exist
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    
    # Set the required registry value. This creates the value if it's missing.
    Set-ItemProperty -Path $regPath -Name $regValueName -Value $enforcedValue -Type DWord -Force
    
    Write-Host "✅ Successfully enforced WN10-CC-000365."
    Write-Host "Voice activation of apps while locked is now disabled."
}
catch {
    Write-Host "❗ An error occurred. Please ensure you are running this script with administrative privileges."
    Write-Host "Error details: $($_.Exception.Message)"
} 
