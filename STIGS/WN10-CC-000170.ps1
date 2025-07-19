 <#
.SYNOPSIS
   The PowerShell script allows users to sign in to supported modern-style apps using their enterprise (domain) credentials instead of being forced to use a personal Microsoft account.
.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-19
    Last Modified   : 2025-07-19
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000170

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-CC-000170.ps1 
#>


$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$regValueName = "MSAOptional"
$enforcedValue = 1

try {
    # Create the registry path if it doesn't exist (though it's a common system path)
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    
    # Set the required registry value
    Set-ItemProperty -Path $regPath -Name $regValueName -Value $enforcedValue -Type DWord -Force
    
    Write-Host "✅ Successfully enforced WN10-CC-000170."
    Write-Host "The setting to allow Microsoft accounts to be optional has been enabled."
}
catch {
    Write-Host "❗ An error occurred. Please ensure you are running this script with administrative privileges."
    Write-Host "Error details: $($_.Exception.Message)"
} 
