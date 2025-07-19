 <#
.SYNOPSIS
   The PowerShell script will configure the WinRM client policy to prevent the use of unencrypted communication. 

.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-19
    Last Modified   : 2025-07-19
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000335

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-CC-000335.ps1 
#>
#Requires -RunAsAdministrator

# Define the registry path and key for the WinRM client policy
$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
$RegistryKey = "AllowUnencryptedTraffic"

# The desired value '0' ensures unencrypted traffic is NOT allowed
$DesiredValue = 0

# Check if the policy path exists. If not, create it.
if (-not (Test-Path $RegistryPath)) {
    Write-Host "WinRM client policy path not found. Creating it now..."
    New-Item -Path $RegistryPath -Force | Out-Null
}

# Get the current value of the 'AllowUnencryptedTraffic' setting
# Using -ErrorAction SilentlyContinue to handle cases where the key doesn't exist
$CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $RegistryKey -ErrorAction SilentlyContinue

# If the setting is not configured or is not set to 0, enforce the policy
if ($null -eq $CurrentValue -or $CurrentValue.$RegistryKey -ne $DesiredValue) {
    Write-Host "WinRM client is currently allowing unencrypted traffic or is not configured."
    Write-Host "Configuring the client to prevent unencrypted traffic..."
    
    # Set the registry value to 0 (disallow)
    Set-ItemProperty -Path $RegistryPath -Name $RegistryKey -Value $DesiredValue -Type DWord -Force
    
    Write-Host "✅ The WinRM client policy has been successfully configured."
}
else {
    Write-Host "✅ The WinRM client is already configured to prevent unencrypted traffic. No action needed."
} 
