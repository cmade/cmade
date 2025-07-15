 <#
.SYNOPSIS
   The PowerShell script will check for and disable WDigest authentication by modifying the Windows Registry. 

.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-14
    Last Modified   : 2025-07-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000038

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-CC-000038.ps1 
#>
#Requires -RunAsAdministrator

# Define the registry path and key for WDigest settings
$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
$RegistryKey = "UseLogonCredential"

# Check if the WDigest registry path exists
if (Test-Path $RegistryPath) {
    # Get the current value of the UseLogonCredential key
    $CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $RegistryKey -ErrorAction SilentlyContinue

    # If the key exists and is not set to 0, or if it doesn't exist, disable it
    if ($null -eq $CurrentValue -or $CurrentValue.UseLogonCredential -ne 0) {
        Write-Host "WDigest Authentication is currently enabled or not configured. Disabling it now."
        # Set the UseLogonCredential value to 0 to disable WDigest
        Set-ItemProperty -Path $RegistryPath -Name $RegistryKey -Value 0 -Type DWord -Force
        Write-Host "WDigest Authentication has been successfully disabled."
    }
    else {
        Write-Host "WDigest Authentication is already disabled. No action needed."
    }
}
else {
    # If the WDigest path does not exist, create it and set the value to disable authentication
    Write-Host "WDigest registry key not found. Creating key and disabling WDigest Authentication."
    New-Item -Path $RegistryPath -Force | Out-Null
    Set-ItemProperty -Path $RegistryPath -Name $RegistryKey -Value 0 -Type DWord -Force
    Write-Host "WDigest Authentication has been successfully disabled."
}

# A system restart is recommended for the changes to take full effect.
Write-Host "A reboot is recommended to ensure the setting is applied system-wide." 
