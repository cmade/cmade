 <#
.SYNOPSIS
   The PowerShell script sets Remote Desktop Services client connection encryption level to 'High'.

.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-13
    Last Modified   : 2025-07-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000290

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-CC-000290.ps1 
#>
# WN10-CC-000290: Set Remote Desktop Services client connection encryption level to 'High'

# Define registry key path and property details
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$valueName = "MinEncryptionLevel"
$requiredValue = 3

# Check if the registry path exists. If not, create it.
if (-not (Test-Path $registryPath)) {
    try {
        New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
        Write-Host "Registry path '$registryPath' was created."
    }
    catch {
        Write-Error "Failed to create registry path '$registryPath'. Please run PowerShell as an administrator."
        return
    }
}

# Get the current value of the MinEncryptionLevel registry key
$currentValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue

# Check if the value is set correctly. If not, set it.
if ($null -eq $currentValue -or $currentValue.MinEncryptionLevel -ne $requiredValue) {
    try {
        Set-ItemProperty -Path $registryPath -Name $valueName -Value $requiredValue -Type DWord -Force -ErrorAction Stop
        Write-Host "Successfully set '$valueName' to '$requiredValue' at '$registryPath'."
    }
    catch {
        Write-Error "Failed to set the registry value. Please ensure you are running PowerShell with administrator privileges."
    }
}
else {
    Write-Host "The RDP client connection encryption level is already compliant with WN10-CC-000290."
} 
