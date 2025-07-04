<#
.SYNOPSIS
    This PowerShell script sets the ECC Curve Order to prioritize NistP384 over NistP256, ensuring stronger cryptographic algorithms are used.
    
.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-04
    Last Modified   : 2025-07-04
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000052

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-CC-000052.ps1 
#>
# Must run in an elevated PowerShell session

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
$propertyName = "EccCurves"
$eccCurves = [string[]]("NistP384", "NistP256")

# Create the registry key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Delete existing malformed value (if any)
if (Get-ItemProperty -Path $regPath -Name $propertyName -ErrorAction SilentlyContinue) {
    Remove-ItemProperty -Path $regPath -Name $propertyName -Force
}

# Use Set-ItemProperty instead of New-ItemProperty
Set-ItemProperty -Path $regPath -Name $propertyName -Value $eccCurves

# Confirm the correct formatting
Write-Host "`n✅ ECC Curve Order set as REG_MULTI_SZ:"
(Get-ItemProperty -Path $regPath -Name $propertyName).$propertyName | ForEach-Object { Write-Host "   → $_" }
