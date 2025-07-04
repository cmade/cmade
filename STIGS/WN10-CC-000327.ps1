   <#
.SYNOPSIS
   The PowerShell script makes your Windows 10 system compliant with STIG WN10-CC-000327 by enabling transcription and routing logs to a centralized, secure location.

.NOTES
    Author          : Clive Mangerere
    LinkedIn        : https://www.linkedin.com/in/mclive/
    GitHub          : https://github.com/cmade
    Date Created    : 2025-07-04
    Last Modified   : 2025-07-04
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000327

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\WN10-CC-000327.ps1 
#>
# Must run as Administrator

# Define the registry path and values
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
$transcriptDir = "\\CentralLogServer\PowerShellLogs"  # Replace with your secure UNC path

# Create the registry key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the required values
Set-ItemProperty -Path $regPath -Name "EnableTranscripting" -Value 1 -Type DWord
Set-ItemProperty -Path $regPath -Name "OutputDirectory" -Value $transcriptDir -Type String
Set-ItemProperty -Path $regPath -Name "IncludeInvocationHeader" -Value 1 -Type DWord

# Display confirmation
Write-Host "`n✅ PowerShell Transcription has been enabled."
Write-Host "   → Logs will be saved to: $transcriptDir"
Write-Host "   → Invocation headers included in transcripts."
 
