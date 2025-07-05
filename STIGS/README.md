# Programmatic Vulnerability Remediations

## Remediations Table

| Tenable Vuln-ID  | STIG-ID        | Description                                                                                                             | Language   | Link                                                     |
|------------------|----------------|-------------------------------------------------------------------------------------------------------------------------|------------|----------------------------------------------------------|
| V-220732         | WN10-00-000175 | This PowerShell script disables the Secondary Logon service (seclogon) to prevent privilege escalation via "Run as" functionality. | PowerShell | [View Remediation](https://github.com/cmade/cmade/blob/main/STIGS/WN10-00-000175.ps1) |
| V-220739         | WN10-AC-000005 | This PowerShell script configures the account lockout duration to 15 minutes or more to protect against brute-force login attempts. | PowerShell | [View Remediation](https://github.com/cmade/cmade/blob/main/STIGS/WN10-AC-000005.PS1) |
| V-220751         | WN10-AU-000035 | The PowerShell script enables auditing of failed user account management events to ensure changes and errors are logged for security monitoring. | PowerShell | [View Remediation](https://github.com/cmade/cmade/blob/main/STIGS/WN10-AU-000035.ps1) |
| V-220779         | WN10-AU-000500 | This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB). | PowerShell | [View Remediation](https://github.com/cmade/cmade/blob/main/STIGS/WN10-AU-000500.PS1) |
| V-220805         | WN10-CC-000052 | This PowerShell script sets the ECC Curve Order to prioritize NistP384 over NistP256, ensuring stronger cryptographic algorithms are used. | PowerShell | [View Remediation](https://github.com/cmade/cmade/blob/main/STIGS/WN10-CC-000052.ps1) |
| V-220828         | WN10-CC-000185 | This PowerShell script disables AutoRun for all drives to prevent automatic execution of potentially malicious code from removable media. | PowerShell | [View Remediation](https://github.com/cmade/cmade/blob/main/STIGS/WN10-CC-000185.PS1) |
| V-220857         | WN10-CC-000315 | The PowerShell script disables the Windows Installer policy that allows users to install with elevated privileges — which poses a significant security risk. | PowerShell | [View Remediation](https://github.com/cmade/cmade/blob/main/STIGS/WN10-CC-000315.ps1) |
| V-252896         | WN10-CC-000327 | The PowerShell script makes your Windows 10 system compliant with STIG WN10-CC-000327 by enabling transcription and routing logs to a centralized, secure location. | PowerShell | [View Remediation](https://github.com/cmade/cmade/blob/main/STIGS/WN10-CC-000327.ps1) |
