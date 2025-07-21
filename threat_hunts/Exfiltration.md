# Threat Hunt Report: Data Exfiltration from PIP'd Employee

## Investigation Scenario: Data Exfiltration from PIP'd Employee

Create a VM and onboard it to MDE if you haven't already — Do not use `labuser`/`Cyberlab123!` for credentials (or any other easy password). Your VM will most certainly get breached by a bad actor if it’s on long enough. This has already happened once.

Run this PowerShell command on your VM after onboarding it to MDE:

```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1' -OutFile 'C:\programdata\exfiltratedata.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1
```

-----

## 1\. Preparation

**Goal:** Set up the hunt by defining what you're looking for.

An employee named John Doe, working in a sensitive department, recently got put on a performance improvement plan (PIP). After John threw a fit, management has raised concerns that John may be planning to steal proprietary information and then quit the company. Your task is to investigate John's activities on his corporate device (`windows-target-1`) using Microsoft Defender for Endpoint (MDE) and ensure nothing suspicious is taking place.

**Activity:** Develop a hypothesis based on threat intelligence and security gaps (e.g., “Could there be lateral movement in the network?”).

**Hypothesis:** John is an administrator on his device and is not limited on which applications he uses. He may try to archive/compress sensitive information and then send it to a private drive or something.

-----

## 2\. Data Collection

**Goal:** Gather relevant data from logs, network traffic, and endpoints.

Consider inspecting process activity as well as the file system for anything that matches the compression or exfiltration of data.

**Activity:** Ensure data is available from all key sources for analysis.

Ensure the relevant tables contain recent logs for your virtual machine:

  * `DeviceFileEvents`
  * `DeviceProcessEvents`
  * `DeviceNetworkEvents`

-----

## 3\. Data Analysis

**Goal:** Analyze data to test your hypothesis.

**Activity:** Look for anomalies, patterns, or indicators of compromise (IOCs) using various tools and techniques.

  * Is there any evidence of anything that resembles company files being archived?
  * If so, can you identify exactly what is happening?
  * If you find something, take note of the timestamp and search the other tables for +/-1 minutes around the same time to see if you can notice anything.
  * Take note of your findings with the corresponding queries below.

-----

## 4\. Investigation

**Goal:** Investigate any suspicious findings.

**Activity:** Dig deeper into detected threats, determine their scope, and escalate if necessary. See if anything you find matches TTPs within the MITRE ATT\&CK Framework.

  * Search the `DeviceProcessEvents` for suspicious archiving tools or commands.
  * Search `DeviceFileEvents` for unusual file creations or modifications, especially related to archives.
  * You can use ChatGPT to figure this out by pasting/uploading the logs: Scenario 4: TTPs

-----

## 5\. Response

**Goal:** Mitigate any confirmed threats.

**Activity:** Work with security teams to contain, remove, and recover from the threat.

  * Can anything be done? (e.g., Isolate the device, suspend the user's account, block outbound connections to suspicious destinations, conduct forensic imaging).

-----

## 6\. Documentation

**Goal:** Record your findings and learn from them.

**Activity:** Document what you found and use it to improve future hunts and defenses.

  * Document what you did.

-----

## 7\. Improvement

**Goal:** Improve your security posture or refine your methods for the next hunt.

**Activity:** Adjust strategies and tools based on what worked or didn’t.

  * Anything we could have done to prevent the thing we hunted for? (e.g., Stricter data loss prevention (DLP) policies, monitoring for sensitive file access, user behavior analytics, restricting admin privileges).
  * Any way we could have improved our hunting process? (e.g., new queries to detect specific archive formats, better correlation of process/file/network events).

-----

## Notes / Findings:

### Timeline Summary and Findings:

We did a search within MDE `DeviceFileEvents` for any activities with zip files, and found a lot of regular activity of archiving stuff and moving to a "backup" folder:

```kusto
DeviceFileEvents
| where DeviceName == "cwav3-test-mde" // Replace with your VM name
| where FileName endswith ".zip"
| order by Timestamp desc
```

I took one of the instances of a zip file being created, took the timestamp and searched under `DeviceProcessEvents` for anything happening 2 minutes before the archive was created and 2 minutes after. I discovered around the same time, a PowerShell script silently installed 7-Zip and then used 7-Zip to zip up employee data into an archive:

```kusto
let VMName = "cwav3-test-mde"; // Replace with your VM name
let specificTime = datetime(2025-06-06T20:54:05.4523205Z); // Replace with your observed timestamp
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```

I searched around the same time period for any evidence of exfiltration from the network, but I didn't see any logs indicating as such:

```kusto
let VMName = "cwav3-test-mde"; // Replace with your VM name
let specificTime = datetime(2025-06-06T20:54:05.4523205Z); // Replace with your observed timestamp
DeviceNetworkEvents
| where Timestamp between ((specificTime - 4m) .. (specificTime + 4m))
| where DeviceName == VMName
| order by Timestamp desc
```

### Response:

I relayed the information to the employee's manager, including everything with the archives being created at regular intervals via PowerShell script. There didn't appear to be any evidence of exfiltration. Standing by for further instructions from management.

### Relevant MITRE ATT\&CK TTPs:

  * **T1070.004 - Indicator Removal on Host: File Deletion**
      * The consistent use of archiving and backing up files might suggest an attempt to obscure or stage the data for later exfiltration while avoiding detection.
  * **T1105 - Ingress Tool Transfer**
      * The silent installation of 7-Zip indicates the download or installation of a tool onto the target system, which aligns with this technique.
  * **T1055.011 - Process Injection: Extra Window Memory Injection**
      * Although no explicit process injection was mentioned, PowerShell-based silent operations often involve process injection techniques to execute payloads without creating new processes.
  * **T1027 - Obfuscated Files or Information**
      * Using scripts to silently install and execute 7-Zip to create ZIP archives might involve obfuscation to avoid detection by traditional security tools.
  * **T1047 - Windows Management Instrumentation**
      * Although not explicitly mentioned, silent installations and script executions on Windows often involve WMI (Windows Management Instrumentation) as a technique to execute and automate processes remotely or locally.

-----

## MDE Tables Referenced:

| **Parameter** | **Description** |
|---|---|
| **Name** | `DeviceFileEvents` |
| **Info** | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| **Purpose** | Used for detecting file compression activities (e.g., creation of `.zip` files) and identifying files being accessed or modified that may contain proprietary information. |

| **Parameter** | **Description** |
|---|---|
| **Name** | `DeviceProcessEvents` |
| **Info** | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Purpose** | Used to identify the processes responsible for archiving data (e.g., `7z.exe`, `powershell.exe` with `Invoke-WebRequest` for tool download) and their command-line arguments. |

| **Parameter** | **Description** |
|---|---|
| **Name** | `DeviceNetworkEvents` |
| **Info** | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
| **Purpose** | Used to detect outbound network connections that could indicate data exfiltration (e.g., connections to cloud storage, personal email services, or suspicious IPs). |

-----

## Detection Queries:

\<details\>
\<summary\>Click to expand sample queries\</summary\>

```kusto
// Look for any kind of archive activity
let archive_applications = dynamic(["winrar.exe", "7z.exe", "winzip32.exe", "peazip.exe", "Bandizip.exe", "UniExtract.exe", "POWERARC.EXE", "IZArc.exe", "AshampooZIP.exe", "FreeArc.exe"]);
let VMName = "windows-target-1"; // Replace with your VM name
DeviceProcessEvents
| where DeviceName == VMName
| where FileName has_any(archive_applications)
| order by Timestamp desc
```

```kusto
// Look for any file activity, based on the Timestamp from any discovered process activity
let specificTime = datetime(2025-06-06T20:54:05.4523205Z); // Replace with your observed timestamp
let VMName = "windows-target-1"; // Replace with your VM name
DeviceFileEvents
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| order by Timestamp desc
```

```kusto
// Look for any network activity, based on the Timestamp from the process or file activity
let VMName = "windows-target-1"; // Replace with your VM name
let specificTime = datetime(2025-06-06T20:54:05.4523205Z); // Replace with your observed timestamp
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
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
| 1.0         | Initial draft | July 20, 2025 | Clive M|
