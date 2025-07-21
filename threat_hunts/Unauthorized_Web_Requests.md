# Threat Hunt Report: Unauthorized PowerShell Web Requests

## Detection of Suspicious PowerShell `Invoke-WebRequest` Activity

## Explanation

Sometimes when a bad actor has access to a system, they will attempt to download malicious payloads or tools directly from the internet to expand their control or establish persistence. This is often achieved using legitimate system utilities like PowerShell to blend in with normal activity. By leveraging commands such as `Invoke-WebRequest`, they can download files or scripts from an external server and immediately execute them, bypassing traditional defenses or detection mechanisms. This tactic is a hallmark of post-exploitation activity, enabling them to deploy malware, exfiltrate data, or establish communication channels with a command-and-control (C2) server. Detecting this behavior is critical to identifying and disrupting an ongoing attack.

When processes are executed/run on the local VM, logs will be forwarded to Microsoft Defender for Endpoint under the `DeviceProcessEvents` table. These logs are then forwarded to the Log Analytics Workspace being used by Microsoft Sentinel, our SIEM. Within Sentinel, we will define an alert to trigger when PowerShell is used to download a remote file from the internet.

-----

## High-Level IoC Discovery Plan:

1.  Identify PowerShell process events.
2.  Filter for `Invoke-WebRequest` command-line arguments.
3.  Analyze the source URLs for remote file downloads.

-----

## Steps Taken

### Part 1: Create Alert Rule (PowerShell Suspicious Web Request)

Design a Sentinel Scheduled Query Rule within Log Analytics that will discover when PowerShell is detected using `Invoke-WebRequest` to download content.

**Hint:** Use the `DeviceProcessEvents` table.

**KQL Query:**

```kusto
let TargetHostname = "windows-target-1"; // Replace with the name of your VM as it shows up in the logs
DeviceProcessEvents
| where DeviceName == TargetHostname //comment this line out for MORE results
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated
```

Once the query is validated, create the Scheduled Query Rule in: **Sentinel → Analytics → Schedule Query Rule**

**Analytics Rule Settings:**

  * **Name:** `PowerShell Suspicious Web Request`
  * **Description:** `Detects PowerShell using Invoke-WebRequest to download remote content, indicative of potential post-exploitation activity.`
  * **Enable the Rule:** Yes
  * **MITRE ATT\&CK Framework Categories (using ChatGPT for analysis):**
      * **TA0002: Execution**
      * **T1059.001: PowerShell**
      * **T1105: Ingress Tool Transfer**
      * **T1071.001: Application Layer Protocol: Web Protocols**
  * **Run query every:** `4 hours`
  * **Lookup data for last:** `24 hours`
  * **Stop running query after alert is generated:** `Yes`
  * **Configure Entity Mappings:**
      * **Account:** Identifier: `Name`, Value: `AccountName`
      * **Host:** Identifier: `HostName`, Value: `DeviceName`
      * **Process:** Identifier: `CommandLine`, Value: `ProcessCommandLine`
  * **Automatically create an Incident if the rule is triggered:** Yes
  * **Group all alerts into a single Incident per:** `24 hours`
  * **Stop running query after alert is generated:** `24 hours`

### Part 2: Trigger Alert to Create Incident

**Note:** If your VM is onboarded to MDE and has been running for several hours, the attack simulator will have done the actions necessary to create the logs. If not, you can paste the following into PowerShell on your VM to create the necessary logs:

```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1' -OutFile 'C:\programdata\eicar.ps1';
powershell.exe -ExecutionPolicy Bypass -File 'C:\programdata\eicar.ps1';
```

**Don’t get confused between the [Configuration → Analytics] and [Threat Management → Incidents] sections.**

### Part 3: Work Incident

Work your incident to completion and close it out, in accordance with the **NIST 800-61: Incident Response Lifecycle**.

#### Preparation

  * Documented roles, responsibilities, and procedures.
  * Ensured tools, systems, and training were in place.

#### Detection and Analysis

  * Identified and validated the incident.

  * Observed the incident and assigned it to myself, setting the status to Active.

  * Investigated the Incident via **Actions → Investigate**.

  * Gathered relevant evidence and assessed impact. In this case, the actual script files would be evidence, but the primary threat is how they got there or why the user (or system account) downloaded and executed them. In a real-world scenario, this could result from accidental malware downloads or installing compromised software.

      * **Notes:** For the lab, we'll assume the user unknowingly installed free software, triggering these events. (In reality, the attack simulator downloaded and executed these scripts.)

  * Observed and noted the different entity mappings:

      * The `Cwav3 PowerShell Suspicious Web Request` incident was triggered on **1** different Device by **1** different user.
          * **Devices:** `cwav3-test-mde`
          * **Users:** `cwav3`
      * The PowerShell commands downloaded **1** different script from the internet:
          * URL to Script 1: `https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1`
          * The following script contained: `eicar.ps1`

  * Checked to ensure none of the downloaded scripts were actually executed (or noted if they were):

    **KQL Query:**

    ```kusto
    let TargetHostname = "windows-target-1"; // Replace with the name of your VM as it shows up in the logs
    let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]); // Add the name of the scripts that were downloaded
    DeviceProcessEvents
    | where DeviceName == TargetHostname // Comment this line out for MORE results
    | where FileName == "powershell.exe"
    | where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
    | order by TimeGenerated
    | project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
    ```

      * It was observed that after being downloaded, the `eicar.ps1` script was subsequently executed by the `cwav3` account.
      * Script `eicar.ps1` was observed to `simulate a test virus detection by antivirus software.`

#### Containment, Eradication, and Recovery

  * Isolated affected systems to prevent further damage. In a real-life scenario, `cwav3-test-mde` would be isolated with Defender for Endpoint.
  * Machine was isolated in MDE and an anti-malware scan was run.
  * If any of the downloaded files had been executed, their purpose would be discerned using tools like ChatGPT, and findings would be recorded.
  * Removed the threat and restored systems to normal. While the machine was isolated, an antimalware scan was performed in MDE to check for anything that might have caused these scripts to be downloaded and run.

#### Post-Incident Activities

  * Documented findings and lessons learned within the incident notes.
  * Considered updating policies and tools to prevent recurrence, such as restricting PowerShell usage.

#### Closure

  * Reviewed and confirmed incident resolution.
  * Reviewed/observed notes for the incident.
  * Finalized reporting and closed the case.
  * Closed out the Incident within Sentinel as a “True Positive”.

### Part 4: Cleanup (BE EXTREMELY CAREFUL HERE)

In **Sentinel → Threat Management → Incidents**, filtered for closed incidents and deleted **YOUR** incident.
In **Sentinel → Configuration → Analytics**, deleted **YOUR** analytics rule.

**Be extremely careful to only delete YOUR Incident and Analytics Rule. Do not screw this up and delete someone else's, because it’s possible. Search by your name to narrow them down if you have to.**

-----

## MDE Tables Referenced:

| **Parameter** | **Description** |
|---|---|
| **Name** | `DeviceProcessEvents` |
| **Info** | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table) |
| **Purpose** | Used to detect PowerShell process launches, including the use of `Invoke-WebRequest` for downloading content, and the execution of downloaded scripts. |

-----

## Detection Queries:

```kusto
// Highlight to show query 👇
let TargetHostname = "windows-target-1"; // Replace with the name of your VM as it shows up in the logs
DeviceProcessEvents
| where DeviceName == TargetHostname //comment this line out for MORE results
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated
```

```kusto
// Highlight to show query 👇
let TargetHostname = "windows-target-1"; // Replace with the name of your VM as it shows up in the logs
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]); // Add the name of the scripts that were downloaded
DeviceProcessEvents
| where DeviceName == TargetHostname // Comment this line out for MORE results
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```

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
| 1.0 | Initial draft | July 20, 2025 | Clive M |
