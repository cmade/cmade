# Threat Hunt Report: Exposed VM Brute-Force Monitoring

## Detection of Brute-Force Attempts on Exposed VMs

## Scenario Overview:

During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.

-----

## High-Level Brute-Force Related IoC Discovery Plan:

1.  Check `DeviceInfo` for internet-facing VMs.
2.  Check `DeviceLogonEvents` for failed login attempts from external IPs.
3.  Check `DeviceLogonEvents` for successful logins following multiple failed attempts from external IPs.

-----

## Steps Taken

1.  Identified internet-facing VMs within the shared services cluster.
2.  Queried `DeviceLogonEvents` to identify failed login attempts on exposed VMs, focusing on remote IP addresses.
3.  Analyzed the failed login attempts for patterns indicative of brute-force attacks (e.g., high volume from single/multiple IPs).
4.  Cross-referenced failed login attempts with successful logons to identify potential brute-force successes.
5.  Investigated legitimate logon activity to differentiate from malicious attempts.

-----

## Chronological Events

1.  **June 3, 2025, 19:49:45 UTC:** `windows-target-1` was detected as internet-facing.
2.  **Throughout June/July 2025:** Numerous failed login attempts from various external IP addresses were observed targeting `windows-target-1`.
3.  **Throughout June/July 2025:** Analysis of top failed login attempt IP addresses revealed no successful logons from those specific IPs.
4.  **Throughout June/July 2025:** Legitimate `labuser` account showed only two successful network logons, with zero failed attempts, confirming no brute-force targeting of this specific account.

-----

## Summary

The threat hunt focused on identifying VMs mistakenly exposed to the public internet and detecting brute-force login attempts. `windows-target-1` was confirmed as internet-facing. While significant brute-force attempts from multiple external IP addresses were observed, **there is no evidence of any successful brute-force access or unauthorized logins** to `windows-target-1` from the analyzed failed login sources during the observed period. Legitimate access by the `labuser` account was verified and showed no signs of compromise.

-----

## Response Taken

While no successful brute-force attacks were identified on `windows-target-1`, the device's internet exposure and the presence of numerous brute-force attempts highlight a security misconfiguration. Recommendations were made to restrict public internet access to the VM and implement stronger account lockout policies.

-----

## MDE Tables Referenced:

| **Parameter** | **Description** |
|---|---|
| **Name** | `DeviceInfo` |
| **Info** | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table) |
| **Purpose** | Used to identify devices that are internet-facing. |

| **Parameter** | **Description** |
|---|---|
| **Name** | `DeviceLogonEvents` |
| **Info** | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table) |
| **Purpose** | Used to detect both failed and successful login attempts, identify source IP addresses, and analyze logon types. |

-----

## Detection Queries:

```kusto
// Check most failed logons
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts desc
```

```kusto
// Take the top X IPs with the most logon failures and see if any succeeded to logon
// REPLACE "RemoteIPsInQuestion" with IPs from your initial failed logons query
let RemoteIPsInQuestion = dynamic(["119.42.115.235","183.81.169.238", "74.39.190.50", "121.30.214.172", "83.222.191.62", "45.41.204.12", "192.109.240.116"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
| project Timestamp, DeviceName, RemoteIP, AccountName, LogonType, ActionType
| order by Timestamp desc
```

```kusto
// Look for any remote IP addresses who have had both successful and failed logons
// Investigate for potential brute force successes
let FailedLogons = DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize FailedLogonAttempts = count() by ActionType, RemoteIP, DeviceName;
let SuccessfulLogons = DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| summarize SuccessfulLogons = count() by ActionType, RemoteIP, DeviceName, AccountName;
FailedLogons
| join kind=inner SuccessfulLogons on RemoteIP
| project RemoteIP, DeviceName, FailedLogonAttempts, SuccessfulLogons, AccountName
| order by FailedLogonAttempts desc
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

  * **Relevant MITRE ATT\&CK TTPs:**
      * **T1190: Exploit Public-Facing Application**
      * **T1078: Valid Accounts**
      * **T1110: Brute Force**
      * **T1587.001: Develop Capabilities: Exploit Code**

-----

## Revision History:

| **Version** | **Changes** | **Date** | **Modified By** |
| :---------- | :---------- | :------- | :-------------- |
| 1.0         | Initial draft | July 20, 2025 | Clive M |
