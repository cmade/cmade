# Threat Hunt Report: Malicious Firefox Extension Installation

**Malicious Firefox Extension Installation and Data Exfiltration Simulation**

---

## Scenario

A recent increase in alerts related to **unusual browser extension installations** or **suspicious outbound connections from web browsers** has been observed by the Security Operations Center (SOC). This could indicate a user inadvertently installing a **malicious Firefox extension**, leading to potential data exfiltration or further compromise.
This hunt aims to identify any such unauthorized or malicious Firefox extension activity within the environment.

---

## High-Level IoC Discovery Plan: Malicious Firefox Extension

1. **DeviceFileEvents**

   * Look for `.xpi` file downloads or creations from unusual sources.
   * Investigate unexpected files (e.g., `firefox_history_dump.txt`) in Firefox profile directories.

2. **DeviceProcessEvents**

   * Identify abnormal `firefox.exe` behavior, such as spawning `cmd.exe` or `powershell.exe`.
   * Look for process command lines referencing `.xpi` files.

3. **DeviceNetworkEvents**

   * Monitor unauthorized outbound connections from `firefox.exe`.
   * Flag connections to suspicious domains (e.g., `exfil-data-c2.com`) or unusual external IPs.

4. **DeviceRegistryEvents**

   * Look for registry modifications that enable persistence mechanisms.

5. **Correlation of Events**

   * Combine multiple indicators for higher confidence (e.g., file creation + process spawn + suspicious outbound connection).

6. **Threat Intelligence**

   * Cross-reference file hashes, domains, and IPs with threat intelligence feeds.

---

## Steps Taken (Simulation in Azure VM)

**Purpose:** Simulate a user tricked into installing a malicious Firefox extension to generate logs and IoCs.

### 1. Download Simulated Malicious Extension

```plaintext
- Download a benign .zip file.
- Rename it to: malicious_firefox_ext.xpi
- Save to: C:\Users\<YourUsername>\Desktop\
```

### 2. Attempt to Install Extension in Firefox

```plaintext
- Drag and drop malicious_firefox_ext.xpi into Firefox.
- Click "Add" (or allow the warning to generate logs).
```

### 3. Simulate Data Exfiltration Network Activity

```plaintext
- In Firefox, visit: http://exfil-data-c2.com/data (nonexistent domain to generate DNS lookup).
```

### 4. Simulate Local Data Access

```plaintext
- Create a file: firefox_history_dump.txt
- Location: C:\Users\<YourUsername>\Desktop\
```

### 5. Clean Up

```plaintext
- Delete malicious_firefox_ext.xpi
- Delete firefox_history_dump.txt
```

---

## Chronological Events (cwav3-stig)

| **Timestamp**                  | **Event**                                      | **Process**    | **Location / Details**                                                       |
| ------------------------------ | ---------------------------------------------- | -------------- | ---------------------------------------------------------------------------- |
| **Jul 17, 2025, 6:13 PM**      | Downloaded/created `malicious_firefox_ext.xpi` | `explorer.exe` | `C:\Users\cwav3\Desktop`                                                     |
| **Jul 17, 2025, 6:22 PM**      | Firefox launched with `.xpi`                   | `firefox.exe`  | `Command Line: firefox.exe C:\Users\cwav3\Desktop\malicious_firefox_ext.xpi` |
| **Jul 17, 2025, 6:23 PM**      | Created `firefox_history_dump.txt`             | `notepad.exe`  | `C:\Users\cwav3\Desktop`                                                     |
| **Jul 17, 2025, 6:25–6:30 PM** | Random files created in Firefox profile        | `firefox.exe`  | `C:\Users\cwav3\AppData\Roaming\Mozilla\Firefox\Profiles\`                   |
| **Jul 17, 2025, 6:41 PM**      | Outbound connection attempt                    | `firefox.exe`  | `192.0.2.1:80` (`exfil-data-c2.com`)                                         |

---

## Summary

This threat hunt successfully simulated a **malicious Firefox extension installation** and its typical behaviors, including file creation, extension installation attempts, and simulated C2 communication.

---

## Response Taken

### **1. Incident Validation & Assessment**

* Verified IoCs (`malicious_firefox_ext.xpi`, `firefox_history_dump.txt`, suspicious outbound IPs).
* Expanded queries across endpoints to scope the incident.

### **2. Containment**

* Isolated `cwav3-stig` via Microsoft Defender for Endpoint.
* Blocked `192.0.2.1` and `exfil-data-c2.com` on firewalls and DNS.

### **3. Eradication**

* Removed suspicious files and reset Firefox profile.
* Scanned endpoint for additional malware.

### **4. Recovery & Hardening**

* Applied patches, updated Firefox, and enforced stricter extension policies.

### **5. Post-Incident**

* Enhanced detection rules in MDE.
* Conducted forensic analysis and user awareness training.

---

## MDE Tables Referenced

| **Table**              | **Purpose**                                            | **Reference**                                                                                      |
| ---------------------- | ------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| `DeviceFileEvents`     | Detects `.xpi` downloads and suspicious file creations | [Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)     |
| `DeviceProcessEvents`  | Identifies Firefox process behavior                    | [Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)  |
| `DeviceNetworkEvents`  | Tracks outbound connections from Firefox               | [Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)  |
| `DeviceRegistryEvents` | Detects persistence attempts via registry              | [Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table) |

---

## Created By

* **Author:** Clive M
* **GitHub:** [cmade](https://github.com/cmade)
* **Date:** July 17, 2025

---

## Revision History

| **Version** | **Changes**   | **Date**     | **Modified By** |
| ----------- | ------------- | ------------ | --------------- |
| 1.0         | Initial draft | Jul 17, 2025 | Clive M         |

