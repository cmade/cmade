# Threat Hunt Report: Potential Impossible Travel

## Detection of Unusual User Logon Behavior

## Explanation

Sometimes corporations have policies against working outside of designated geographic regions, account sharing (this should be standard), or use of non-corporate VPNs. The following scenario will be used to detect unusual logon behavior by creating an incident if a user's login patterns are too erratic. “Too erratic” can be defined as logging in from multiple geographic regions within a given time period.

Whenever a user logs into Azure or authenticates with their main Azure account, logs will be created in the “SigninLogs” table, which is being forwarded to the Log Analytics Workspace being used by Microsoft Sentinel, our SIEM. Within Sentinel, we will define an alert to trigger whenever a user logs into more than one location in a 7 day time period. Not all triggers will be true positives, but it will give us a chance to investigate.

In order to generate the necessary logs for you to detect this activity, simply create a new VM if you don’t already have one, log into it, and then log into azure ([https://portal.azure.com](https://portal.azure.com)) from within your VM. This will trigger a new logon event in some random city on the East Coast (east us 2) somewhere.

-----

## High-Level IoC Discovery Plan:

1.  Identify user logon events from the `SigninLogs` table.
2.  Group logons by user and geographic location.
3.  Detect instances where a single user logs in from multiple distinct geographic regions within a defined timeframe.

-----

## Steps Taken

### Part 1: Create Alert Rule (Potential Impossible Travel)

Design a Sentinel Scheduled Query Rule within Log Analytics that will discover when a user logs in to more than a certain number of locations within a given time period; for example, trigger if a user logs into 2 different geographic regions within a 7 day time period. (ensure the appropriate logs show up before creating the alert rule)

**Hint:** Use the `SigninLogs` table.

**KQL Query:**

```kusto
// Locate Instances of Potential Impossible Travel
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```

Once your query is good, create the Schedule Query Rule in: **Sentinel → Analytics → Schedule Query Rule**

**Analytics Rule Settings:**

  * **Name:** `Potential Impossible Travel`
  * **Description:** `Detects unusual logon behavior where a user logs in from multiple distinct geographic regions within a defined timeframe, potentially indicating compromised credentials or policy violation.`
  * **Enable the Rule:** Yes
  * **MITRE ATT\&CK Framework Categories (using ChatGPT for analysis):**
      * **TA0001: Initial Access**
      * **T1078: Valid Accounts**
      * **T1133: External Remote Services** (if external VPNs are involved)
      * **T1534: Event Triggered Execution** (if logs from login events are seen as a trigger)
  * **Run query every:** `4 hours`
  * **Lookup data for last:** `5 hours` (can define in query)
  * **Stop running query after alert is generated:** `Yes`
  * **Configure Entity Mappings:**
      * **Account:** Identifier: `AadUserId`, Value: `UserId`
      * **Account:** Identifier: `DisplayName`, Value: `UserPrincipalName`
  * **Automatically create an Incident if the rule is triggered:** Yes
  * **Group all alerts into a single Incident per:** `24 hours`
  * **Stop running query after alert is generated:** `24 hours`

### Part 2: Trigger Alert to Create Incident

**Reminder:** In order to generate the necessary logs for you to detect this activity, simply create a new VM if you don’t already have one, log into it, and then log into azure ([https://portal.azure.com](https://portal.azure.com)) from within your VM. This will trigger a new logon event in some random city on the East Coast (east us 2) somewhere.

**Don’t get confused between the [Configuration → Analytics] and [Threat Management → Incidents] sections.**

### Part 3: Work Incident

Work your incident to completion and close it out, in accordance with the **NIST 800-61: Incident Response Lifecycle**.

#### Preparation

  * Documented roles, responsibilities, and procedures.
  * Ensured tools, systems, and training were in place.

#### Detection and Analysis

  * Identified and validated the incident.

  * Observed the incident and assigned it to myself, setting the status to Active.

  * Investigated the Incident via **Actions → Investigate** (sometimes takes time for entities to appear).

  * Gathered relevant evidence and assessed impact.

  * Observed the output from the analytics rule and noted which accounts triggered the Impossible Travel alert.

  * Investigated each individual account using a KQL query to see exactly where they have been logging into and made a judgment on whether they are false or true positives. For example, if the user logged into two neighboring cities within a reasonable amount of time, this would be a false positive. However, if someone has logged into Thailand, then Seattle, then Thailand all within 12 hours, this would be suspect.

    **KQL Analysis Query:**

    ```kusto
    // Investigate Potential Impossible Travel Instances
    let TargetUserPrincipalName = "josh.madakor@gmail.com"; // Change to your target user (UserPrincipalName)
    let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
    SigninLogs
    | where TimeGenerated > ago(TimePeriodThreshold)
    | where UserPrincipalName == TargetUserPrincipalName
    | project TimeGenerated, UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
    | order by TimeGenerated desc
    ```

  * Observed the different Users (`UserPrincipalNames`) logon patterns and took notes:

      * `josh.madakor@gmail.com` logged in from X and Y within Z time period: suspect
      * `arisa_lognpacific@lognpacific.com` logged in from A and B within C time period: normal
      * (and so on for other relevant accounts)

#### Containment, Eradication, and Recovery

  * Isolated affected systems to prevent further damage.

      * In real life, depending on corporate policy and evidence, the account might be immediately disabled in Entra ID (Azure Active Directory) and the user or the user’s manager contacted to investigate.

  * It was determined that the alert was a **TRUE POSITIVE**. User `cwav3` logged into `Kenya` and `USA` within an `24` day time period, which should not be possible.

  * The user's account was disabled and management was contacted.

  * Removed the threat and restored systems to normal.

      * There is currently no threat to remove; further action may be taken pending a decision from management.
      * If the logon behavior was unusual, account compromise may be possible.
      * Pivoted to see what other activity the user has been doing. For example, by looking in the AzureActivity log:

    <!-- end list -->

    ```kusto
    AzureActivity
    | where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "<azure user id/guid>"
    ```

#### Post-Incident Activities

  * Updated policies and tools to prevent recurrence.
      * Could consider creating a geo-fencing policy within Azure that prevents logins outside of certain regions (not feasible in this lab environment but a real-world consideration).
  * Documented findings and lessons learned within the incident notes.

#### Closure

  * Reviewed and confirmed incident resolution.
  * Reviewed/observed notes for the incident.
  * Finalized reporting and closed the case.
  * Closed out the Incident within Sentinel as a “Benign Positive” (or whatever the final determination was).

### Part 4: Cleanup (BE EXTREMELY CAREFUL HERE)

In **Sentinel → Threat Management → Incidents**, filtered for closed incidents and deleted **YOUR** incident.
In **Sentinel → Configuration → Analytics**, deleted **YOUR** analytics rule.

**Be extremely careful to only delete YOUR Incident and Analytics Rule. Do not screw this up and delete someone else's, because it’s possible. Search by your name to narrow them down if you have to.**

-----

## MDE Tables Referenced:

| **Parameter** | **Description** |
|---|---|
| **Name** | `SigninLogs` |
| **Info** | [https://learn.microsoft.com/en-us/azure/sentinel/connect-azure-active-directory\#data-connectors](https://www.google.com/search?q=https://learn.microsoft.com/en-us/azure/sentinel/connect-azure-active-directory%23data-connectors) (General info on AAD SigninLogs in Sentinel) |
| **Purpose** | Used to analyze user logon events, including geographic location details, to detect unusual patterns indicative of impossible travel. |

-----

## Detection Queries:

```kusto
// Locate Instances of Potential Impossible Travel
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```

```kusto
// Investigate Potential Impossible Travel Instances
let TargetUserPrincipalName = "josh.madakor@gmail.com"; // Change to your target user (UserPrincipalName)
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == TargetUserPrincipalName
| project TimeGenerated, UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
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
| 1.0         | Initial draft | July 20, 2025 | Clive M |
