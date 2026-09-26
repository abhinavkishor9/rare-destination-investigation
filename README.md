# Rare Destination Investigation

## Overview

This lab investigates unusual network destinations observed on a Windows endpoint using Sysmon network telemetry and supporting Wazuh data.

The investigation begins with a broad set of Sysmon Event ID 3 network connection events. Because a Windows endpoint can generate a large volume of network activity, manually reviewing every connection is inefficient. Destination IP addresses are therefore extracted from the collected events and grouped by frequency to identify communication patterns that deserve closer examination.

The destination `8.8.8.8` was selected for deeper investigation after frequency analysis showed 269 observations in the collected sample. The investigation then examines repeated connections involving the destination and attempts to correlate the network activity with Sysmon Event ID 1 process creation telemetry.

Wazuh telemetry is also reviewed as an additional source of endpoint evidence. Throughout the investigation, unusual activity is treated as an investigative lead rather than automatically classified as malicious.

## Lab Objectives

- Collect and preserve Sysmon network connection telemetry.
- Extract destination IP addresses from Event ID 3 events.
- Perform destination-frequency analysis.
- Identify a destination requiring further investigation.
- Review repeated connections to the selected destination.
- Correlate network activity with process creation telemetry.
- Review supporting Wazuh endpoint telemetry.
- Identify evidence gaps and correlation limitations.
- Document findings using an evidence-driven approach.
- Map relevant investigative activity to MITRE ATT&CK techniques where appropriate.

## Environment

| Component | Details |
|-----------|---------|
| Operating System | Windows 11 Pro |
| Hostname | `DESKTOP-9MMM37V` |
| PowerShell | `7.6.6` |
| Sysmon | Running |
| Wazuh Agent | `001` |
| Network Telemetry | Sysmon Event ID 3 |
| Process Telemetry | Sysmon Event ID 1 |
| Centralized Telemetry | Wazuh |

## Scenario

A Windows endpoint is generating network connections to multiple external destinations. Some destinations appear only a few times, while others occur repeatedly during the observation period.

The analyst needs to reduce the large network dataset into a smaller number of destinations that can be investigated efficiently. Destination-frequency analysis is used as the first filtering mechanism.

The analysis identified `8.8.8.8` as the most frequently observed destination in the collected sample, with 269 observations.

This frequency makes the destination noteworthy within the dataset, but it does not establish that the communication is suspicious or malicious. The investigation therefore continues with targeted event review and process correlation.

## Investigation Workflow

### 1. Verify Sysmon

The analyst confirms that the Sysmon service is running before relying on Sysmon Event ID 1 and Event ID 3 telemetry.

### 2. Collect Network Telemetry

Sysmon Event ID 3 network connection records are collected from the endpoint and preserved as evidence.

### 3. Extract Destinations

Destination IP addresses are extracted from the collected Event ID 3 messages.

### 4. Analyze Frequency

The extracted destination values are grouped and counted to identify repeated communication patterns.

### 5. Select an Investigation Target

`8.8.8.8` is selected because it has the highest observed frequency in the collected sample.

### 6. Perform Targeted Review

Network events involving the selected destination are reviewed across multiple timestamps.

### 7. Review Process Activity

Sysmon Event ID 1 process creation telemetry is examined to determine whether the network activity can be linked to a specific process or execution context.

### 8. Review Wazuh

Available Wazuh telemetry is reviewed for additional endpoint evidence that may support or challenge the observations.

### 9. Document the Assessment

Confirmed findings, unresolved questions, and telemetry limitations are recorded without making unsupported assumptions.

## Destination Frequency

The collected destination analysis produced the following results:

| Destination | Observed Count |
|-------------|---------------:|
| `8.8.8.8` | 269 |
| `8.8.4.4` | 73 |
| `169.148.149.132` | 70 |
| `172.64.154.50` | 23 |
| `169.148.148.118` | 16 |
| `169.148.149.218` | 15 |
| `169.148.148.221` | 14 |
| `169.148.146.108` | 7 |
| `18.155.33.82` | 5 |
| `184.26.54.200` | 4 |

The counts represent the collected investigation sample. They are not threat scores, reputation values, or indicators of maliciousness by themselves.

## Selected Destination

The selected destination was:

`8.8.8.8`

The targeted review showed repeated network activity at multiple timestamps, including:

- `06:08:15`
- `06:10:53`
- `06:12:59`
- `06:13:41`
- `06:17:16`
- `06:17:20`
- `06:19:50`
- `06:21:55`
- `06:26:00`

The multiple observations confirm recurring communication involving the destination during the sampled period.

## Process Correlation

Sysmon Event ID 1 was reviewed to identify process creation activity around the network activity.

The review included processes such as:

- `powershell.exe`
- `cmd.exe`
- `wscript.exe`
- `cscript.exe`
- `rundll32.exe`
- `mshta.exe`

Process telemetry was available, but the collected evidence did not directly establish which process generated the connections to `8.8.8.8`.

Timestamp proximity alone was not treated as sufficient for process attribution.

A stronger correlation would require additional evidence such as process ID, network-event process information, command line, destination port, parent-child process relationships, or application context.

## Wazuh Review

Wazuh telemetry was reviewed as a secondary endpoint evidence source.

A Windows process-related record for:

`sdbinst.exe`

was observed with the path:

`C:\Windows\System32\sdbinst.exe`

The record also contained the SHA256 value:

`8F67CBBD8250CEDA1E5DB21DF87AD870576229B8FD729E80F9092EB578B6915`

This demonstrated that Wazuh was receiving Windows endpoint process telemetry.

However, the available Wazuh event did not directly connect `sdbinst.exe` to the investigated `8.8.8.8` network activity.

## MITRE ATT&CK Mapping

This investigation can be mapped to relevant MITRE ATT&CK techniques based on the type of endpoint activity being examined.

### T1049 — System Network Connections Discovery

The investigation analyzes network connection information from the Windows endpoint, including destination IP addresses and repeated communication patterns.

This aligns with the broader ATT&CK concept of examining system network connections to understand active or established network relationships.

The mapping represents the investigative behavior and telemetry being analyzed; it does not imply that a malicious actor performed the technique on the endpoint.

### T1057 — Process Discovery

The investigation reviews process creation telemetry from Sysmon Event ID 1 to identify processes that may provide context for observed network activity.

Process information is used for correlation rather than as standalone evidence of malicious behavior.

### ATT&CK Interpretation

MITRE ATT&CK is used here as an investigation and documentation framework.

The technique mappings describe the type of endpoint evidence being examined. They should not be interpreted as confirmation that any mapped technique was successfully used by an attacker.

## Evidence

Investigation artifacts were stored under:

`C:\RareDestinationLab\Evidence`

Primary artifacts included:

- `Sysmon-NetworkConnections.txt`
- `Investigation-Summary.txt`

The raw network output was preserved so that individual events could be reviewed again after the destination-frequency analysis.

## Key Findings

- Sysmon was running and providing endpoint telemetry.
- Sysmon Event ID 3 contained multiple network connection events.
- Several destination IP addresses were observed repeatedly.
- `8.8.8.8` was the most frequently observed destination in the collected sample.
- `8.8.8.8` appeared 269 times in the analyzed data.
- Multiple timestamps showed repeated communication involving the destination.
- Sysmon Event ID 1 provided process creation telemetry for correlation.
- Available evidence did not establish direct process attribution.
- Wazuh provided additional endpoint process telemetry.
- The available Wazuh data did not directly connect `sdbinst.exe` to the investigated destination.

## Assessment

The investigation confirms repeated network activity involving `8.8.8.8` and identifies the destination as the most frequently observed destination in the collected sample.

The available evidence does not establish malicious activity or identify a responsible process with sufficient confidence.

Additional evidence such as process IDs, destination ports, command lines, DNS information, application context, firewall logs, proxy logs, or packet-level telemetry could provide stronger correlation.

## Investigation Principle

The central lesson of this lab is:

**An unusual network destination is an investigative lead, not a conclusion.**

A frequency-based anomaly should lead to deeper investigation rather than immediate classification.

The investigative progression is:

**Destination → Frequency → Repeated Activity → Process Correlation → Context → Assessment**

The analyst should clearly separate what the telemetry confirms from what remains unknown.

