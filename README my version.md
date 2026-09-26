# rare-destination-investigation
## Overview
A rare destination is a remote IP, hostname, or network endpoint that appears infrequently in a host's network telemetry.

The investigation question is:

“Is this destination merely uncommon, or is it suspicious when correlated with the process, port, timing, and other host activity?”

A destination being rare does not automatically mean malicious. For example, Windows Update, Microsoft services, cloud applications, or software updates can legitimately contact destinations that are rarely observed on a particular machine.

Investigation flow:
Network Connections
       ↓
Identify Rare Destination
       ↓
Determine Frequency
       ↓
Identify Process
       ↓
Check Process Creation
       ↓
Correlate Timeline
       ↓
Assess Benign vs Suspicious

This lab investigates unusual network destinations observed on a Windows endpoint using Sysmon network telemetry and supporting Wazuh data.

The investigation begins with a broad set of Sysmon Event ID 3 network connection events. Because a Windows endpoint can generate a large volume of network activity, manually reviewing every connection is inefficient. Destination IP addresses are therefore extracted from the collected events and grouped by frequency to identify communication patterns that deserve closer examination.

The destination `8.8.8.8` was selected for deeper investigation after frequency analysis showed 269 observations in the collected sample. The investigation then examines repeated connections involving the destination and attempts to correlate the network activity with Sysmon Event ID 1 process creation telemetry.

Wazuh telemetry is also reviewed as an additional source of endpoint evidence. Throughout the investigation, unusual activity is treated as an investigative lead rather than automatically classified as malicious.

## Lab Objectives

- Establish a baseline of network destinations observed on a Windows endpoint.
- Identify destinations that stand out based on their occurrence within the collected telemetry.
- Examine repeated connections to a selected destination across multiple timestamps.
- Determine whether the network activity can be associated with a specific process or execution context.
- Compare endpoint network activity with available centralized security telemetry.
- Preserve relevant observations and supporting evidence for later review.
- Document telemetry gaps where available data cannot establish direct attribution.
- Apply an evidence-driven approach that separates unusual behavior from confirmed malicious activity.

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

## Lab Scenario

A Windows endpoint is generating network traffic to multiple external destinations. Most destinations appear only occasionally, while a small number occur repeatedly during the collected monitoring period. The SOC analyst needs to determine whether any destination deserves further investigation based on the available endpoint telemetry.

The investigation begins with Sysmon network connection events and focuses on identifying destination patterns rather than assuming that an unusual IP address is malicious. A destination that appears frequently is selected for deeper analysis, and its activity is examined across different timestamps.

The analyst then attempts to correlate the network connections with endpoint process activity and available Wazuh telemetry. The objective is to determine whether the observed connections can be explained by an identifiable process, application, or expected system behavior.

### Investigation Focus

- Review Windows network connection telemetry.
- Identify destinations that appear repeatedly within the collected data.
- Examine the selected destination across multiple timestamps.
- Correlate network activity with process creation telemetry.
- Review centralized Wazuh data for supporting evidence.
- Identify gaps where the available telemetry does not provide direct attribution.
- Preserve the evidence and document the findings without making assumptions beyond the available data.

The final assessment should distinguish between an **unusual or noteworthy network destination** and **confirmed malicious activity**. Any conclusion must be supported by observable evidence such as destination, port, process, command line, timing, and endpoint context.


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

