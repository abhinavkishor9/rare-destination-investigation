# Investigation Notes — Rare Destination Investigation

## Investigation Focus

This investigation focused on network destinations recorded by Sysmon Event ID 3 on a Windows endpoint.

The initial telemetry contained a large number of network connection events involving multiple destinations. To make the dataset easier to investigate, destination IP addresses were extracted and grouped according to their observed frequency.

The destination with the highest frequency was then selected for targeted analysis. The investigation continued by reviewing repeated connections, process creation telemetry, and available Wazuh data.

The investigation maintained a distinction between confirmed observations and assumptions. A destination was not considered malicious simply because it appeared frequently.

## Host Information

| Field | Value |
|-------|-------|
| Hostname | `DESKTOP-9MMM37V` |
| Operating System | Windows 11 Pro |
| PowerShell | `7.6.6` |
| Sysmon | Running |
| Wazuh Agent | `001` |

## Initial Network Collection

Sysmon Event ID 3 was used to collect network connection telemetry from the Windows endpoint.

The collected records contained information associated with network activity, including destination values that could be extracted and analyzed.

The raw output was preserved as:

`C:\RareDestinationLab\Evidence\Sysmon-NetworkConnections.txt`

Preserving the raw data was important because the frequency analysis was derived from this original event set.

## Destination Extraction

Destination IP addresses were extracted from the Sysmon Event ID 3 message content.

A pattern similar to the following was used:

    if ($_.Message -match "DestinationIp:\s+([0-9a-fA-F\.:]+)") {
        $Matches[1]
    }

The extracted destination values were then grouped and counted.

This allowed the investigation to move from individual network events to a destination-level summary.

## Frequency Analysis

The resulting destination counts included:

| Destination | Count |
|-------------|------:|
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

`8.8.8.8` was selected for further investigation because it appeared most frequently within the analyzed sample.

The selection was based on observed frequency and did not represent a determination that the destination was malicious.

## Targeted Destination Review

A focused search was performed for:

`8.8.8.8`

Multiple network events were identified.

Examples of observed timestamps included:

- `06:08:15`
- `06:10:53`
- `06:12:59`
- `06:13:41`
- `06:17:16`
- `06:17:20`
- `06:19:50`
- `06:21:55`
- `06:26:00`

The repeated timestamps show that the destination was contacted at multiple points during the observation period.

This established recurring communication but did not establish why the communication occurred.

## Process Correlation

Sysmon Event ID 1 was reviewed to identify process creation activity around the network observations.

The review included:

- `powershell.exe`
- `cmd.exe`
- `wscript.exe`
- `cscript.exe`
- `rundll32.exe`
- `mshta.exe`

The purpose of this step was to determine whether a process could be reliably associated with the network activity.

Multiple process creation events were available, but the collected evidence did not directly establish that any specific process initiated the connections to `8.8.8.8`.

## Correlation Limitation

The investigation did not treat simple timestamp overlap as proof of attribution.

For example, a process created shortly before a network connection may be relevant, but additional evidence is required before establishing that the process generated the traffic.

Useful correlation fields would include:

- Process ID
- Destination port
- Source port
- Command line
- Parent process
- Network-event process information
- Exact event timestamps
- User context
- Application context

These fields were not sufficiently available in the collected evidence to establish direct attribution.

## Wazuh Review

Wazuh was reviewed as an additional endpoint telemetry source.

A process-related Wazuh record was observed for:

`sdbinst.exe`

The available record included:

`C:\Windows\System32\sdbinst.exe`

and the SHA256 value:

`8F67CBBD8250CEDA1E5DB21DF87AD870576229B8FD729E80F9092EB578B6915`

The Wazuh event provided additional endpoint visibility, but it did not directly associate `sdbinst.exe` with the `8.8.8.8` network activity.

The event was therefore treated as contextual evidence rather than direct network attribution.

## Confirmed Evidence

The following points were supported by the collected telemetry:

- Sysmon was running.
- Sysmon Event ID 3 network telemetry was available.
- Multiple destination IP addresses were present.
- `8.8.8.8` appeared 269 times in the collected sample.
- Multiple network events involving `8.8.8.8` were identified.
- Sysmon Event ID 1 process telemetry was available.
- Wazuh contained Windows process telemetry.

## Unresolved Questions

The investigation did not establish:

- Which process generated the connections to `8.8.8.8`.
- Which application was responsible for the traffic.
- Why the endpoint communicated with the destination.
- Whether the activity was user-driven or system-generated.
- Whether the communication was expected for the endpoint.
- Whether the activity had malicious intent.

These questions remain dependent on additional telemetry.

## Evidence Preservation

The investigation artifacts were stored under:

`C:\RareDestinationLab\Evidence`

Primary files included:

- `Sysmon-NetworkConnections.txt`
- `Investigation-Summary.txt`

The raw telemetry was retained so that the investigation could be reproduced and individual events could be reviewed later.

## Current Assessment

The investigation confirms repeated network communication involving `8.8.8.8` and identifies the destination as the most frequently observed destination in the collected dataset.

The available evidence does not provide sufficient support for direct process attribution or a definitive malicious classification.

The most defensible result is therefore to document the repeated activity, preserve the evidence, identify the unresolved correlation, and continue investigation if additional telemetry becomes available.
