# Timeline — Rare Destination Investigation

## Investigation Timeline

| Time | Source | Activity | Significance |
|------|--------|----------|--------------|
| Initial stage | Sysmon | Sysmon service verified | Confirmed that Sysmon telemetry collection was active |
| Initial stage | Sysmon Event ID 1 | Process telemetry collected | Provided process information for later correlation |
| Initial stage | Sysmon Event ID 3 | Network telemetry collected | Established the primary network evidence set |
| Analysis stage | Sysmon Event ID 3 | Destination values extracted | Converted raw network events into analyzable destination data |
| Analysis stage | Sysmon Event ID 3 | Destination frequencies calculated | Identified repeated communication patterns |
| Analysis stage | Sysmon Event ID 3 | `8.8.8.8` identified with 269 observations | Selected as the investigation target |
| `06:08:15` | Sysmon Event ID 3 | Network activity observed | First listed timestamp associated with the selected activity |
| `06:10:53` | Sysmon Event ID 3 | Network activity observed | Demonstrated continued communication |
| `06:12:59` | Sysmon Event ID 3 | Network activity observed | Additional network activity |
| `06:13:41` | Sysmon Event ID 3 | Network activity observed | Repeated communication |
| `06:17:16` | Sysmon Event ID 3 | Network activity observed | Continued activity |
| `06:17:20` | Sysmon Event ID 3 | Network activity observed | Additional activity shortly after the previous event |
| `06:19:50` | Sysmon Event ID 3 | Network activity observed | Continued communication |
| `06:21:55` | Sysmon Event ID 3 | Network activity observed | Additional repeated activity |
| `06:26:00` | Sysmon Event ID 3 | Connection involving `8.8.8.8` | Selected destination directly observed |
| `06:27:08–06:28:00` | Sysmon Event ID 1 | Process creation activity reviewed | Used for possible network-process correlation |
| `06:29:18` | Wazuh | Windows process telemetry observed | Provided supporting endpoint context |
| Final stage | Analyst | Correlation assessment | Direct process attribution not established |
| Final stage | Analyst | Evidence preservation | Investigation artifacts documented |

## Phase 1 — Telemetry Preparation

The investigation began by confirming that Sysmon was running on the Windows endpoint.

This established that the endpoint could provide the Sysmon Event ID 1 and Event ID 3 telemetry required for the investigation.

The analyst then collected process and network telemetry so that the investigation could examine both network activity and possible process context.

## Phase 2 — Network Collection

Sysmon Event ID 3 records were collected and preserved.

The dataset contained numerous network connection events involving several destination IP addresses.

At this stage, the investigation had a broad collection of network observations rather than a single investigation target.

## Phase 3 — Destination Frequency Analysis

Destination IP addresses were extracted from the collected Event ID 3 records and grouped by occurrence.

The analysis produced the following high-frequency destinations:

| Destination | Observed Count |
|-------------|---------------:|
| `8.8.8.8` | 269 |
| `8.8.4.4` | 73 |
| `169.148.149.132` | 70 |
| `172.64.154.50` | 23 |
| `169.148.149.218` | 15 |

`8.8.8.8` was selected for further investigation because it had the highest observed frequency in the sample.

The frequency result was treated as a prioritization signal and not as a maliciousness determination.

## Phase 4 — Targeted Network Review

A focused search was performed for network events involving:

`8.8.8.8`

The review identified activity at multiple timestamps.

The observed sequence included:

- `06:08:15`
- `06:10:53`
- `06:12:59`
- `06:13:41`
- `06:17:16`
- `06:17:20`
- `06:19:50`
- `06:21:55`
- `06:26:00`

The repeated observations demonstrate that the destination was contacted multiple times during the sampled period.

## Phase 5 — Process Correlation

Sysmon Event ID 1 process creation telemetry was reviewed to identify possible relationships between process activity and the network connections.

The review included common execution-related processes such as:

- `powershell.exe`
- `cmd.exe`
- `wscript.exe`
- `cscript.exe`
- `rundll32.exe`
- `mshta.exe`

Process events were available, but the collected evidence did not provide sufficient information to establish direct ownership of the `8.8.8.8` connections.

The process timeline was therefore treated as supporting context rather than confirmed network attribution.

## Phase 6 — Wazuh Review

Wazuh telemetry was reviewed as an additional evidence source.

At approximately `06:29:18`, a Windows process-related event involving:

`sdbinst.exe`

was observed.

The process path was:

`C:\Windows\System32\sdbinst.exe`

The event also contained the SHA256 value:

`8F67CBBD8250CEDA1E5DB21DF87AD870576229B8FD729E80F9092EB578B6915`

The Wazuh observation provided additional endpoint context but did not directly establish that the process generated the investigated network activity.

## Evidence Relationship

The investigation progressed through the following sequence:

**Sysmon Event ID 3 → Destination Extraction → Frequency Analysis → `8.8.8.8` Selected → Targeted Network Review → Sysmon Event ID 1 Correlation → Wazuh Review → Evidence Assessment**

Each stage narrowed the investigation while retaining the distinction between observed activity and confirmed attribution.

## Confirmed Timeline Facts

The timeline supports the following observations:

- Sysmon was active.
- Network connection telemetry was available.
- Multiple destination IP addresses were observed.
- `8.8.8.8` had 269 observations in the analyzed sample.
- Connections involving the destination occurred at multiple timestamps.
- Process creation telemetry was available.
- Wazuh provided additional process telemetry.
- Direct process attribution to the network activity was not established.

## Timeline Limitations

The timeline does not establish:

- The process responsible for the network connections.
- The application responsible for the communication.
- The purpose of the connections.
- Whether the communication was expected.
- Whether the activity was malicious.

These limitations should remain part of the final investigative record.

## Final Timeline Assessment

The collected timeline demonstrates repeated network activity involving `8.8.8.8` during the observation period.

The investigation successfully moved from broad endpoint telemetry to a focused destination review and then to process and centralized telemetry correlation.

The available evidence does not independently establish malicious behavior or direct process ownership. Additional network, process, DNS, firewall, proxy, or application telemetry would be required for stronger attribution.
