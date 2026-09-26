# Timeline 

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

