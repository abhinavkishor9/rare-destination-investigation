# Troubleshooting Notes — Rare Destination Investigation

## Purpose

This document records the practical issues, investigation decisions, and telemetry limitations encountered during the Rare Destination Investigation.

The purpose is to document not only what worked, but also how the investigation was handled when the available telemetry was incomplete or difficult to correlate.

---

## 1. Sysmon Service Verification

Before collecting network telemetry, the Sysmon service was verified to confirm that the endpoint was actively generating Sysmon events.

Command used:

`Get-Service Sysmon64`

The service was running successfully.

This verification was important because the investigation depended on Sysmon Event ID 3 for network connection data and Sysmon Event ID 1 for process creation data.

If Sysmon had not been running, a lack of events could have been incorrectly interpreted as a lack of endpoint activity.

---

## 2. Large Number of Network Events

The initial Sysmon Event ID 3 query returned a large number of network connection events.

Manually reviewing every event would have made the investigation inefficient and would have made it harder to identify broader destination patterns.

The investigation therefore reduced the dataset in stages:

1. Collect the Event ID 3 network events.
2. Extract destination IP addresses.
3. Group the destinations by frequency.
4. Identify destinations that stand out.
5. Perform a focused search on the selected destination.

This approach made it possible to retain the original network evidence while reducing the amount of data requiring detailed manual review.

---

## 3. Destination IP Extraction

The destination IP address was extracted from the Sysmon Event ID 3 message content.

The extraction used a regular expression similar to:

`DestinationIp:\s+([0-9a-fA-F\.:]+)`

The extracted value was then used for grouping and frequency analysis.

This approach was more reliable than manually copying destination values from individual events and allowed the analysis to be repeated against the collected dataset.

---

## 4. Destination Frequency Analysis

The frequency analysis identified several destinations that appeared repeatedly.

The most frequently observed destination in the collected sample was:

`8.8.8.8`

Observed count:

`269`

The frequency result was useful for selecting an investigation target, but it was not treated as a maliciousness indicator.

A destination can appear frequently because of legitimate system activity, application behavior, background services, DNS-related activity, synchronization, or other expected communications.

Therefore:

> Frequency was treated as a triage signal, not as a verdict.

---

## 5. Why `8.8.8.8` Was Selected

`8.8.8.8` was selected because it had the highest observed frequency in the collected destination sample.

The selection means that the destination stood out enough to justify deeper investigation.

It does not mean that the destination was considered malicious.

The investigation continued by examining individual events associated with the destination and looking for additional context.

---

## 6. Repeated Network Connections

A targeted search for `8.8.8.8` identified multiple network connection events across different timestamps.

Observed timestamps included:

- `06:08:15`
- `06:10:53`
- `06:12:59`
- `06:13:41`
- `06:17:16`
- `06:17:20`
- `06:19:50`
- `06:21:55`
- `06:26:00`

This confirmed that the destination was contacted repeatedly during the observation period.

However, repeated communication alone does not establish whether the traffic was legitimate or malicious.

The next step was therefore to investigate process context.

---

## 7. Process Correlation Challenge

Sysmon Event ID 1 was reviewed to identify process creation events that could potentially be related to the network activity.

The review included processes such as:

- `powershell.exe`
- `cmd.exe`
- `wscript.exe`
- `cscript.exe`
- `rundll32.exe`
- `mshta.exe`

Several process events were available.

The main challenge was that the collected evidence did not provide a reliable direct relationship between a specific process and the connections to `8.8.8.8`.

The investigation therefore did not assign the network activity to a process based only on the fact that the process existed during approximately the same time period.

---

## 8. Avoiding False Temporal Correlation

A process event and a network event occurring close together in time may indicate a possible relationship, but timing alone is not sufficient for attribution.

For example, a PowerShell process starting shortly before a network connection does not automatically prove that PowerShell generated the connection.

A stronger process-to-network correlation would require supporting evidence such as:

- Matching Process ID.
- Process information within the network event.
- Exact timestamps.
- Command-line information.
- Parent-child process relationships.
- Destination port.
- Application context.

Because the available evidence did not establish these relationships, the process attribution remained unresolved.

---

## 9. Wazuh Telemetry Review

Wazuh was reviewed as an additional source of endpoint telemetry.

A Windows process-related event involving `sdbinst.exe` was observed.

The executable path was:

`C:\Windows\System32\sdbinst.exe`

The available record also contained the SHA256 value:

`8F67CBBD8250CEDA1E5DB21DF87AD870576229B8FD729E80F9092EB578B6915`

The Wazuh record demonstrated that centralized endpoint process telemetry was available.

However, the record did not directly connect `sdbinst.exe` to the network activity involving `8.8.8.8`.

The event was therefore treated as supporting endpoint context and not as direct attribution evidence.

---

## 10. Missing Network Evidence in Wazuh

The absence of a specific network event in the available Wazuh data was treated carefully.

Not seeing an event in a centralized platform does not automatically prove that the event never occurred on the endpoint.

Potential reasons for missing telemetry include:

- Collection configuration.
- Event filtering.
- Agent visibility.
- Indexing limitations.
- Retention.
- Timing differences.
- Unsupported event sources.

For this reason, missing Wazuh evidence was documented as a telemetry limitation rather than evidence of non-occurrence.

---

## 11. Evidence Directory

The investigation used a dedicated evidence directory:

`C:\RareDestinationLab\Evidence`

The investigation path was represented using:

`$LabPath = "C:\RareDestinationLab"`

and:

`$EvidencePath = "$LabPath\Evidence"`

Keeping the evidence in a dedicated directory reduced the risk of mixing investigation artifacts with unrelated files on the endpoint.

---

## 12. Evidence Preservation

The collected Sysmon network telemetry was preserved as:

`C:\RareDestinationLab\Evidence\Sysmon-NetworkConnections.txt`

The investigation summary was preserved as:

`C:\RareDestinationLab\Evidence\Investigation-Summary.txt`

Preserving the raw network output was important because the destination-frequency analysis was derived from the original event data.

The raw evidence can be reviewed again if additional fields or different correlations become necessary.

---

## 13. Raw Evidence vs. Derived Analysis

The frequency table is a derived result.

It summarizes the original Event ID 3 records by counting how often each destination appeared.

Derived results are useful for identifying patterns, but they do not replace the raw telemetry.

Keeping both forms of evidence makes it possible to:

- Recalculate the destination counts.
- Review individual events.
- Examine fields that were not used during the first analysis.
- Perform additional correlation.
- Verify the original findings.

---

## 14. Observation vs. Conclusion

The investigation deliberately separated observable facts from conclusions.

For example:

**Observation:** `8.8.8.8` appeared 269 times in the collected destination data.

**Interpretation:** The destination was prominent within the sampled network activity and was selected for deeper investigation.

The following conclusion would not be justified by the frequency count alone:

**Unsupported conclusion:** `8.8.8.8` is malicious because it appeared frequently.

The distinction is important because SOC investigations should remain tied to available evidence rather than assumptions.

---

## 15. Telemetry Limitation

The main limitation of the investigation was process attribution.

The available Sysmon and Wazuh evidence showed network activity and process activity, but it did not establish a sufficiently strong relationship between a specific process and the selected destination.

This limitation was documented rather than hidden.

A good DFIR investigation should clearly state when the available evidence is insufficient to answer a particular question.

---

## 16. Additional Telemetry That Could Help

The investigation could be strengthened with additional telemetry sources.

Potentially useful evidence includes:

- Windows Filtering Platform events.
- Windows Firewall logs.
- DNS query logs.
- Proxy logs.
- Endpoint detection telemetry.
- Process identifiers.
- Command-line data.
- Application-specific logs.
- Network flow data.
- Packet captures.

These sources could help determine which process or application generated the communication and provide additional context around the purpose of the traffic.

---

## 17. Investigation Quality Check

Before finalizing the investigation, the following checks were completed:

- Sysmon service status was verified.
- Network telemetry was collected.
- Raw network evidence was preserved.
- Destination IP addresses were extracted.
- Destination frequency was calculated.
- `8.8.8.8` was selected for focused analysis.
- Multiple connection timestamps were reviewed.
- Process creation telemetry was examined.
- Wazuh telemetry was reviewed.
- Process attribution limitations were documented.
- Unsupported conclusions were avoided.

---

## 18. Final Troubleshooting Lesson

The most important lesson from this investigation was not a failed command or collection problem.

The main challenge was correctly interpreting incomplete correlation.

The telemetry clearly established repeated network activity involving the selected destination. However, the available evidence did not establish which process generated the connections or why the communication occurred.

The appropriate DFIR approach was therefore to preserve the evidence, document the known facts, identify the unresolved questions, and specify what additional telemetry would be required for stronger attribution.

> **A telemetry gap should be documented as a limitation, not filled with an assumption.**
