# MySQL Honeypot Investigation: Database Extortion and Incident Response

## Overview

This personal lab investigates suspicious activity against an Azure-hosted Windows virtual machine running MySQL. I reviewed MySQL authentication and query logs alongside Microsoft Defender for Endpoint telemetry to reconstruct the activity, identify indicators of compromise, and assess potential impact.

## Tools and Evidence

* Microsoft Azure virtual machine
* MySQL authentication and query logs
* Microsoft Defender for Endpoint
* Process, file, registry, network, and Windows logon events
* MDE investigation package

## Key Findings

* Identified remote MySQL `root` connections and correlated the later destructive SQL activity with sessions from `64.89.163.94`.
* Observed table-reading queries, recovery-note statements, and commands targeting four databases for deletion.
* Identified a bitcoin payment demand, contact email, reference URL, and DATAID in the logged note.
* Reviewed 28 failed Windows administrator network logons.
* Distinguished local setup and Defender collection activity from potentially malicious behavior.

## Evidence Limitations

The logs establish that destructive SQL commands were received, but do not independently confirm completed deletion or data exfiltration. Successful Windows takeover and file encryption were not established.

I did not retain a pre-incident investigation package from the original VM. I later recreated the setup and collected a baseline from a separate installation. That package provides configuration context, but is not a direct before-and-after snapshot.

Evidence images are rendered excerpts from exported CSV files, not screenshots of the Defender portal. Included KQL hunts are suggested follow-up queries and are not presented as tenant-tested detections.

## Incident Report

[Read the full incident report](incident-report.md)

The report includes an incident timeline, discovered indicators, supporting evidence, response recommendations, and outstanding investigative gaps.

## Skills Demonstrated

Log correlation, authentication analysis, SQL activity investigation, endpoint triage, evidence assessment, and incident documentation.
