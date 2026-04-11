# Sigma Rules Sync and Gap Report

Date: 2026-04-11

## What Was Done

1. Reorganized local Windows Sigma rules into a management-friendly EVTX hierarchy:
   - `data/sigma_rules/windows/evtx/...`
2. Moved existing local security rules into:
   - `data/sigma_rules/windows/evtx/security/...`
3. Synced missing built-in Windows EVTX rules from SigmaHQ:
   - Source: `sigma/rules/windows/builtin/...`
   - Destination: `data/sigma_rules/windows/evtx/...`

## Current Local Coverage

- Local Windows Sigma rules: **324**
- SigmaHQ built-in Windows rules imported: **324 / 324**
- Missing from SigmaHQ built-in set: **0**

## Remaining Missing From SigmaHQ Windows Corpus

The full SigmaHQ Windows corpus currently has 2387 rules.
Your local managed set includes 324 EVTX built-in rules.

Remaining missing categories (count):

- `process_creation`: 1169
- `registry`: 247
- `powershell`: 208
- `file`: 187
- `image_load`: 98
- `network_connection`: 51
- `process_access`: 23
- `dns_query`: 22
- `pipe_created`: 17
- `create_remote_thread`: 11
- `driver_load`: 10
- `create_stream_hash`: 9
- `sysmon`: 6
- `wmi_event`: 3
- `raw_access_thread`: 1
- `process_tampering`: 1

## Notes for Analysis

- The imported EVTX built-in rules are directly relevant to classic Windows Event Log channels (Security, System, Application, and service-specific channels).
- Most remaining missing categories are Sysmon-oriented telemetry families. Importing all of them can significantly increase rule volume and matching cost.
- Current Sigma matcher implementation in this project supports only simple detection condition patterns (`condition: selection`), so not all SigmaHQ rules will be actionable without matcher enhancements.
