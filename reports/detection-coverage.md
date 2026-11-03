# Detection Coverage: MITRE ATT&CK Mapping

**Lab:** Purple-Team Home Lab (isolated VirtualBox NAT network)
**SIEM:** Wazuh 4.x (official OVA) + Sysmon (SwiftOnSecurity config) on Windows 10
**Date:** 2026-11-03
**Author:** Mazen Ashraf

This table maps every technique executed in the attack chain to what the SIEM
detected **out of the box** versus **after** the custom detection engineering.
"Default" means Wazuh's bundled ruleset plus the SwiftOnSecurity Sysmon config
with no changes.

| # | Technique | ATT&CK ID | Detected by default | Custom rule | Detected after |
|---|-----------|-----------|:-------------------:|:-----------:|:--------------:|
| 1 | Network Service Discovery (nmap port scan) | T1046 | No[1] | - | No[1] |
| 2 | Brute Force: Password Guessing (RDP, Hydra) | T1110.001 | **Yes** (1,157 failed-logon events) | - | **Yes** |
| 3 | Valid Accounts (RDP login as jsmith) | T1078 | Partial[2] | - | Partial[2] |
| 4 | Remote Services: RDP | T1021.001 | Partial[2] | - | Partial[2] |
| 5 | Ingress Tool Transfer (certutil download) | T1105 | **Yes** (rule 92075) | - | **Yes** |
| 6 | System Binary Proxy Exec: Msiexec (AlwaysInstallElevated) | T1218.007 / T1548.002 | Partial[3] (payload drop in Public: rules 92207/92213) | - | Partial[3] |
| 7 | Impair Defenses: Disable/Modify Tools (Defender off) | T1562.001 | No[4] | - | No[4] |
| 8 | Create Account: Local Account (svc_backup) | T1136.001 | **Yes** (rule 60154, "Administrators Group Changed", level 12) | - | **Yes** |
| 9 | Scheduled Task/Job (OneDrive Sync Helper) | T1053.005 | **No (gap)**, logged only at level 4, buried in noise | - | **No (gap)** |
| 10 | OS Credential Dumping: LSASS Memory (Mimikatz) | T1003.001 | **No (gap)**, no alert; Sysmon event 10 not logged | **rule 100101 (level 15)** | **Yes** |

**Fully-detected techniques: 4 -> 5 of 10.** The critical credential-access
stage (T1003.001) moved from *undetected* to a *high-severity (level 15)* alert.

---

## Notes

[1] **T1046 (port scan):** No network IDS (e.g., Suricata/Zeek) was deployed in
this lab, and host-based telemetry does not reliably surface an external
`-Pn` SYN scan. Out of scope for this iteration; noted as a future improvement.

[2] **T1078 / T1021.001 (valid-account RDP login):** The successful logon is
*visible* in telemetry (51 authentication-success events, Windows 4624 Type 10),
but there is no rule that distinguishes a legitimate RDP login from a malicious
one on its own. Marked **Partial**: the data exists, the alerting logic does not.
A realistic improvement is a "successful logon immediately following a lockout /
brute-force burst" correlation rule.

[3] **T1218.007 / T1548.002 (msiexec privilege escalation):** The *side effects*
were caught, the payload written to `C:\Users\Public` fired rules 92207/92213,
but the `msiexec /i` execution leveraging AlwaysInstallElevated did not raise a
dedicated alert. Marked **Partial**.

[4] **T1562.001 (disabling Defender):** Done manually via the Windows Security UI
as a deliberate test-scoping action, which does not generate the same telemetry
as a scripted `Set-MpPreference` / registry tamper. Not alerted. In production,
Defender tamper-protection events and the Wazuh Windows-Defender decoders would
be the detection path.

---

## What the default stack got right

Wazuh's bundled rules + SwiftOnSecurity Sysmon performed well on the **noisy,
disk-touching** parts of the intrusion:

- Brute force over RDP, 1,157 failed-logon events.
- `certutil.exe` used as a downloader, rule **92075**.
- Executables dropped in `C:\Users\Public`, rules **92207 / 92213**.
- Backdoor account added to Administrators, rule **60154** (level 12).

## Where it was blind

- **Credential dumping (T1003.001):** no alert at all. This was the headline
  gap and the target of the custom rule.
- **Scheduled-task persistence (T1053.005):** present only as a level-4 event,
  effectively invisible in day-to-day triage.
- **LSASS access (Sysmon event 10):** not logged, a Wazuh search for
  `data.win.system.eventID: "10"` returned **No results**
  (`screenshots/09-wazuh-lsass-gap.png`).

See [`../detection/local_rules.xml`](../detection/local_rules.xml) for the rule
that closed the credential-dumping gap, and the
[pentest report](pentest-report.md) / [incident report](incident-report.md)
for full context.
