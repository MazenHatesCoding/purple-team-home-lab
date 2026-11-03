# Lab Setup

Three VMs in VirtualBox on my laptop (12 GB RAM), all on one **NAT network** with
no route out to the internet or anything real. Here's how it's wired up.

## The layout

```
        VirtualBox NAT network (10.0.2.0/24), isolated
   ┌──────────────────────────────────────────────────────┐
   │                                                        │
   │   Kali Linux            Windows 10 Pro      Wazuh SIEM │
   │   (attacker)            (victim)            (Ubuntu)   │
   │   10.0.2.3              10.0.2.15            10.0.2.4   │
   │                         DESKTOP-RVJTQU1               │
   │                         Sysmon + Wazuh agent          │
   │                                   │                    │
   │                                   └──── sends logs ───>│
   │                                       Sysmon channel   │
   └──────────────────────────────────────────────────────┘
```

| Role | OS | IP | Notes |
|------|----|----|-------|
| Attacker | Kali Linux | 10.0.2.3 | nmap, Hydra, NetExec, Metasploit/msfvenom, Mimikatz, John |
| Victim | Windows 10 Pro | 10.0.2.15 | `DESKTOP-RVJTQU1`; Sysmon + Wazuh agent "Victim-1" |
| SIEM | Ubuntu (Wazuh OVA) | 10.0.2.4 | Official Wazuh OVA with the manager + dashboard |

## Telemetry on the Windows host

- **Sysmon** with the SwiftOnSecurity config, gives solid process and
  command-line logging, which is what most of the detection relies on.
- **Wazuh agent** forwarding the Sysmon event channel to the manager at
  `10.0.2.4`.

## Weaknesses I planted on purpose

I configured these myself so I'd have a realistic target to attack. They're what
the findings in the reports map back to:

1. A weak user, `jsmith` / `password123`, added to **Remote Desktop Users**.
2. **RDP** left open on port **3389**.
3. **`AlwaysInstallElevated = 0x1`** in **both** `HKLM` and `HKCU`.

## A note on Microsoft Defender

Partway through, I disabled Defender's real-time protection, but only to isolate
what the SIEM/Sysmon layer would detect on its own, *after* Defender had already
detected and deleted my first payload. So this isn't me saying "turn off your
antivirus." The opposite, really: Defender did its job. More on that in the
[pentest report](../reports/pentest-report.md), section 2.

> Note: these are throwaway, offline VMs. Don't apply any of these weak settings
> to a machine you actually care about.
