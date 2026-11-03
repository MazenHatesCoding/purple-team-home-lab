# Detection

This is the blue-team half, the files that define what the SIEM detects.

## Files

| File | What it is |
|------|------------|
| [`local_rules.xml`](local_rules.xml) | My custom Wazuh rule (`id 100101`, level 15, T1003.001) that detects credential-dumping command lines. Deploys to the SIEM at `/var/ossec/etc/rules/local_rules.xml`. |
| [`sysmon-lsass-processaccess.xml`](sysmon-lsass-processaccess.xml) | The LSASS / event-10 (ProcessAccess) approach I tried **first**. I kept it in because it didn't fire reliably, and that pivot is part of the story. |

## What happened

1. **The goal:** detect credential dumping (Mimikatz, `T1003.001`). The default
   Wazuh + Sysmon setup didn't alert on it at all.
2. **First approach:** detect processes accessing LSASS via Sysmon event 10
   (ProcessAccess). In my lab that channel never produced event-10 records,
   searching Wazuh for `data.win.system.eventID: "10"` returned *No results*
   (`../screenshots/09-wazuh-lsass-gap.png`).
3. **What I shipped instead:** match on the **command line** of the process
   (Sysmon event 1), keying on the strings these tools reliably use,
   `sekurlsa`, `privilege::debug`, `lsadump`, `logonpasswords`, `mimikatz`.
4. **Result:** before, no alert. After, every run raises a **level-15** detection
   (`rule.id 100101`), `../screenshots/10-wazuh-custom-rule-firing.png`.

The full technique-by-technique table is in
[`../reports/detection-coverage.md`](../reports/detection-coverage.md).

### Loading the rule

```bash
# On the Wazuh manager
sudo cp local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

Because it matches the *command line* rather than a file name or hash, renaming
the Mimikatz binary doesn't evade it. For a production tune I'd add an allow-list
for legitimate admin tooling to cut down on false positives.
