# INC-002 — Privilege Escalation via Sudo

## What this is

Wazuh's default rule for a successful sudo doesn't check what command was actually run. `sudo ls /root` and `sudo -i` (a full interactive root shell) get flagged the same way, at the same low severity — even though opening a root shell is far more dangerous.
I found this, wrote a custom rule to fix it, and tested it with a real command.

---

## What Wazuh already covers well

Before looking for a gap, I checked what the default sudo ruleset already handles:

| Rule | Level | Fires on |
|---|---|---|
| 5401 | 5 | Wrong sudo password |
| 5404 | 10 | Three wrong sudo passwords in a row |
| 5405 | 5 | A user who isn't allowed to use sudo |
| 5406 | 5 | A command the user isn't allowed to run |
| 5403 | 4 | First time a user ever runs sudo |
| 5901/5902 | 8 | A new user or group is created |

Failed sudo attempts and new-account creation are already handled properly. The gap is somewhere else.

```bash
sudo sed -n '615,720p' /var/ossec/ruleset/rules/0020-syslog_rules.xml
```

---

## The gap

```bash
sudo grep -A 10 'id="5402"' /var/ossec/ruleset/rules/0020-syslog_rules.xml
```

```xml
<rule id="5402" level="3">
  <if_sid>5400</if_sid>
  <regex> ; USER=root ; COMMAND=| ; USER=root ; TSID=\S+ ; COMMAND=</regex>
  <description>Successful sudo to ROOT executed.</description>
</rule>
```

This rule only checks that a sudo command ran as root. It never looks at *what* the command was. So a one-off command and a full root shell look identical to it.

Proof — open a root shell and check the alert:
```bash
sudo -i
exit
```
```bash
sudo grep '"id":"5402"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq .
```
Result: level 3. Same as any harmless sudo command. No indication that an interactive root shell was opened.

---

## The fix

```xml
<rule id="100020" level="12">
  <if_sid>5402</if_sid>
  <regex>COMMAND=/usr/bin/bash|COMMAND=/bin/bash|COMMAND=/usr/bin/sh|COMMAND=/bin/sh</regex>
  <description>Sudo used to open an interactive root shell (possible full compromise).</description>
  <mitre><id>T1548.003</id></mitre>
  <group>privilege_escalation,attack,</group>
</rule>
```

- Sits on top of `5402` (`if_sid`) — only evaluates after a successful root sudo is already confirmed.
- Checks the command field specifically for `bash` or `sh` — the fingerprint of an interactive shell rather than a single command.
- If it matches, severity jumps from level 3 to level 12.

Load it:
```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

---

## Proof it works

```bash
sudo -i
exit
```
```bash
sudo grep '"id":"100020"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq .
```

Result: level 12, "Sudo used to open an interactive root shell (possible full compromise)", MITRE T1548.003.

Screenshots: [`screenshots/`](screenshots/)

---

## How to demo this live

1. Show the gap:
   ```bash
   sudo grep -A 10 'id="5402"' /var/ossec/ruleset/rules/0020-syslog_rules.xml
   ```
2. Trigger it:
   ```bash
   sudo -i
   exit
   ```
3. Show the weak alert:
   ```bash
   sudo grep '"id":"5402"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq .
   ```
4. Show the fix:
   ```bash
   cat /var/ossec/etc/rules/local_rules.xml
   ```
5. Show it caught properly:
   ```bash
   sudo grep '"id":"100020"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq .
   ```

---

## MITRE ATT&CK

| Technique | ID |
|---|---|
| Sudo and Sudo Caching | T1548.003 |

---

## What I'd do next in a real environment

- Terminate the session
- Review everything run inside the root shell
- Check for new users, cron jobs, or SSH keys added during the session
- Confirm whether the account's normal behaviour justifies a root shell at all
