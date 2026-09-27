# INC-001 : SSH Brute Force Detection

## What this is

Wazuh's default rule for detecting SSH brute-force attacks only works if the attacker guesses **usernames that don't exist**. If someone guesses passwords against a **real, valid account** instead, the default rule never fires.
I found this gap, wrote a custom rule to fix it, and tested it with a real attack.

## The gap

Wazuh's built-in brute-force rule (`5712`) only correlates against rule `5710` ("non-existent user"). It never watches rule `5503` ("failed login for a real user"). So a brute-force attack against a real account is invisible to it.

```bash
sudo grep -A 15 'id="5712"' /var/ossec/ruleset/rules/0095-sshd_rules.xml
```
this is the whole problem:
```xml
<if_matched_sid>5710</if_matched_sid>
```

## The fix

Two custom rules, added to `/var/ossec/etc/rules/local_rules.xml`:
```xml
<group name="local,syslog,sshd,">

  <rule id="100010" level="10" frequency="5" timeframe="120">
    <if_matched_sid>5503</if_matched_sid>
    <same_source_ip />
    <description>SSH: Multiple failed password attempts against a valid user (possible brute force).</description>
    <mitre><id>T1110.001</id></mitre>
    <group>authentication_failures,</group>
  </rule>

  <rule id="100011" level="12">
    <if_sid>5715</if_sid>
    <if_matched_sid>100010</if_matched_sid>
    <same_source_ip />
    <description>SSH: Successful login following multiple failed attempts - possible account compromise.</description>
    <mitre><id>T1110.001</id><id>T1078</id></mitre>
    <group>authentication_success,attack,</group>
  </rule>

</group>
```

- **100010** — 5 failed passwords against a real user, same IP, within 2 minutes → flag as possible brute force.
- **100011** — a successful login right after 100010 fires → flag as possible compromise.

Load it:
```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```
## Proof it works

Attack simulation - 5 failed logins against a real account, then a real successful login:
```bash
for i in {1..5}; do
  sshpass -p "wrongpass$i" ssh -o StrictHostKeyChecking=no -o PubkeyAuthentication=no pvee@localhost 'exit' 2>/dev/null
  sleep 1
done

ssh pvee@localhost 'echo SUCCESS'   # type your real password here
```

Check the result:
```bash
sudo grep -E '"id":"100010"|"id":"100011"' /var/ossec/logs/alerts/alerts.json | tail -4
```

What you'll see:
```
21:24:12–21:24:27 → 5 failed passwords, user pvee, 127.0.0.1  → rule 100010 fires
21:24:37           → successful login, same user, same IP    → rule 100011 fires
```

Screenshots: [`screenshots/`](screenshots/)

---

## How to demo this live

1. Show the gap:
   ```bash
   sudo grep -A 15 'id="5712"' /var/ossec/ruleset/rules/0095-sshd_rules.xml
   ```
2. Show the fix:
   ```bash
   cat /var/ossec/etc/rules/local_rules.xml
   ```
3. Show it firing:
   ```bash
   sudo grep -E '"id":"100010"|"id":"100011"' /var/ossec/logs/alerts/alerts.json | tail -4
   ```

---

## MITRE ATT&CK

| Technique | ID |
|---|---|
| Password Guessing | T1110.001 |
| Valid Accounts | T1078 |

---

## What I'd do next in a real environment

- Disable the account
- Block the source IP
- Force a password reset
- Check for anything the attacker did after logging in
