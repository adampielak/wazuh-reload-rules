# Wazuh reload rules (without restart wazuh-manager)
Authenticate to Wazuh API, trigger ruleset reload (analysisd), pretty-print results with jq, parse issues table, and tail ossec.log.

## How to use

1. Clone the repository or just download script:

```bash
cd /var/ossec/bin
OR
/usr/local/bin/
wget -O wazuh-reload-rule https://raw.githubusercontent.com/adampielak/wazuh-reload-rules/refs/heads/main/wazuh-reload-rules.sh
chmod 0750 wazuh-reload-rule

```

2. After create/modify/delete decoders or ruleset:

```bash
wazuh-reload-rules -u https://localhost:55000 -U USER -p 'PASS' -k -L /var/ossec/logs/ossec.log

```
- OR
  
```bash
WAZUH_PASS='PASS' wazuh-reload-rules

```

3. Output:

- Adding Custom Environment Fields:

```bash
[root@siem-manager-01-dc1]-[]-[~] # /var/ossec/bin/wazuh-reload-rules
[*] Authenticating to https://127.0.0.1:55000 as 'wazuh'…
[*] Requesting ruleset reload (analysisd)…

[✓] API accepted reload request.
Message: Reload request sent to all specified nodes
Affected items: 1, Failed items: 0
Details:
 - (7617): Signature ID '89606' was not found and will be ignored in the 'if_sid' option of rule '99909'.
 - (7619): Empty 'if_sid' value. Rule '99909' will be ignored.
 - (7617): Signature ID '89607' was not found and will be ignored in the 'if_sid' option of rule '99910'.
 - (7619): Empty 'if_sid' value. Rule '99910' will be ignored.

Parsed ruleset issues:
Rule      Issue             Detail
--------  ----------------  ----------------------------------------------
99909     if_sid_sig_missing  sid=89606
99909     if_sid_empty      if_sid empty
99910     if_sid_sig_missing  sid=89607
99910     if_sid_empty      if_sid empty

---- Recent ossec.log (ruleset/analysisd) ----
2025/09/25 11:09:47 wazuh-analysisd: INFO: Reloading ruleset
----------------------------------------------

```
