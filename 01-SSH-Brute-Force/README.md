# Incident #01: SSH Brute Force Detection & False Positive Triage

* **Date / Time (UTC):** 2026-11-19 22:48:33 UTC
* **Affected Endpoint:** Rocky Linux (`10.0.2.5` - Agent ID `001`)
* **Attacker Source IP:** `10.0.2.4` (Kali Linux)
* **Triggered Rules:** Rule ID `5710` (Level 5), Rule ID `2502` (Level 10 - High)
* **MITRE ATT&CK:** Credential Access / Brute Force (`T1110`)
* **Final Verdict:** True Positive (Contained)

## 1. Alert Analysis & Log Investigation
During active monitoring in Wazuh (`Threat Hunting -> Events`), a sequence of failed SSH authentication attempts (`Rule 5710`) escalated into a correlation alert (`Rule 2502: syslog: User missed the password more than one time`).

Inspecting the raw event (`full_log` from `journald`) revealed multiple failed login attempts targeting the non-existent user `auditoria` originating from `rhost=10.0.2.4`. Cross-referencing subsequent logs confirmed no `authentication_success` events occurred from that source IP.

![Wazuh Alert Timeline](../01-timeline.png)

## 2. False Positive Triage (Rootcheck)
Prior to the brute force activity, a Level 11 alert (`Rule 521: Possible kernel level rootkit - Process '2959' hidden from /proc`) was triggered. Live endpoint verification using `ps -fp 2959` and checking `/proc/2959` confirmed the process no longer existed, identifying it as a benign race condition caused by short-lived Docker container processes during startup.

## 3. Containment & Remediation
Blocked the attacking IP address `10.0.2.4` at the host firewall level using `firewalld`:
```bash
firewall-cmd --add-rich-rule='rule family="ipv4" source address="10.0.2.4" reject'
```

## 4. SOC Ticket Closure Note
> Alert ID 2502 (SSH Brute Force - MITRE T1110) triggered on host 10.0.2.5. Source IP 10.0.2.4 performed multiple failed login attempts targeting non-existent user auditoria. Verified raw journald logs; no successful logins observed. Concurrent Rootcheck alert (PID 2959) investigated and ruled out as a benign container race condition. Source IP blocked on host firewall. Closing as True Positive - Contained.
