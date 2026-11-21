# 🛡️ Home SOC Lab: Threat Detection & Incident Response with Wazuh

This repository documents hands-on security monitoring, alert triage, false positive analysis, and incident containment exercises performed in a virtualized lab environment.

## Lab Architecture
* **SIEM / XDR:** Wazuh 4.14.10 (Deployed on Rocky Linux 9 via Docker)
* **Monitored Endpoints:** Rocky Linux 9 (`10.0.2.5`), Windows 10/11
* **Attacker Machine:** Kali Linux (`10.0.2.4`)
* **Network:** Isolated VirtualBox NAT Network (`10.0.2.0/24`)

## Documented Investigations
1. [Incident #01: SSH Brute Force Detection & Containment (MITRE T1110)](./01-SSH-Brute-Force)
