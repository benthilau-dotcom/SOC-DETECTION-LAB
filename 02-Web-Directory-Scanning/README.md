# Incident #02: Web Directory Enumeration Detection (Gobuster)

* **Date / Time:** 2026-11-21 03:14:00 UTC (04:14:00 CET - Spain / 00:14:00 ART - Argentina)
* **Affected Endpoint:** Rocky Linux Web Server (`10.0.2.5` - Agent ID `001`)
* **Attacker Source IP:** `10.0.2.4` (Kali Linux)
* **User-Agent Detected:** `gobuster/3.8.2`
* **Rule Groups:** `web`, `accesslog`, `web_scan`, `recon`
* **MITRE ATT&CK:** Reconnaissance (`TA0043`) / Vulnerability Scanning (`T1595`)
* **Final Verdict:** True Positive - Contained (No sensitive paths exposed)

## 1. Alert Analysis & Log Investigation
During active monitoring of the Apache HTTP server (`httpd`) logs integrated into Wazuh, a burst of HTTP `404 Not Found` error codes triggered a web reconnaissance correlation alert.

Inspecting the raw event details (`previous_output` / `full_log`) confirmed automated directory brute-forcing originating from IP `10.0.2.4` using the `gobuster/3.8.2` User-Agent (e.g., `GET /yml HTTP/1.1 404 196`). 

![Web Scan Alert Details](../02-gobuster-alert.png)

## 2. Impact Assessment
* Filtered all HTTP events from source IP `10.0.2.4` to verify response status codes.
* Confirmed all requests returned `404 Not Found` responses; no `200 OK` or unauthorized access to sensitive files occurred.

## 3. Containment & Remediation
Blocked the scanning IP address `10.0.2.4` at the host firewall level using `firewalld` to prevent further enumeration or exploitation attempts:
```bash
firewall-cmd --add-rich-rule='rule family="ipv4" source address="10.0.2.4" reject'
```

## 4. SOC Ticket Closure Note (Spanish / English)
> **ES:** Alerta de escaneo web (`web_scan`, `recon`) detectada en el servidor Apache (`10.0.2.5`) a las 03:14 UTC (04:14 CET). Los logs crudos confirmaron enumeración automatizada de directorios desde la IP `10.0.2.4` mediante `gobuster/3.8.2` generando múltiples errores HTTP 404 (`GET /yml`). Sin accesos exitosos (HTTP 200). IP atacante bloqueada en el firewall del host (`firewalld`). Cerrado como Verdadero Positivo - Contenido.
>
> **EN:** Web scan alert (`web_scan`, `recon`) triggered on Apache server (`10.0.2.5`) at 03:14 UTC (04:14 CET). Raw access logs confirmed automated directory enumeration from `10.0.2.4` using `gobuster/3.8.2` generating repeated HTTP 404 responses (`GET /yml`). Verified no HTTP 200 responses occurred. Attacking IP blocked via host firewall (`firewalld`). Closing as True Positive - Contained.

