🛡️ Log Analysis Tool

A Python-based cybersecurity tool that parses system and web server logs, detects threats such as brute-force attacks and web exploitation attempts, and generates detailed HTML reports.


📋 Features


Multi-format log parsing — Linux auth.log/syslog, Apache/Nginx access logs, Windows Event logs
Threat detection — brute-force attacks, possible account compromise, web attacks, credential stuffing, suspicious account changes
HTML report generation — self-contained dashboard with metric cards, charts, and threat tables
JSON output — machine-readable results for SIEM integration
Configurable thresholds — adjust brute-force sensitivity via CLI flags
Zero dependencies — pure Python standard library, no pip installs needed



🔍 Threat Detection Capabilities

Threat TypeSeverityDescriptionBrute-force attackHIGH5+ failed logins from one IP within 5 minutesPossible compromiseCRITICALBrute-force followed by successful login from same IPWeb attackHIGHDirectory traversal, .env/.git probing, SQLi patternsCredential stuffingMEDIUMRepeated HTTP 401/403 responses from same IPAccount changeMEDIUMWindows Event IDs 4720/4725/4726 (user created/disabled/deleted)


🚀 Usage

Basic

bashpython log_analyzer.py /var/log/auth.log

Multiple files with HTML report

bashpython log_analyzer.py auth.log access.log --output results.json --report report.html

Custom brute-force threshold

bashpython log_analyzer.py auth.log --threshold 3

CLI Options

positional arguments:
  logs                  Log file(s) to analyze

optional arguments:
  -o, --output          Save JSON results to file
  -r, --report          Generate HTML report
  -t, --threshold       Brute-force failed-login threshold (default: 5)


📁 Project Structure

log-analysis-tool/
├── log_analyzer.py       # Core engine — parsing, threat detection, CLI
├── report_generator.py   # HTML report builder
├── README.md
└── samples/
    ├── sample_auth.log       # Linux auth.log sample
    ├── sample_access.log     # Apache/Nginx access log sample
    └── sample_windows.log    # Windows Event log sample


🧪 Test with Sample Logs

bashpython log_analyzer.py samples/sample_auth.log samples/sample_access.log samples/sample_windows.log --output results.json --report report.html

Expected output:

============================================================
  Log Analysis Tool
============================================================

[+] Analyzing: samples/sample_auth.log
  [*] Detected format : linux_auth
  [*] Lines read      : 19
  [*] Events parsed   : 19
  [*] Threats found   : 3
...
  Total threats  : 10
  CRITICAL      : 1
  HIGH          : 7
  MEDIUM        : 2

  TOP THREATS:
  [CRITICAL] POSSIBLE COMPROMISE: 192.168.1.105 had multiple failed logins followed by a SUCCESSFUL login.
  [HIGH] Brute-force attack detected: 6 failed login attempts from 192.168.1.105 within 5 minutes.
  [HIGH] Suspicious web request from 45.33.32.156: GET /../../../../etc/passwd → 400


📊 HTML Report

The HTML report is fully self-contained (no internet required) and includes:


Overview metrics — total events, failed logins, unique IPs, total threats
Severity summary — CRITICAL / HIGH / MEDIUM / LOW counts
Aggregated threat table — all threats across all files
Per-file analysis — charts for top failing IPs, targeted users, HTTP paths, and status codes



🖥️ Supported Log Formats

Linux auth.log / syslog

Supports both legacy syslog format and modern ISO 8601 format (rsyslog):

Jun 10 08:01:11 host sshd[1234]: Failed password for root from 192.168.1.105
2026-06-24T08:18:43+05:30 kali sudo: kali : COMMAND=/usr/bin/systemctl

Apache / Nginx Access Log

192.168.1.1 - - [10/Jun/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024

Windows Event Log (text export)

EventID: 4625
TimeCreated: 2024-06-10 08:30:01
Account Name: Administrator
Source Network Address: 172.16.0.55


🔧 Requirements
Python 3.8+
No external libraries required


Tested on:
Kali Linux (rolling)
Ubuntu 22.04
Windows 10/11



👤 Author

Thavindu Danuja
BSc (Hons) Information Technology — Cyber Security, SLIIT
ISC2 Certified in Cybersecurity (CC)
