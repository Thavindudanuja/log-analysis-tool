#!/usr/bin/env python3
"""
Log Analysis Tool
Supports: Linux auth.log/syslog, Apache/Nginx access logs, Windows Event logs
Detects: Brute-force attacks, suspicious IPs, failed logins, port scans
"""

import re
import os
import sys
import json
import argparse
from datetime import datetime
from collections import defaultdict
from pathlib import Path


# ── Thresholds ────────────────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5       # failed logins from one IP within window
BRUTE_FORCE_WINDOW    = 300     # seconds (5 min)
PORT_SCAN_THRESHOLD   = 10      # distinct ports from one IP
CRITICAL_PORTS        = {22, 23, 3389, 5900, 1433, 3306, 5432}


# ── Regex Patterns ────────────────────────────────────────────────────────────
PATTERNS = {

    # Linux auth.log — supports BOTH formats:
    #   Old: Jun 10 08:01:11 host sshd[1234]: ...
    #   New: 2026-06-24T08:18:06.185391+05:30 host sshd[1234]: ...
    "linux_auth_failed": re.compile(
        r"(?:(?P<iso_ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
        r"|(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2}))"
        r".*?\S+\[\d+\]:\s+.*?"
        r"from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        re.IGNORECASE,
    ),
    "linux_auth_success": re.compile(
        r"(?:(?P<iso_ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
        r"|(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2}))"
        r".*?\S+\[\d+\]:\s+.*?"
        r"from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        re.IGNORECASE,
    ),
    "linux_sudo": re.compile(
        r"(?:(?P<iso_ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
        r"|(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2}))"
        r".*?sudo[\[:].*?(?P<user>\S+)\s+:.*?COMMAND=(?P<cmd>.+)",
        re.IGNORECASE,
    ),
    # Apache / Nginx combined log
    "apache": re.compile(
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+\[(?P<datetime>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
        r'(?P<status>\d{3})\s+(?P<size>\d+|-)',
        re.IGNORECASE,
    ),

    # Windows Event Log (text export)
    "windows_event": re.compile(
        r"(?:Date|TimeCreated).*?(?P<date>\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4})"
        r".*?(?:Time|).*?(?P<time>\d{2}:\d{2}:\d{2})"
        r".*?(?:Event\s*ID|EventID)\D*(?P<event_id>\d+)",
        re.IGNORECASE | re.DOTALL,
    ),
    "windows_logon_fail": re.compile(
        r"(?:4625|An account failed to log on)"
        r".*?(?:Account Name|User):\s*(?P<user>\S+)"
        r".*?(?:Source Network Address|Workstation Name):\s*(?P<ip>\S+)?",
        re.IGNORECASE | re.DOTALL,
    ),
    "windows_logon_success": re.compile(
        r"(?:4624|An account was successfully logged on)"
        r".*?(?:Account Name):\s*(?P<user>\S+)"
        r".*?(?:Source Network Address):\s*(?P<ip>\S+)?",
        re.IGNORECASE | re.DOTALL,
    ),
}

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5,  "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10,"Nov": 11, "Dec": 12,
}

SUSPICIOUS_STATUS = {400, 401, 403, 404, 405, 429, 500, 501, 502, 503}

SUSPICIOUS_PATHS = re.compile(
    r"(?:\.\.\/|\/etc\/passwd|\/etc\/shadow|cmd\.exe|powershell|"
    r"wp-admin|phpmyadmin|\.env|\.git|xmlrpc|eval\(|base64_decode|"
    r"union.*select|drop\s+table|<script|%3Cscript|javascript:)",
    re.IGNORECASE,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def detect_log_type(filepath: str) -> str:
    """Sniff first 20 lines to determine log format."""
    try:
        with open(filepath, "r", errors="ignore") as f:
            sample = "".join(f.readline() for _ in range(20))
    except OSError:
        return "unknown"

    if PATTERNS["apache"].search(sample):
        return "apache"
    if re.search(r"sshd[\[:]|vsftpd[\[:]|sudo[\[:]", sample):
        return "linux_auth"
    if re.search(r"kernel:|systemd\[", sample):
        return "syslog"
    if re.search(r"EventID|Event ID|4624|4625|Security|Microsoft-Windows", sample):
        return "windows"
    return "unknown"

def parse_linux_timestamp(month=None, day=None, time_str=None, iso_ts=None) -> datetime:
    """Parse both old syslog format and new ISO 8601 format timestamps."""
    if iso_ts:
        try:
            # Strip fractional seconds and timezone for fromisoformat compat
            clean = re.sub(r"\.\d+", "", iso_ts)
            return datetime.fromisoformat(clean)
        except ValueError:
            return datetime.now()
    try:
        year = datetime.now().year
        m = MONTH_MAP.get(month, 1)
        d = int(day)
        h, mi, s = map(int, time_str.split(":"))
        return datetime(year, m, d, h, mi, s)
    except Exception:
        return datetime.now()


def parse_apache_timestamp(dt_str: str) -> datetime:
    try:
        return datetime.strptime(dt_str[:20], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return datetime.now()


# ── Parsers ───────────────────────────────────────────────────────────────────

def parse_linux_auth(lines: list) -> dict:
    events = []
    for line in lines:
        m = PATTERNS["linux_auth_failed"].search(line)
        if m and re.search(r"Failed password|Invalid user|authentication failure|FAILED su", line, re.IGNORECASE):
            ts = parse_linux_timestamp(
                month=m.group("month"),
                day=m.group("day"),
                time_str=m.group("time"),
                iso_ts=m.group("iso_ts"),
            )
            user_m = re.search(r"for(?:\s+invalid user)?\s+(\S+)\s+from", line, re.IGNORECASE)
            events.append({
                "type": "failed_login",
                "timestamp": ts,
                "ip": m.group("ip"),
                "user": user_m.group(1) if user_m else None,
                "raw": line.strip(),
            })
            continue

        m = PATTERNS["linux_auth_success"].search(line)
        if m and re.search(r"Accepted password|Accepted publickey|session opened", line, re.IGNORECASE):
            ts = parse_linux_timestamp(
                month=m.group("month"),
                day=m.group("day"),
                time_str=m.group("time"),
                iso_ts=m.group("iso_ts"),
            )
            user_m = re.search(r"for\s+(\S+)\s+from", line, re.IGNORECASE)
            events.append({
                "type": "successful_login",
                "timestamp": ts,
                "ip": m.group("ip"),
                "user": user_m.group(1) if user_m else None,
                "raw": line.strip(),
            })
            continue

        m = PATTERNS["linux_sudo"].search(line)
        if m:
            ts = parse_linux_timestamp(
                month=m.group("month"),
                day=m.group("day"),
                time_str=m.group("time"),
                iso_ts=m.group("iso_ts"),
            )
            events.append({
                "type": "sudo_command",
                "timestamp": ts,
                "ip": None,
                "user": m.group("user"),
                "command": m.group("cmd").strip(),
                "raw": line.strip(),
            })

    return {"format": "linux_auth", "events": events}


def parse_apache(lines: list) -> dict:
    events = []
    for line in lines:
        m = PATTERNS["apache"].match(line)
        if not m:
            continue
        status = int(m.group("status"))
        path   = m.group("path")
        ts     = parse_apache_timestamp(m.group("datetime"))
        is_suspicious = (
            status in SUSPICIOUS_STATUS
            or bool(SUSPICIOUS_PATHS.search(path))
        )
        events.append({
            "type": "http_request",
            "timestamp": ts,
            "ip": m.group("ip"),
            "method": m.group("method"),
            "path": path,
            "status": status,
            "size": m.group("size"),
            "suspicious": is_suspicious,
            "raw": line.strip(),
        })
    return {"format": "apache", "events": events}


def parse_windows(lines: list) -> dict:
    events = []
    full_text = "\n".join(lines)
    blocks = re.split(r"\n{2,}|[-=]{10,}", full_text)

    for block in blocks:
        if not block.strip():
            continue

        event_id_m = re.search(r"(?:Event\s*ID|EventID)[:\s]*(\d+)", block, re.IGNORECASE)
        event_id   = int(event_id_m.group(1)) if event_id_m else None

        ts_m = re.search(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", block)
        if ts_m:
            try:
                ts = datetime.fromisoformat(ts_m.group(1).replace("T", " "))
            except ValueError:
                ts = None
        else:
            ts = None

        user_matches = re.findall(r"Account Name:\s*(\S+)", block, re.IGNORECASE)
        user = user_matches[-1] if user_matches else None
        ip_m = re.search(r"(?:Source Network Address|Workstation Name):\s*(\S+)", block, re.IGNORECASE)
        ip   = ip_m.group(1) if ip_m else None

        if event_id == 4625:
            events.append({"type": "failed_login",     "timestamp": ts, "ip": ip, "user": user, "event_id": event_id, "raw": block.strip()})
        elif event_id == 4624:
            events.append({"type": "successful_login", "timestamp": ts, "ip": ip, "user": user, "event_id": event_id, "raw": block.strip()})
        elif event_id in (4720, 4722, 4723, 4724, 4725, 4726):
            events.append({"type": "account_change",   "timestamp": ts, "ip": ip, "user": user, "event_id": event_id, "raw": block.strip()})
        elif event_id:
            events.append({"type": "other",            "timestamp": ts, "ip": ip, "user": user, "event_id": event_id, "raw": block.strip()})

    return {"format": "windows", "events": events}


# ── Threat Detection ──────────────────────────────────────────────────────────

def detect_threats(parsed: dict) -> dict:
    events  = parsed["events"]
    threats = []

    # 1. Brute-force: 5+ failed logins from same IP within 5 min
    ip_failures = defaultdict(list)
    for e in events:
        if e["type"] == "failed_login" and e.get("ip") and e.get("timestamp"):
            ip_failures[e["ip"]].append(e["timestamp"])

    for ip, timestamps in ip_failures.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            window = [
                t for t in timestamps[i:]
                if (t - timestamps[i]).total_seconds() <= BRUTE_FORCE_WINDOW
            ]
            if len(window) >= BRUTE_FORCE_THRESHOLD:
                threats.append({
                    "type": "brute_force",
                    "severity": "HIGH",
                    "ip": ip,
                    "count": len(window),
                    "first_seen": window[0].isoformat(),
                    "last_seen": window[-1].isoformat(),
                    "description": (
                        f"Brute-force attack detected: {len(window)} failed login "
                        f"attempts from {ip} within {BRUTE_FORCE_WINDOW//60} minutes."
                    ),
                })
                break

    # 2. Successful login AFTER brute-force → possible compromise
    success_ips = {e["ip"] for e in events if e["type"] == "successful_login" and e.get("ip")}
    brute_ips   = {t["ip"] for t in threats if t["type"] == "brute_force"}
    for ip in brute_ips & success_ips:
        threats.append({
            "type": "possible_compromise",
            "severity": "CRITICAL",
            "ip": ip,
            "description": (
                f"POSSIBLE COMPROMISE: {ip} had multiple failed logins "
                f"followed by a SUCCESSFUL login."
            ),
        })

    # 3. Apache: directory traversal / injection
    for e in events:
        if e.get("type") == "http_request" and e.get("suspicious"):
            if SUSPICIOUS_PATHS.search(e.get("path", "")):
                threats.append({
                    "type": "web_attack",
                    "severity": "HIGH",
                    "ip": e["ip"],
                    "path": e["path"],
                    "status": e["status"],
                    "description": (
                        f"Suspicious web request from {e['ip']}: "
                        f"{e.get('method','GET')} {e['path']} → {e['status']}"
                    ),
                })

    # 4. Repeated 401/403 from same IP
    http_errors = defaultdict(int)
    for e in events:
        if e.get("type") == "http_request" and e.get("status") in {401, 403}:
            http_errors[e["ip"]] += 1
    for ip, count in http_errors.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            threats.append({
                "type": "credential_stuffing",
                "severity": "MEDIUM",
                "ip": ip,
                "count": count,
                "description": (
                    f"Possible credential stuffing: {count} HTTP 401/403 "
                    f"responses for {ip}."
                ),
            })

    # 5. Windows account management events
    for e in events:
        if e.get("type") == "account_change":
            eid = e.get("event_id")
            labels = {
                4720: "User account created",
                4722: "User account enabled",
                4723: "Password change attempted",
                4724: "Password reset attempted",
                4725: "User account disabled",
                4726: "User account deleted",
            }
            threats.append({
                "type": "account_change",
                "severity": "MEDIUM",
                "ip": e.get("ip"),
                "user": e.get("user"),
                "event_id": eid,
                "description": f"{labels.get(eid, 'Account change')} for user '{e.get('user')}'.",
            })

    # Deduplicate
    seen = {}
    severity_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
    for t in threats:
        key = (t["type"], t.get("ip"), t.get("path", ""))
        existing = seen.get(key)
        if not existing or severity_rank[t["severity"]] > severity_rank[existing["severity"]]:
            seen[key] = t
    threats = list(seen.values())
    threats.sort(key=lambda x: severity_rank.get(x["severity"], 0), reverse=True)

    return threats


# ── Statistics ────────────────────────────────────────────────────────────────

def build_stats(parsed: dict) -> dict:
    events = parsed["events"]
    stats  = {
        "total_events":        len(events),
        "failed_logins":       sum(1 for e in events if e["type"] == "failed_login"),
        "successful_logins":   sum(1 for e in events if e["type"] == "successful_login"),
        "sudo_commands":       sum(1 for e in events if e["type"] == "sudo_command"),
        "http_requests":       sum(1 for e in events if e["type"] == "http_request"),
        "suspicious_requests": sum(1 for e in events if e.get("suspicious")),
        "unique_ips":          len({e["ip"] for e in events if e.get("ip")}),
        "top_failing_ips":     {},
        "top_users_targeted":  {},
        "http_status_codes":   {},
        "top_paths":           {},
        "account_changes":     sum(1 for e in events if e["type"] == "account_change"),
    }

    ip_fail_count   = defaultdict(int)
    user_fail_count = defaultdict(int)
    status_count    = defaultdict(int)
    path_count      = defaultdict(int)

    for e in events:
        if e["type"] == "failed_login":
            if e.get("ip"):   ip_fail_count[e["ip"]] += 1
            if e.get("user"): user_fail_count[e["user"]] += 1
        if e["type"] == "http_request":
            status_count[e["status"]] += 1
            path_count[e["path"]]     += 1

    stats["top_failing_ips"]    = dict(sorted(ip_fail_count.items(),   key=lambda x: -x[1])[:10])
    stats["top_users_targeted"] = dict(sorted(user_fail_count.items(), key=lambda x: -x[1])[:10])
    stats["http_status_codes"]  = dict(sorted(status_count.items(),    key=lambda x: -x[1]))
    stats["top_paths"]          = dict(sorted(path_count.items(),      key=lambda x: -x[1])[:10])

    return stats


# ── Main Analyzer ─────────────────────────────────────────────────────────────

def analyze_file(filepath: str) -> dict:
    path = Path(filepath)
    if not path.exists():
        return {"error": f"File not found: {filepath}"}

    log_type = detect_log_type(filepath)
    print(f"  [*] Detected format : {log_type}")

    with open(filepath, "r", errors="ignore") as f:
        lines = f.readlines()
    print(f"  [*] Lines read      : {len(lines):,}")

    if log_type in ("linux_auth", "syslog"):
        parsed = parse_linux_auth(lines)
    elif log_type == "apache":
        parsed = parse_apache(lines)
    elif log_type == "windows":
        parsed = parse_windows(lines)
    else:
        results = [
            parse_linux_auth(lines),
            parse_apache(lines),
            parse_windows(lines),
        ]
        parsed = max(results, key=lambda r: len(r["events"]))
        print(f"  [*] Auto-selected   : {parsed['format']} ({len(parsed['events'])} events)")

    threats = detect_threats(parsed)
    stats   = build_stats(parsed)

    print(f"  [*] Events parsed   : {stats['total_events']:,}")
    print(f"  [*] Threats found   : {len(threats)}")

    return {
        "file":        filepath,
        "format":      parsed["format"],
        "stats":       stats,
        "threats":     threats,
        "events":      parsed["events"],
        "analyzed_at": datetime.now().isoformat(),
    }


def analyze_files(filepaths: list) -> list:
    results = []
    for fp in filepaths:
        print(f"\n[+] Analyzing: {fp}")
        results.append(analyze_file(fp))
    return results


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Log Analysis Tool — detect threats in system/web/Windows logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_analyzer.py auth.log
  python log_analyzer.py access.log auth.log --output results.json
  python log_analyzer.py *.log --report report.html
        """,
    )
    parser.add_argument("logs", nargs="+", help="Log file(s) to analyze")
    parser.add_argument("--output", "-o", help="Save JSON results to file")
    parser.add_argument("--report", "-r", help="Generate HTML report")
    parser.add_argument("--threshold", "-t", type=int, default=5,
                        help="Brute-force failed-login threshold (default: 5)")
    args = parser.parse_args()

    global BRUTE_FORCE_THRESHOLD
    BRUTE_FORCE_THRESHOLD = args.threshold

    print("=" * 60)
    print("  Log Analysis Tool")
    print("=" * 60)

    results = analyze_files(args.logs)

    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    total_threats = sum(len(r.get("threats", [])) for r in results)
    print(f"  Files analyzed : {len(results)}")
    print(f"  Total threats  : {total_threats}")

    severity_counts = defaultdict(int)
    for r in results:
        for t in r.get("threats", []):
            severity_counts[t["severity"]] += 1

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if severity_counts[sev]:
            print(f"  {sev:10s}    : {severity_counts[sev]}")

    if total_threats:
        print("\n  TOP THREATS:")
        shown = 0
        for r in results:
            for t in r.get("threats", []):
                print(f"  [{t['severity']}] {t['description']}")
                shown += 1
                if shown >= 10:
                    break

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[+] JSON saved → {args.output}")

    if args.report:
        try:
            from report_generator import generate_html_report
            generate_html_report(results, args.report)
            print(f"[+] HTML report  → {args.report}")
        except ImportError:
            print("[!] report_generator.py not found — skipping HTML report")

    print()
    return 0 if total_threats == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
