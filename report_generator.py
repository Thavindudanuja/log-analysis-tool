#!/usr/bin/env python3
"""
Report Generator for Log Analysis Tool
Produces a self-contained HTML report with charts and threat tables.
"""

import json
import html
from datetime import datetime
from collections import defaultdict
from pathlib import Path


SEVERITY_COLOR = {
    "CRITICAL": ("#7c1010", "#fef2f2", "#fca5a5"),
    "HIGH":     ("#92400e", "#fffbeb", "#fcd34d"),
    "MEDIUM":   ("#1e3a8a", "#eff6ff", "#93c5fd"),
    "LOW":      ("#166534", "#f0fdf4", "#86efac"),
}

THREAT_ICON = {
    "brute_force":        "🔨",
    "possible_compromise": "🚨",
    "web_attack":         "🌐",
    "credential_stuffing": "🔑",
    "account_change":     "👤",
    "other":              "⚠️",
}


def _esc(s) -> str:
    return html.escape(str(s)) if s is not None else "—"


def _bar_chart(data: dict, title: str, color: str = "#3b82f6") -> str:
    if not data:
        return f'<p class="empty">No data</p>'
    total = max(data.values()) or 1
    rows = ""
    for label, val in list(data.items())[:10]:
        pct = int(val / total * 100)
        rows += f"""
        <div class="bar-row">
          <span class="bar-label" title="{_esc(label)}">{_esc(label[:40])}</span>
          <div class="bar-track">
            <div class="bar-fill" style="width:{pct}%;background:{color}"></div>
          </div>
          <span class="bar-val">{val:,}</span>
        </div>"""
    return f'<div class="chart-title">{title}</div><div class="bar-chart">{rows}</div>'


def _status_pie_html(status_codes: dict) -> str:
    """Simple visual status code breakdown."""
    if not status_codes:
        return ""
    groups = defaultdict(int)
    for code, count in status_codes.items():
        groups[f"{code // 100}xx"] += count
    colors = {"2xx": "#22c55e", "3xx": "#3b82f6", "4xx": "#f59e0b", "5xx": "#ef4444"}
    total = sum(groups.values()) or 1
    items = ""
    for grp, cnt in sorted(groups.items()):
        pct = cnt / total * 100
        col = colors.get(grp, "#94a3b8")
        items += f"""
        <div class="pie-item">
          <span class="pie-dot" style="background:{col}"></span>
          <span class="pie-grp">{grp}</span>
          <span class="pie-count">{cnt:,}</span>
          <span class="pie-pct">({pct:.1f}%)</span>
        </div>"""
    return f'<div class="pie-legend">{items}</div>'


def generate_html_report(results: list, output_path: str):
    """Generate a self-contained HTML report from analyzer results."""

    # ── Aggregate across files ──────────────────────────────────────
    all_threats  = []
    total_events = 0
    total_files  = len(results)
    formats      = []
    agg_stats    = defaultdict(int)
    top_ips_agg  = defaultdict(int)
    top_users_agg = defaultdict(int)
    status_agg   = defaultdict(int)

    for r in results:
        if "error" in r:
            continue
        all_threats.extend(r.get("threats", []))
        s = r.get("stats", {})
        total_events += s.get("total_events", 0)
        formats.append(r.get("format", "unknown"))
        agg_stats["failed_logins"]      += s.get("failed_logins", 0)
        agg_stats["successful_logins"]  += s.get("successful_logins", 0)
        agg_stats["http_requests"]      += s.get("http_requests", 0)
        agg_stats["suspicious_requests"]+= s.get("suspicious_requests", 0)
        agg_stats["unique_ips"]         += s.get("unique_ips", 0)
        agg_stats["account_changes"]    += s.get("account_changes", 0)
        for ip, cnt in s.get("top_failing_ips", {}).items():
            top_ips_agg[ip]   += cnt
        for u, cnt in s.get("top_users_targeted", {}).items():
            top_users_agg[u]  += cnt
        for code, cnt in s.get("http_status_codes", {}).items():
            status_agg[code]  += cnt

    severity_counts = defaultdict(int)
    for t in all_threats:
        severity_counts[t["severity"]] += 1

    analyzed_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Metric cards ────────────────────────────────────────────────
    def metric(label, value, color="#1e3a8a"):
        return f"""
        <div class="metric-card">
          <div class="metric-value" style="color:{color}">{value:,}</div>
          <div class="metric-label">{label}</div>
        </div>"""

    metrics_html = (
        metric("Total Events", total_events) +
        metric("Files Analyzed", total_files) +
        metric("Failed Logins", agg_stats["failed_logins"], "#b45309") +
        metric("Successful Logins", agg_stats["successful_logins"], "#166534") +
        metric("HTTP Requests", agg_stats["http_requests"]) +
        metric("Suspicious Requests", agg_stats["suspicious_requests"], "#b91c1c") +
        metric("Unique IPs Seen", agg_stats["unique_ips"]) +
        metric("Total Threats", len(all_threats), "#7c1010")
    )

    # ── Severity summary ────────────────────────────────────────────
    sev_html = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cnt = severity_counts.get(sev, 0)
        text_col, bg_col, border_col = SEVERITY_COLOR[sev]
        sev_html += f"""
        <div class="sev-badge" style="background:{bg_col};border:1px solid {border_col};color:{text_col}">
          <span class="sev-label">{sev}</span>
          <span class="sev-count">{cnt}</span>
        </div>"""

    # ── Threats table ───────────────────────────────────────────────
    def threat_rows(threats):
        if not threats:
            return '<tr><td colspan="4" class="empty-row">No threats detected ✓</td></tr>'
        rows = ""
        for t in threats:
            sev = t.get("severity", "LOW")
            text_col, bg_col, _ = SEVERITY_COLOR[sev]
            icon = THREAT_ICON.get(t.get("type", "other"), "⚠️")
            rows += f"""
            <tr>
              <td>
                <span class="sev-pill" style="background:{bg_col};color:{text_col}">{sev}</span>
              </td>
              <td>{icon} {_esc(t.get("type","").replace("_"," ").title())}</td>
              <td><code>{_esc(t.get("ip") or "—")}</code></td>
              <td>{_esc(t.get("description",""))}</td>
            </tr>"""
        return rows

    # ── Per-file breakdown ──────────────────────────────────────────
    file_sections = ""
    for r in results:
        if "error" in r:
            file_sections += f'<div class="file-error">Error: {_esc(r["error"])}</div>'
            continue
        s = r.get("stats", {})
        ft = r.get("threats", [])
        fp = Path(r.get("file", "unknown")).name

        ip_chart   = _bar_chart(dict(list(s.get("top_failing_ips", {}).items())[:8]),
                                 "Top Failing IPs", "#ef4444")
        user_chart = _bar_chart(dict(list(s.get("top_users_targeted", {}).items())[:8]),
                                 "Most Targeted Users", "#f59e0b")
        path_chart = _bar_chart(dict(list(s.get("top_paths", {}).items())[:8]),
                                 "Top Requested Paths", "#8b5cf6")
        status_pie = _status_pie_html(s.get("http_status_codes", {}))

        charts_html = ""
        if s.get("top_failing_ips"):   charts_html += f'<div class="chart-box">{ip_chart}</div>'
        if s.get("top_users_targeted"):charts_html += f'<div class="chart-box">{user_chart}</div>'
        if s.get("top_paths"):         charts_html += f'<div class="chart-box">{path_chart}</div>'
        if s.get("http_status_codes"): charts_html += f'<div class="chart-box"><div class="chart-title">HTTP Status Distribution</div>{status_pie}</div>'

        file_sections += f"""
        <div class="file-section">
          <h2 class="file-title">📄 {_esc(fp)}</h2>
          <div class="file-meta">
            Format: <strong>{_esc(r.get("format","—"))}</strong> &nbsp;|&nbsp;
            Events: <strong>{s.get("total_events",0):,}</strong> &nbsp;|&nbsp;
            Threats: <strong>{len(ft)}</strong>
          </div>
          <div class="charts-grid">{charts_html}</div>
          <h3>Threats Detected</h3>
          <table class="threat-table">
            <thead><tr><th>Severity</th><th>Type</th><th>Source IP</th><th>Description</th></tr></thead>
            <tbody>{threat_rows(ft)}</tbody>
          </table>
        </div>"""

    # ── Full HTML ───────────────────────────────────────────────────
    html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Log Analysis Report — {analyzed_at}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#f8fafc;color:#1e293b;font-size:14px;line-height:1.6}}
  .header{{background:linear-gradient(135deg,#0f172a 0%,#1e3a8a 100%);color:#fff;padding:32px 40px}}
  .header h1{{font-size:24px;font-weight:700;letter-spacing:-0.5px}}
  .header .sub{{opacity:.7;font-size:13px;margin-top:4px}}
  .container{{max-width:1100px;margin:0 auto;padding:32px 24px}}
  h2{{font-size:18px;font-weight:600;color:#0f172a;margin:28px 0 12px}}
  h3{{font-size:15px;font-weight:600;color:#334155;margin:20px 0 8px}}
  .metrics-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:28px}}
  .metric-card{{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:16px 12px;text-align:center}}
  .metric-value{{font-size:28px;font-weight:700;color:#1e3a8a}}
  .metric-label{{font-size:11px;color:#64748b;margin-top:4px;text-transform:uppercase;letter-spacing:.5px}}
  .sev-row{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:28px}}
  .sev-badge{{border-radius:8px;padding:12px 20px;min-width:90px;text-align:center}}
  .sev-label{{display:block;font-size:11px;font-weight:700;letter-spacing:.5px}}
  .sev-count{{display:block;font-size:28px;font-weight:700}}
  .sev-pill{{border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700;letter-spacing:.3px}}
  .charts-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin:16px 0 24px}}
  .chart-box{{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:16px}}
  .chart-title{{font-size:12px;font-weight:700;color:#475569;text-transform:uppercase;letter-spacing:.5px;margin-bottom:12px}}
  .bar-chart{{display:flex;flex-direction:column;gap:6px}}
  .bar-row{{display:grid;grid-template-columns:140px 1fr 48px;align-items:center;gap:8px}}
  .bar-label{{font-size:12px;color:#475569;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
  .bar-track{{height:10px;background:#f1f5f9;border-radius:5px;overflow:hidden}}
  .bar-fill{{height:100%;border-radius:5px;transition:width .3s}}
  .bar-val{{font-size:12px;color:#64748b;text-align:right}}
  .pie-legend{{display:flex;flex-direction:column;gap:8px;padding-top:4px}}
  .pie-item{{display:flex;align-items:center;gap:8px;font-size:13px}}
  .pie-dot{{width:12px;height:12px;border-radius:50%;flex-shrink:0}}
  .pie-grp{{font-weight:600;min-width:32px}}
  .pie-count{{color:#475569;margin-left:auto}}
  .pie-pct{{color:#94a3b8;font-size:12px}}
  .threat-table{{width:100%;border-collapse:collapse;font-size:13px;background:#fff;border-radius:10px;overflow:hidden;border:1px solid #e2e8f0}}
  .threat-table th{{background:#f8fafc;padding:10px 14px;text-align:left;font-weight:600;color:#475569;border-bottom:2px solid #e2e8f0;font-size:11px;text-transform:uppercase;letter-spacing:.4px}}
  .threat-table td{{padding:10px 14px;border-bottom:1px solid #f1f5f9;vertical-align:top}}
  .threat-table tr:last-child td{{border-bottom:none}}
  .threat-table tr:hover td{{background:#f8fafc}}
  .empty-row{{text-align:center;color:#22c55e;padding:20px!important;font-weight:600}}
  .file-section{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:24px;margin-bottom:24px}}
  .file-title{{font-size:16px;font-weight:700;color:#0f172a;margin:0 0 8px}}
  .file-meta{{font-size:12px;color:#64748b;margin-bottom:16px}}
  .file-error{{background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:12px 16px;color:#b91c1c;margin-bottom:16px}}
  .footer{{text-align:center;color:#94a3b8;font-size:12px;padding:24px;border-top:1px solid #e2e8f0;margin-top:8px}}
  code{{background:#f1f5f9;padding:1px 5px;border-radius:4px;font-size:12px;font-family:monospace}}
  .empty{{color:#94a3b8;font-size:13px;font-style:italic;padding:8px 0}}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ Log Analysis Report</h1>
  <div class="sub">Generated: {analyzed_at} &nbsp;|&nbsp; Files: {total_files} &nbsp;|&nbsp; Total Events: {total_events:,}</div>
</div>

<div class="container">

  <h2>Overview</h2>
  <div class="metrics-grid">{metrics_html}</div>

  <h2>Threat Severity Summary</h2>
  <div class="sev-row">{sev_html}</div>

  <h2>All Threats (Aggregated)</h2>
  <table class="threat-table">
    <thead><tr><th>Severity</th><th>Type</th><th>Source IP</th><th>Description</th></tr></thead>
    <tbody>{threat_rows(all_threats)}</tbody>
  </table>

  <h2>Per-File Analysis</h2>
  {file_sections}

</div>
<div class="footer">
  Log Analysis Tool &nbsp;·&nbsp; Thavindu's Cybersecurity Portfolio &nbsp;·&nbsp; {analyzed_at}
</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_out)
    print(f"[+] Report written  → {output_path}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python report_generator.py results.json report.html")
        sys.exit(1)
    with open(sys.argv[1]) as f:
        data = json.load(f)
    generate_html_report(data, sys.argv[2])
