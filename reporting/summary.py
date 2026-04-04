from datetime import datetime, timedelta
from typing import Optional
from storage.db import AlertDatabase

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def generate_terminal_report(db: AlertDatabase, since: Optional[datetime] = None) -> None:
    stats = db.get_summary_stats(since)
    since_str = since.strftime("%Y-%m-%d %H:%M UTC") if since else "all time"

    print("\n" + "=" * 60)
    print(f"  THREAT DETECTION PIPELINE — SUMMARY REPORT")
    print(f"  Period: {since_str}")
    print("=" * 60)
    print(f"\n  Total Alerts Fired: {stats['total_alerts']}\n")

    print("  Alerts by Rule:")
    print(f"  {'Rule':<30} {'Count':>6}")
    print("  " + "-" * 38)
    for rule, count in stats["by_rule"].items():
        print(f"  {rule:<30} {count:>6}")

    print("\n  Alerts by Severity:")
    print(f"  {'Severity':<15} {'Count':>6}")
    print("  " + "-" * 23)
    for sev in SEVERITY_ORDER:
        count = stats["by_severity"].get(sev, 0)
        if count:
            print(f"  {sev:<15} {count:>6}")

    print("\n  Top Source IPs:")
    print(f"  {'IP':<20} {'Alerts':>6}")
    print("  " + "-" * 28)
    for entry in stats["top_source_ips"][:10]:
        print(f"  {entry['source_ip']:<20} {entry['count']:>6}")

    print("\n" + "=" * 60 + "\n")


def generate_html_report(db: AlertDatabase, output_path: str, since: Optional[datetime] = None) -> None:
    stats = db.get_summary_stats(since)
    alerts = db.get_alerts(since)
    since_str = since.strftime("%Y-%m-%d %H:%M UTC") if since else "All time"

    severity_colors = {
        "CRITICAL": "#cc0000",
        "HIGH": "#ff6600",
        "MEDIUM": "#e6ac00",
        "LOW": "#2d8a2d",
    }

    rows = ""
    for a in alerts:
        color = severity_colors.get(a.get("severity", ""), "#888")
        rows += f"""
        <tr>
          <td>{a.get('alerted_at','')[:19]}</td>
          <td>{a.get('rule_name','')}</td>
          <td><span style="color:{color};font-weight:bold">{a.get('severity','')}</span></td>
          <td>{a.get('source_ip','')}</td>
          <td>{a.get('username','')}</td>
          <td style="font-size:0.85em">{a.get('description','')}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Threat Detection Report</title>
<style>
  body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
  h1 {{ color: #58a6ff; }} h2 {{ color: #8b949e; border-bottom: 1px solid #30363d; padding-bottom:0.3em; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; }}
  th {{ background: #161b22; color: #8b949e; text-align:left; padding: 8px 12px; }}
  td {{ padding: 6px 12px; border-bottom: 1px solid #21262d; font-size:0.9em; }}
  tr:hover td {{ background: #161b22; }}
  .stat-box {{ display:inline-block; background:#161b22; border:1px solid #30363d; border-radius:6px; padding:1rem 2rem; margin:0.5rem; text-align:center; }}
  .stat-num {{ font-size:2rem; font-weight:bold; color:#58a6ff; }}
</style></head>
<body>
<h1>Threat Detection Pipeline — Report</h1>
<p style="color:#8b949e">Period: {since_str} &nbsp;|&nbsp; Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
<div class="stat-box"><div class="stat-num">{stats['total_alerts']}</div><div>Total Alerts</div></div>
<h2>Alert Detail</h2>
<table>
<thead><tr><th>Time</th><th>Rule</th><th>Severity</th><th>Source IP</th><th>User</th><th>Description</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</body></html>"""

    with open(output_path, "w") as f:
        f.write(html)
    print(f"[REPORT] HTML report written to {output_path}")


def run_scheduled_report(config: dict, db: AlertDatabase) -> None:
    since = datetime.utcnow() - timedelta(hours=24)
    fmt = config.get("reporting", {}).get("output_format", "terminal")
    if fmt == "html":
        out = config.get("reporting", {}).get("html_output_path", "report.html")
        generate_html_report(db, out, since)
    else:
        generate_terminal_report(db, since)
    print(f"[REPORT] Daily report generated at {datetime.utcnow().isoformat()}")
