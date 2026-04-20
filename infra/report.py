#!/usr/bin/env python3
"""
Purple Lab Lite — Detection Coverage Report Generator
Queries Elasticsearch for evidence of each attack playbook and produces
a self-contained HTML report scored as Detected / Partial / Missed.

Usage:
    python3 report.py
    python3 report.py --elastic http://localhost:9200 --index dvwa-raw-* --output report.html
    python3 report.py --window 60  # look back 60 minutes
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Playbook definitions
# Each entry maps a human-readable name to the Elastic query terms that
# indicate the attack was executed and logged. Add new playbooks here.
# ---------------------------------------------------------------------------
PLAYBOOKS = [
    {
        "id": "sqli",
        "name": "SQL Injection",
        "mitre": "T1190",
        "tactic": "Initial Access",
        "tool": "curl (custom)",
        # Keywords derived from the actual sqli_attack.sh payloads:
        # - /vulnerabilities/sqli/ is the target endpoint
        # - OR+1%3D1 is the URL-encoded form of OR 1=1
        # - user_token appears in every authenticated DVWA request
        # - security=low is sent as a cookie on every attack request
        "keywords": ["vulnerabilities/sqli", "OR+1", "1%3D1", "user_token", "security=low"],
        "min_hits": 3,
    },
    {
        "id": "port_scan",
        "name": "Port Scan / Recon",
        "mitre": "T1046",
        "tactic": "Discovery",
        "tool": "nmap",
        "keywords": ["nmap", "SYN", "port scan", "Nmap scan report"],
        "min_hits": 5,
    },
    {
        "id": "bruteforce",
        "name": "HTTP Brute Force",
        "mitre": "T1110.001",
        "tactic": "Credential Access",
        "tool": "curl (custom)",
        # bruteforce.sh hammers POST /login.php with many user_token + credential pairs.
        # Each failed attempt returns a redirect back to login.php (Location header).
        # Successful login redirects to index.php. All requests carry a PHPSESSID cookie.
        "keywords": ["login.php", "PHPSESSID", "Login=Login", "user_token"],
        "min_hits": 10,
    },
]

# ---------------------------------------------------------------------------
# Elastic query helpers
# ---------------------------------------------------------------------------

def build_query(keywords: list[str], window_minutes: int) -> dict:
    """Build an Elastic bool query that matches any keyword in the message field."""
    since = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return {
        "query": {
            "bool": {
                "must": [
                    {
                        "bool": {
                            "should": [
                                {"match_phrase": {"message": kw}} for kw in keywords
                            ],
                            "minimum_should_match": 1,
                        }
                    }
                ],
                "filter": [{"range": {"@timestamp": {"gte": since}}}],
            }
        },
        "size": 0,  # we only need the count
        "track_total_hits": True,
    }


def query_elastic(elastic_url: str, index: str, query: dict) -> int:
    """Run a query against Elastic and return the hit count. Returns -1 on error."""
    url = f"{elastic_url.rstrip('/')}/{index}/_search"
    body = json.dumps(query).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data["hits"]["total"]["value"]
    except urllib.error.URLError as e:
        print(f"  [!] Elastic connection error: {e}", file=sys.stderr)
        return -1
    except (KeyError, json.JSONDecodeError) as e:
        print(f"  [!] Unexpected response: {e}", file=sys.stderr)
        return -1


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score_playbook(hits: int, min_hits: int) -> tuple[str, str]:
    """Return (status_label, css_class) based on hit count."""
    if hits < 0:
        return "Error", "error"
    if hits == 0:
        return "Missed", "missed"
    if hits < min_hits:
        return "Partial", "partial"
    return "Detected", "detected"


# ---------------------------------------------------------------------------
# HTML report template
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Purple Lab Lite — Detection Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;700;800&display=swap');

  :root {{
    --bg:        #0a0a0f;
    --surface:   #111118;
    --border:    #1e1e2e;
    --purple:    #9b59f5;
    --purple-dim:#5a3a8a;
    --green:     #00e5a0;
    --yellow:    #f5c842;
    --red:       #f5425a;
    --grey:      #6b6b80;
    --text:      #e0e0f0;
    --text-dim:  #7070a0;
    --mono:      'Share Tech Mono', monospace;
    --sans:      'Syne', sans-serif;
  }}

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    padding: 2rem;
  }}

  /* ── header ── */
  header {{
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 1rem;
    border-bottom: 1px solid var(--border);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
  }}
  .logo {{ display: flex; align-items: center; gap: 0.75rem; }}
  .logo-dot {{
    width: 14px; height: 14px; border-radius: 50%;
    background: var(--purple);
    box-shadow: 0 0 12px var(--purple);
  }}
  h1 {{ font-size: 1.6rem; font-weight: 800; letter-spacing: -0.02em; }}
  h1 span {{ color: var(--purple); }}
  .meta {{ font-family: var(--mono); font-size: 0.72rem; color: var(--text-dim); text-align: right; line-height: 1.8; }}

  /* ── summary bar ── */
  .summary {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 1rem;
    margin-bottom: 2.5rem;
  }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem 1rem;
    text-align: center;
  }}
  .stat-card .value {{ font-size: 2.4rem; font-weight: 800; line-height: 1; }}
  .stat-card .label {{ font-family: var(--mono); font-size: 0.68rem; color: var(--text-dim); margin-top: 0.4rem; text-transform: uppercase; letter-spacing: 0.08em; }}
  .stat-card.detected .value {{ color: var(--green); }}
  .stat-card.partial  .value {{ color: var(--yellow); }}
  .stat-card.missed   .value {{ color: var(--red); }}
  .stat-card.total    .value {{ color: var(--purple); }}

  /* ── coverage bar ── */
  .coverage-wrap {{ margin-bottom: 2.5rem; }}
  .coverage-label {{ font-family: var(--mono); font-size: 0.75rem; color: var(--text-dim); margin-bottom: 0.5rem; }}
  .coverage-bar {{ height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; display: flex; }}
  .coverage-bar .seg-detected {{ background: var(--green); }}
  .coverage-bar .seg-partial  {{ background: var(--yellow); }}
  .coverage-bar .seg-missed   {{ background: var(--red); }}
  .coverage-pct {{ font-size: 1.1rem; font-weight: 700; color: var(--green); margin-top: 0.4rem; }}

  /* ── playbook table ── */
  h2 {{ font-size: 1rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-dim); margin-bottom: 1rem; }}

  table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
  thead tr {{ border-bottom: 1px solid var(--purple-dim); }}
  thead th {{ text-align: left; font-family: var(--mono); font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-dim); padding: 0 1rem 0.75rem; }}
  tbody tr {{ border-bottom: 1px solid var(--border); transition: background 0.15s; }}
  tbody tr:hover {{ background: var(--surface); }}
  tbody td {{ padding: 1rem; vertical-align: middle; }}
  td.name {{ font-weight: 700; }}
  td.mitre {{ font-family: var(--mono); font-size: 0.78rem; color: var(--purple); }}
  td.tactic {{ font-family: var(--mono); font-size: 0.75rem; color: var(--text-dim); }}
  td.tool {{ font-family: var(--mono); font-size: 0.75rem; }}
  td.hits {{ font-family: var(--mono); font-size: 0.9rem; font-weight: 700; }}

  /* status badges */
  .badge {{
    display: inline-block;
    padding: 0.25em 0.7em;
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .badge.detected {{ background: rgba(0,229,160,0.12); color: var(--green); border: 1px solid rgba(0,229,160,0.3); }}
  .badge.partial  {{ background: rgba(245,200,66,0.12); color: var(--yellow); border: 1px solid rgba(245,200,66,0.3); }}
  .badge.missed   {{ background: rgba(245,66,90,0.12);  color: var(--red);    border: 1px solid rgba(245,66,90,0.3); }}
  .badge.error    {{ background: rgba(107,107,128,0.2); color: var(--grey);   border: 1px solid var(--border); }}

  /* ── footer ── */
  footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); font-family: var(--mono); font-size: 0.7rem; color: var(--text-dim); display: flex; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem; }}
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-dot"></div>
    <h1>Purple Lab <span>Lite</span></h1>
  </div>
  <div class="meta">
    <div>Generated: {generated_at}</div>
    <div>Index: {index}</div>
    <div>Window: last {window} min</div>
    <div>Elastic: {elastic_url}</div>
  </div>
</header>

<div class="summary">
  <div class="stat-card total">
    <div class="value">{total}</div>
    <div class="label">Playbooks run</div>
  </div>
  <div class="stat-card detected">
    <div class="value">{n_detected}</div>
    <div class="label">Detected</div>
  </div>
  <div class="stat-card partial">
    <div class="value">{n_partial}</div>
    <div class="label">Partial</div>
  </div>
  <div class="stat-card missed">
    <div class="value">{n_missed}</div>
    <div class="label">Missed</div>
  </div>
</div>

<div class="coverage-wrap">
  <div class="coverage-label">Detection coverage</div>
  <div class="coverage-bar">
    <div class="seg-detected" style="width:{pct_detected}%"></div>
    <div class="seg-partial"  style="width:{pct_partial}%"></div>
    <div class="seg-missed"   style="width:{pct_missed}%"></div>
  </div>
  <div class="coverage-pct">{coverage_score}% full coverage</div>
</div>

<h2>Playbook Results</h2>
<table>
  <thead>
    <tr>
      <th>Playbook</th>
      <th>MITRE</th>
      <th>Tactic</th>
      <th>Tool</th>
      <th>Log Hits</th>
      <th>Status</th>
    </tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>

<footer>
  <span>Purple Lab Lite — github.com/Incogn1toBro/Purple_Lab_Lite</span>
  <span>Elastic index: {index} · {total} playbooks evaluated</span>
</footer>

</body>
</html>
"""

ROW_TEMPLATE = """\
    <tr>
      <td class="name">{name}</td>
      <td class="mitre">{mitre}</td>
      <td class="tactic">{tactic}</td>
      <td class="tool">{tool}</td>
      <td class="hits" style="color:{hits_color}">{hits}</td>
      <td><span class="badge {css_class}">{status}</span></td>
    </tr>"""

HITS_COLORS = {
    "detected": "#00e5a0",
    "partial":  "#f5c842",
    "missed":   "#f5425a",
    "error":    "#6b6b80",
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Purple Lab Lite — generate a detection coverage HTML report."
    )
    parser.add_argument("--elastic", default="http://localhost:9200", help="Elasticsearch URL")
    parser.add_argument("--index",   default="dvwa-raw-*",           help="Elastic index pattern")
    parser.add_argument("--output",  default="report.html",          help="Output HTML file")
    parser.add_argument("--window",  default=60, type=int,           help="Look-back window in minutes")
    args = parser.parse_args()

    print(f"[*] Purple Lab Lite — Detection Report Generator")
    print(f"    Elastic : {args.elastic}")
    print(f"    Index   : {args.index}")
    print(f"    Window  : last {args.window} minutes")
    print()

    results = []
    for pb in PLAYBOOKS:
        print(f"  [~] Querying: {pb['name']} ({pb['mitre']}) ...", end=" ", flush=True)
        q = build_query(pb["keywords"], args.window)
        hits = query_elastic(args.elastic, args.index, q)
        status, css_class = score_playbook(hits, pb["min_hits"])
        results.append({**pb, "hits": hits, "status": status, "css_class": css_class})
        marker = {"Detected": "✅", "Partial": "⚠️", "Missed": "❌", "Error": "💔"}[status]
        print(f"{marker}  {status} ({hits} hits)")

    # Tally
    n_detected = sum(1 for r in results if r["status"] == "Detected")
    n_partial  = sum(1 for r in results if r["status"] == "Partial")
    n_missed   = sum(1 for r in results if r["status"] in ("Missed", "Error"))
    total      = len(results)

    pct_detected = round(n_detected / total * 100) if total else 0
    pct_partial  = round(n_partial  / total * 100) if total else 0
    pct_missed   = 100 - pct_detected - pct_partial
    coverage_score = pct_detected

    # Build table rows
    rows = "\n".join(
        ROW_TEMPLATE.format(
            name=r["name"],
            mitre=r["mitre"],
            tactic=r["tactic"],
            tool=r["tool"],
            hits=str(r["hits"]) if r["hits"] >= 0 else "—",
            hits_color=HITS_COLORS[r["css_class"]],
            status=r["status"],
            css_class=r["css_class"],
        )
        for r in results
    )

    # Render report
    html = HTML_TEMPLATE.format(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        index=args.index,
        window=args.window,
        elastic_url=args.elastic,
        total=total,
        n_detected=n_detected,
        n_partial=n_partial,
        n_missed=n_missed,
        pct_detected=pct_detected,
        pct_partial=pct_partial,
        pct_missed=pct_missed,
        coverage_score=coverage_score,
        rows=rows,
    )

    out_path = Path(args.output)
    out_path.write_text(html, encoding="utf-8")
    print()
    print(f"[+] Report written to: {out_path.resolve()}")
    print(f"    Coverage: {coverage_score}% fully detected ({n_detected}/{total} playbooks)")


if __name__ == "__main__":
    main()
