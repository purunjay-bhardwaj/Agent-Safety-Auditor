"""
Minimal UI: trigger a scan, view a formal audit-report-styled page.
Deploy this to Nebius Serverless Endpoints for your live demo URL.
"""

import hashlib
import json
import os
import threading
from datetime import datetime, timezone

from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse
from dotenv import load_dotenv

from report.generator import run_all_probes, build_report

load_dotenv()
app = FastAPI(title="Agent Safety Auditor")

_CACHE_PATH = "reports/latest.json"
_SEVERITY_INK = {"high": "#B3261E", "medium": "#9A6500", "low": "#1E7A4C"}

# Simple in-memory scan state. Fine for a single-demo instance; not meant
# to coordinate multiple concurrent scans across many users.
_scan_state = {"running": False}


def _load_or_run_report() -> dict:
    """
    Serves the cached scan instantly if one exists AND matches the current
    report shape. Falls back to a fresh scan if the cache is missing,
    corrupt, or stale rather than crashing on a KeyError.
    """
    if os.path.exists(_CACHE_PATH):
        try:
            with open(_CACHE_PATH) as f:
                cached = json.load(f)
            if "risk" in cached and "findings" in cached:
                return cached
        except (json.JSONDecodeError, OSError):
            pass
    return _run_fresh_report()


def _run_fresh_report() -> dict:
    findings = run_all_probes()
    report = build_report("toy_agent/vulnerable_agent.py", findings)
    os.makedirs(os.path.dirname(_CACHE_PATH), exist_ok=True)
    with open(_CACHE_PATH, "w") as f:
        json.dump(report, f, indent=2)
    return report


def _background_scan():
    _scan_state["running"] = True
    try:
        _run_fresh_report()
    finally:
        _scan_state["running"] = False


def _report_ref(repo: str, scanned_at: str) -> str:
    digest = hashlib.sha256(f"{repo}{scanned_at}".encode()).hexdigest()[:4].upper()
    year = datetime.now(timezone.utc).year
    return f"ASA-{year}-{digest}"


@app.get("/")
def root():
    return {"status": "ok", "message": "GET /report for the audit report, POST /scan for raw JSON"}


@app.post("/scan")
def scan():
    findings = run_all_probes()
    return build_report("toy_agent/vulnerable_agent.py", findings)


@app.get("/scan-status")
def scan_status():
    return {"running": _scan_state["running"]}


@app.get("/rescan", response_class=HTMLResponse)
def rescan(background_tasks: BackgroundTasks):
    """Kicks off a fresh scan in the background and shows a live-updating spinner page."""
    if not _scan_state["running"]:
        background_tasks.add_task(_background_scan)
    return _scanning_page_html()


def _scanning_page_html() -> str:
    return """
    <html>
    <head>
      <title>Scanning… — Agent Safety Audit</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Source+Serif+4:opsz,wght@8..60,400;8..60,600&family=Inter:wght@400;500;600&display=swap">
      <style>
        :root { --paper: #F6F7F9; --ink: #14181F; --ink-muted: #5B6270; --rule: #E2E4E9; }
        body { margin: 0; background: var(--paper); color: var(--ink); font-family: 'Inter', -apple-system, sans-serif;
               display: flex; align-items: center; justify-content: center; height: 100vh; text-align: center; }
        h1 { font-family: 'Source Serif 4', serif; font-weight: 600; font-size: 24px; margin: 24px 0 8px; }
        p { color: var(--ink-muted); font-size: 14px; }
        .spinner { width: 28px; height: 28px; border: 3px solid var(--rule); border-top-color: var(--ink);
                   border-radius: 50%; margin: 0 auto; animation: spin 0.8s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        @media (prefers-reduced-motion: reduce) { .spinner { animation: none; border-top-color: var(--rule); } }
      </style>
    </head>
    <body>
      <div>
        <div class="spinner"></div>
        <h1>Running the audit</h1>
        <p>Adversarial probes are executing against the real sandbox — this takes a minute.</p>
      </div>
      <script>
        async function poll() {
          const res = await fetch('/scan-status');
          const data = await res.json();
          if (!data.running) {
            window.location.href = '/report';
          } else {
            setTimeout(poll, 1500);
          }
        }
        setTimeout(poll, 1500);
      </script>
    </body>
    </html>
    """


@app.get("/report", response_class=HTMLResponse)
def report_page():
    report = _load_or_run_report()
    risk = report["risk"]
    ref = _report_ref(report["repo"], report["scanned_at"])

    scanned_dt = datetime.fromisoformat(report["scanned_at"])
    scanned_display = scanned_dt.strftime("%-d %B %Y, %H:%M UTC")

    entries = ""
    for i, f in enumerate(report["findings"], start=1):
        color = _SEVERITY_INK.get(f["severity"], "#5B6270")
        title = f["probe_class"].replace("_", " ").title()
        parts = f["evidence"].split(" | ", 1)
        narrative = parts[0]
        trace_detail = parts[1] if len(parts) > 1 else ""
        source_html = (
            f'<a class="source" href="{f["source"]}" target="_blank" rel="noopener">{f["source"].split("//")[-1][:60]}</a>'
            if f.get("source") else ""
        )
        trace_html = (
            f'<details class="evidence-detail"><summary>View evidence trace</summary>'
            f'<pre>{trace_detail}</pre></details>'
            if trace_detail else ""
        )
        entries += f"""
        <div class="finding" data-severity="{f['severity']}">
          <div class="finding-head">
            <span class="finding-num">{i:02d}</span>
            <span class="finding-title">{title}</span>
            <span class="severity-mark" style="color:{color}">[ {f['severity'].upper()} ]</span>
          </div>
          <div class="finding-meta">tool: {f['tool']}{f" at {f['file']}:{f['line']}" if f.get('file') else ""}, confidence: {f['confidence']:.0%}</div>
          <p class="narrative">{narrative}</p>
          {f'<p class="narrative"><strong>Suggested fix:</strong> {f["fix"]}</p>' if f.get("fix") else ""}
          {trace_html}
          {source_html}
        </div>
        """

    html = f"""
    <html>
    <head>
      <title>Agent Safety Audit — {ref}</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Source+Serif+4:opsz,wght@8..60,400;8..60,600&family=Inter:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap">
      <style>
        :root {{
          --paper: #F6F7F9; --surface: #FFFFFF; --ink: #14181F; --ink-muted: #5B6270; --rule: #E2E4E9;
        }}
        * {{ box-sizing: border-box; }}
        body {{
          margin: 0; background: var(--paper); color: var(--ink);
          font-family: 'Inter', -apple-system, sans-serif; -webkit-font-smoothing: antialiased;
        }}
        .sheet {{ max-width: 680px; margin: 0 auto; padding: 56px 24px 80px; }}
        header {{ border-bottom: 1px solid var(--rule); padding-bottom: 24px; margin-bottom: 32px; }}
        .header-row {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }}
        .rescan-btn {{
          display: inline-block; font-family: 'Inter', sans-serif; font-size: 13px; font-weight: 600;
          color: var(--ink); text-decoration: none; border: 1px solid var(--ink); border-radius: 6px;
          padding: 10px 16px; white-space: nowrap;
          transition: background-color 0.15s ease, color 0.15s ease, transform 0.15s ease, box-shadow 0.15s ease;
        }}
        .rescan-btn:hover {{
          background-color: var(--ink); color: var(--paper);
          transform: translateY(-1px); box-shadow: 0 4px 10px rgba(20,24,31,0.15);
        }}
        h1 {{ font-family: 'Source Serif 4', serif; font-weight: 600; font-size: 30px; margin: 0 0 8px; letter-spacing: -0.01em; }}
        .doc-meta {{ color: var(--ink-muted); font-size: 14px; line-height: 1.6; }}
        .doc-meta .ref {{ font-family: 'IBM Plex Mono', monospace; font-size: 13px; }}
        .section-row {{ display: flex; align-items: baseline; justify-content: space-between; margin-bottom: 16px; }}
        .section-label {{ font-size: 12px; font-weight: 600; letter-spacing: 0.08em; color: var(--ink-muted); }}
        .filters {{ display: flex; gap: 4px; }}
        .filter-btn {{
          background: none; border: none; font-family: 'Inter', sans-serif; font-size: 12px;
          color: var(--ink-muted); padding: 2px 8px; cursor: pointer; border-bottom: 2px solid transparent;
        }}
        .filter-btn.active {{ color: var(--ink); border-bottom-color: var(--ink); font-weight: 600; }}
        .summary {{
          border: 1px solid var(--rule); border-radius: 4px; padding: 24px; margin-bottom: 40px;
          display: flex; align-items: baseline; gap: 20px;
        }}
        .grade {{ font-family: 'Source Serif 4', serif; font-weight: 600; font-size: 44px; line-height: 1; }}
        .summary-text {{ font-size: 15px; line-height: 1.6; }}
        .summary-text .score {{ color: var(--ink-muted); }}
        .findings {{ margin-bottom: 48px; animation: reveal 0.4s ease-out; }}
        @keyframes reveal {{ from {{ opacity: 0; transform: translateY(6px); }} to {{ opacity: 1; transform: translateY(0); }} }}
        @media (prefers-reduced-motion: reduce) {{ .findings {{ animation: none; }} }}
        .finding {{
          padding: 20px 12px; margin: 0 -12px; border-bottom: 1px solid var(--rule);
          border-radius: 4px; transition: background-color 0.15s ease;
        }}
        .finding:hover {{ background-color: var(--surface); }}
        .finding:first-child {{ padding-top: 0; }}
        .finding.hidden {{ display: none; }}
        .finding-head {{ display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; margin-bottom: 4px; }}
        .finding-num {{ font-family: 'IBM Plex Mono', monospace; font-size: 13px; color: var(--ink-muted); }}
        .finding-title {{ font-weight: 600; font-size: 16px; }}
        .severity-mark {{ font-family: 'IBM Plex Mono', monospace; font-size: 12px; font-weight: 500; margin-left: auto; }}
        .finding-meta {{ font-size: 13px; color: var(--ink-muted); margin-bottom: 10px; }}
        .narrative {{ font-size: 15px; line-height: 1.6; margin: 0 0 10px; }}
        .evidence-detail {{ margin-bottom: 10px; }}
        .evidence-detail summary {{
          font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: var(--ink-muted);
          cursor: pointer; user-select: none;
        }}
        .evidence-detail summary:hover {{ color: var(--ink); }}
        .evidence-detail pre {{
          font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: var(--ink);
          background: var(--surface); border: 1px solid var(--rule); border-radius: 4px;
          padding: 12px; margin-top: 8px; white-space: pre-wrap; word-break: break-word; overflow-x: auto;
        }}
        .source {{
          font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: var(--ink-muted);
          text-decoration: underline; text-underline-offset: 3px;
        }}
        footer {{ border-top: 1px solid var(--rule); padding-top: 20px; font-size: 13px; color: var(--ink-muted); line-height: 1.6; }}
        @media (max-width: 480px) {{
          .sheet {{ padding: 32px 18px 56px; }}
          h1 {{ font-size: 24px; }}
          .grade {{ font-size: 36px; }}
          .summary {{ flex-direction: column; gap: 8px; }}
          .section-row {{ flex-direction: column; align-items: flex-start; gap: 8px; }}
          .header-row {{ flex-direction: column; }}
          .rescan-btn {{ align-self: flex-start; }}
        }}
      </style>
    </head>
    <body>
      <div class="sheet">
        <header>
          <div class="header-row">
            <div>
              <h1>Agent Safety Audit</h1>
              <div class="doc-meta">
                Target: {report['repo']}<br>
                Scanned {scanned_display} &nbsp; <span class="ref">Ref {ref}</span>
              </div>
            </div>
            <a class="rescan-btn" href="/rescan">Run fresh scan</a>
          </div>
        </header>

        <div class="section-label">EXECUTIVE SUMMARY</div>
        <div class="summary">
          <div class="grade" style="color: {_SEVERITY_INK['high'] if risk['grade'] in ('F','D') else ('#9A6500' if risk['grade']=='C' else '#1E7A4C')}">{risk['grade']}</div>
          <div class="summary-text">
            <span class="score">Risk score {risk['score']}/100 &nbsp;·&nbsp; {len(report['findings'])} findings across 5 vulnerability classes</span>
          </div>
        </div>

        <div class="section-row">
          <div class="section-label">FINDINGS</div>
          <div class="filters">
            <button class="filter-btn active" data-filter="all">All</button>
            <button class="filter-btn" data-filter="high">High</button>
            <button class="filter-btn" data-filter="medium">Medium</button>
            <button class="filter-btn" data-filter="low">Low</button>
          </div>
        </div>
        <div class="findings" id="findings">
          {entries}
        </div>

        <footer>
          Findings generated by adversarial probes built with NVIDIA Nemotron on Nebius Token Factory, executed in isolated Token Factory Sandboxes, and grounded in current threat intelligence via Tavily search.
        </footer>
      </div>
      <script>
        document.querySelectorAll('.filter-btn').forEach(btn => {{
          btn.addEventListener('click', () => {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const filter = btn.dataset.filter;
            document.querySelectorAll('.finding').forEach(card => {{
              const match = filter === 'all' || card.dataset.severity === filter;
              card.classList.toggle('hidden', !match);
            }});
          }});
        }});
      </script>
    </body>
    </html>
    """
    return html