"""
Minimal UI: trigger a scan, view the report. Deploy this to Nebius
Serverless Endpoints for your live demo URL.
"""

from fastapi import FastAPI
from dotenv import load_dotenv

from probes.prompt_injection import PromptInjectionProbe
from report.generator import build_report

load_dotenv()
app = FastAPI(title="Agent Safety Auditor")


@app.get("/")
def root():
    return {"status": "ok", "message": "POST /scan to run a scan against the toy agent"}


@app.post("/scan")
def scan():
    findings = PromptInjectionProbe().run(manifest=None)
    report = build_report("toy_agent/vulnerable_agent.py", findings)
    return report
