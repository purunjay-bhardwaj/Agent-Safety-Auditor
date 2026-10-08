"""
Component 4: turns findings from ALL probes into the final scan report,
including an aggregate risk score.
"""

import json
from dataclasses import asdict
from datetime import datetime, timezone

# Points contributed per finding, scaled by the model's own confidence.
# Capped at 100 total so the score stays a readable 0-100 scale regardless
# of how many probes are run.
_SEVERITY_POINTS = {"high": 20, "medium": 10, "low": 2}


def compute_risk_score(findings: list) -> dict:
    """
    Returns {"score": int 0-100, "grade": "A".."F"}. Score sums each
    finding's severity weight scaled by confidence, capped at 100.
    """
    raw = sum(_SEVERITY_POINTS.get(f.severity, 0) * f.confidence for f in findings)
    score = min(100, round(raw))

    if score >= 80:
        grade = "F"
    elif score >= 60:
        grade = "D"
    elif score >= 40:
        grade = "C"
    elif score >= 20:
        grade = "B"
    else:
        grade = "A"

    return {"score": score, "grade": grade}


def build_report(repo_url: str, findings: list) -> dict:
    return {
        "repo": repo_url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "risk": compute_risk_score(findings),
        "findings": sorted(
            [asdict(f) for f in findings],
            key=lambda f: {"high": 0, "medium": 1, "low": 2}.get(f["severity"], 3),
        ),
    }


def save_report(report: dict, path: str = "reports/latest.json") -> None:
    import os
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)


def run_all_probes(target_path=None, manifest=None) -> list:
    """
    Parses the target agent (defaults to the bundled toy agent) and runs
    every registered probe against the tools it finds.
    """
    from pathlib import Path

    from ingest.parser import parse_file
    from sandbox.runner import TOY_AGENT_PATH
    from probes.prompt_injection import PromptInjectionProbe
    from probes.excessive_permissions import ExcessivePermissionsProbe
    from probes.secret_leakage import SecretLeakageProbe
    from probes.unconfirmed_destructive_actions import UnconfirmedDestructiveActionsProbe
    from probes.missing_rate_limits import MissingRateLimitsProbe

    PROBE_CLASSES = [
        PromptInjectionProbe,
        ExcessivePermissionsProbe,
        SecretLeakageProbe,
        UnconfirmedDestructiveActionsProbe,
        MissingRateLimitsProbe,
    ]

    target_path = Path(target_path or TOY_AGENT_PATH)
    manifest = manifest or parse_file(str(target_path))

    findings = []
    for probe_cls in PROBE_CLASSES:
        findings.extend(probe_cls().run(manifest, target_path))
    return findings


if __name__ == "__main__":
    findings = run_all_probes()
    report = build_report("toy_agent/vulnerable_agent.py", findings)
    save_report(report)
    print(json.dumps(report, indent=2))