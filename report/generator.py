"""
Component 4: turns findings from ALL probes into the final scan report.
"""

import json
from dataclasses import asdict
from datetime import datetime, timezone


def build_report(repo_url: str, findings: list) -> dict:
    return {
        "repo": repo_url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "findings": [asdict(f) for f in findings],
    }


def save_report(report: dict, path: str = "reports/latest.json") -> None:
    import os
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)


def run_all_probes(manifest=None) -> list:
    """
    Runs every registered probe against the target and collects all findings.
    Add new probe classes to PROBE_CLASSES as you build them.
    """
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

    findings = []
    for probe_cls in PROBE_CLASSES:
        probe = probe_cls()
        findings.extend(probe.run(manifest=manifest))
    return findings


if __name__ == "__main__":
    findings = run_all_probes()
    report = build_report("toy_agent/vulnerable_agent.py", findings)
    save_report(report)
    print(json.dumps(report, indent=2))