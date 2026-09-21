"""
Component 4: turns a list of Finding objects into the final scan report.
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


if __name__ == "__main__":
    from probes.prompt_injection import PromptInjectionProbe

    findings = PromptInjectionProbe().run(manifest=None)
    report = build_report("toy_agent/vulnerable_agent.py", findings)
    save_report(report)
    print(json.dumps(report, indent=2))
