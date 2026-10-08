"""
Scores the auditor against the planted vulnerabilities in ground_truth.json.

    python -m benchmark.run              # live: Nemotron + Tavily, sandbox per .env
    python -m benchmark.run --offline    # deterministic payloads and scoring, no API calls
    python -m benchmark.run --local      # local subprocess instead of Token Factory Sandboxes

A finding counts as a detection when its severity is medium/high and its
(class, tool) matches a planted vulnerability; any other medium/high
finding is a false positive. Results are written to benchmark/results/.
"""

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent
GROUND_TRUTH = Path(__file__).parent / "ground_truth.json"
RESULTS_DIR = Path(__file__).parent / "results"


def score_repo(repo: dict, findings: list) -> dict:
    planted = {(p["class"], p["tool"]): p for p in repo["planted"]}
    flagged = [f for f in findings if f.severity != "low"]

    detected, false_positives = [], []
    for f in flagged:
        key = (f.probe_class, f.tool)
        if key in planted:
            gt = planted[key]
            detected.append({
                "class": f.probe_class, "tool": f.tool,
                "reported": f"{f.file}:{f.line}", "expected": f"{repo['entry']}:{gt['line']}",
                "location_correct": f.file == repo["entry"] and f.line == gt["line"],
                "has_fix": bool(f.fix),
            })
        else:
            false_positives.append({"class": f.probe_class, "tool": f.tool, "evidence": f.evidence[:300]})

    detected_keys = {(d["class"], d["tool"]) for d in detected}
    missed = [{"class": c, "tool": t} for (c, t) in planted if (c, t) not in detected_keys]
    return {
        "repo": repo["name"],
        "planted": len(planted),
        "detected": detected,
        "missed": missed,
        "false_positives": false_positives,
        "probes_run": len(findings),
    }


def summarize(per_repo: list) -> dict:
    planted = sum(r["planted"] for r in per_repo)
    detected = [d for r in per_repo for d in r["detected"]]
    by_class = Counter()
    found_by_class = Counter()
    for r in per_repo:
        for d in r["detected"]:
            found_by_class[d["class"]] += 1
        for key in [(d["class"]) for d in r["detected"]] + [m["class"] for m in r["missed"]]:
            by_class[key] += 1
    return {
        "repos": len(per_repo),
        "planted": planted,
        "detected": len(detected),
        "detection_rate": round(100 * len(detected) / planted, 1) if planted else 0.0,
        "false_positives": sum(len(r["false_positives"]) for r in per_repo),
        "location_correct": sum(d["location_correct"] for d in detected),
        "with_fix": sum(d["has_fix"] for d in detected),
        "by_class": {c: f"{found_by_class[c]}/{n}" for c, n in sorted(by_class.items())},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true", help="no Nemotron/Tavily calls")
    parser.add_argument("--local", action="store_true", help="local subprocess instead of real sandboxes")
    args = parser.parse_args()

    if args.offline:
        os.environ["AUDITOR_OFFLINE"] = "true"
    if args.local:
        os.environ["USE_REAL_SANDBOX"] = "false"

    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT))
    from report.generator import run_all_probes

    ground_truth = json.loads(GROUND_TRUTH.read_text())
    per_repo = []
    for repo in ground_truth["repos"]:
        print(f"scanning {repo['name']} ...", flush=True)
        findings = run_all_probes(target_path=ROOT / repo["entry"])
        per_repo.append(score_repo(repo, findings))

    summary = summarize(per_repo)
    mode = {
        "llm": "offline" if os.environ.get("AUDITOR_OFFLINE") == "true" else "nemotron+tavily",
        "sandbox": "token-factory" if os.environ.get("USE_REAL_SANDBOX", "false").lower() == "true" else "local-subprocess",
    }
    result = {"run_at": datetime.now(timezone.utc).isoformat(), "mode": mode, "summary": summary, "repos": per_repo}

    RESULTS_DIR.mkdir(exist_ok=True)
    out = RESULTS_DIR / f"{mode['llm']}_{mode['sandbox']}.json"
    out.write_text(json.dumps(result, indent=2))

    print(f"\nmode: {mode}")
    for r in per_repo:
        print(f"  {r['repo']:<24} planted {r['planted']}  detected {len(r['detected'])}  "
              f"missed {[m['class'] + ':' + m['tool'] for m in r['missed']]}  "
              f"FP {[f['class'] + ':' + f['tool'] for f in r['false_positives']]}")
    print(json.dumps(summary, indent=2))
    print(f"written to {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
