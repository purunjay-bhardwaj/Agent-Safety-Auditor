"""
Offline benchmark checks: the toy agent's planted vulnerabilities are all
found at the right line, and the hardened repo produces no false positives.
"""

import json
import os
from pathlib import Path

os.environ["USE_REAL_SANDBOX"] = "false"
os.environ["AUDITOR_OFFLINE"] = "true"

from benchmark.run import GROUND_TRUTH, ROOT, score_repo
from report.generator import run_all_probes


def _repo(name):
    return next(r for r in json.loads(GROUND_TRUTH.read_text())["repos"] if r["name"] == name)


def test_toy_agent_all_planted_found_with_location_and_fix():
    repo = _repo("toy_agent")
    result = score_repo(repo, run_all_probes(target_path=ROOT / repo["entry"]))
    assert result["missed"] == []
    assert result["false_positives"] == []
    assert all(d["location_correct"] and d["has_fix"] for d in result["detected"])


def test_hardened_repo_has_no_false_positives():
    repo = _repo("hardened_file_manager")
    result = score_repo(repo, run_all_probes(target_path=ROOT / repo["entry"]))
    assert result["false_positives"] == []
