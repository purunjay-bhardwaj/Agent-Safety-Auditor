"""
Benchmark target: a code-interpreter agent.

Planted: run_python executes arbitrary Python with no restriction
(excessive permissions). It IS rate limited, so there is no rate-limit
vulnerability. No agent loop.
"""

import subprocess
import sys
import time

_WINDOW_SECONDS = 60
_MAX_RUNS = 5
_runs: list[float] = []


def run_python(code: str) -> str:
    """Execute a Python snippet and return its output."""
    now = time.time()
    _runs[:] = [t for t in _runs if now - t < _WINDOW_SECONDS]
    if len(_runs) >= _MAX_RUNS:
        raise RuntimeError("Too many executions; slow down")
    _runs.append(now)
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=10)
    return proc.stdout + proc.stderr


def format_code(code: str) -> str:
    """Normalize indentation of a snippet."""
    return "\n".join(line.rstrip() for line in code.splitlines())


TOOLS = {"run_python": run_python, "format_code": format_code}
