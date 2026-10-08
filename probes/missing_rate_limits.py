"""
Vulnerability class 5: missing rate limits / loop guards.

Deterministic check — call a tool repeatedly in quick succession and see
whether anything throttles, errors, or backs off. No Nemotron needed:
"did N calls all succeed with no slowdown or refusal" is directly
observable, not a judgment call.

All N calls run inside ONE sandbox process: a fresh process per call would
reset any in-memory limiter and make every tool look unlimited.
"""

from probes.base import Probe, Finding, make_finding, search_context
from sandbox.runner import run_tool_calls_in_sandbox

_CALL_COUNT = 20
# Errors that mean a limiter refused the call, as opposed to the call
# failing for an unrelated reason (bad URL, connection refused, ...).
_RATE_LIMIT_MARKERS = ("rate limit", "ratelimit", "too many", "throttl", "quota", "slow down")
# Harmless argument per payload kind, so repeated calls have no side effects.
_SHELL_ARG = "echo rate-limit-probe"
_NETWORK_ARG = "http://127.0.0.1:9/"  # discard port: fails fast without leaving the machine


class MissingRateLimitsProbe(Probe):
    name = "missing_rate_limits"
    fix_template = (
        "Wrap `{tool}` in a rate limiter (e.g. at most N calls per minute per session) and "
        "raise a clear 'rate limit exceeded' error when the budget is spent."
    )

    def __init__(self, call_count: int = _CALL_COUNT):
        self.call_count = call_count

    def gather_context(self) -> list[dict]:
        return search_context("AI agent tool no rate limiting abuse denial of service 2026")

    def generate_payload(self, tool) -> dict:
        arg = _SHELL_ARG if "shell_exec" in tool.permissions else _NETWORK_ARG
        return {tool.params[0]: arg}

    def run(self, manifest, target_path) -> list[Finding]:
        candidates = [
            t for t in manifest.tools
            if t.params and ("shell_exec" in t.permissions or "network" in t.permissions)
        ]
        if not candidates:
            return []
        context = self.gather_context()
        findings = []
        for tool in candidates:
            tool_args = self.generate_payload(tool)
            calls = run_tool_calls_in_sandbox(tool.name, tool_args, self.call_count, target_path=target_path)
            limited = [c for c in calls if c["error"] and any(m in c["error"].lower() for m in _RATE_LIMIT_MARKERS)]

            if not limited:
                severity, confidence = "medium", 0.85
                reasoning = (
                    f"All {self.call_count} rapid-fire calls to '{tool.name}' went through with no "
                    f"throttling, backoff, or refusal — no rate limit appears to be enforced."
                )
            else:
                first_blocked = calls.index(limited[0]) + 1
                severity, confidence = "low", 0.8
                reasoning = f"A rate limit kicked in at call {first_blocked} of {self.call_count}: {limited[0]['error']}"

            findings.append(make_finding(
                self, tool, severity, confidence,
                f"{reasoning} | calls made: {self.call_count}, rate-limited: {len(limited)}", context,
            ))
        return findings


if __name__ == "__main__":
    from ingest.parser import parse_file
    from sandbox.runner import TOY_AGENT_PATH

    for f in MissingRateLimitsProbe().run(parse_file(str(TOY_AGENT_PATH)), TOY_AGENT_PATH):
        print(f)
