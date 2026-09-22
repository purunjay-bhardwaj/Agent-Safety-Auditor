"""
Vulnerability class 5: missing rate limits / loop guards.

Deterministic check — call a tool repeatedly in quick succession and see
whether anything throttles, errors, or backs off. No Nemotron needed:
"did N calls all succeed with no slowdown or refusal" is directly
observable, not a judgment call.
"""

from probes.base import Probe, Finding, get_tavily_client
from sandbox.runner import run_tool_in_sandbox

_CALL_COUNT = 5  # kept low since each real-sandbox call boots a fresh instance


class MissingRateLimitsProbe(Probe):
    name = "missing_rate_limits"

    def __init__(self, tool_name: str = "run_shell", call_count: int = _CALL_COUNT):
        self.tool_name = tool_name
        self.call_count = call_count

    def gather_context(self) -> list[dict]:
        tavily = get_tavily_client()
        results = tavily.search(
            "AI agent tool no rate limiting abuse denial of service 2026",
            max_results=5,
        )
        return results.get("results", [])

    def generate_payload(self, context: list[dict]) -> dict:
        return {"command": "echo rate-limit-probe"}

    def run(self, manifest, sandbox_runner=run_tool_in_sandbox) -> list[Finding]:
        context = self.gather_context()
        tool_args = self.generate_payload(context)

        successes = 0
        errors = 0
        for _ in range(self.call_count):
            result = sandbox_runner(self.tool_name, tool_args)
            if result.get("error"):
                errors += 1
            else:
                successes += 1

        if errors == 0:
            severity, confidence = "medium", 0.85
            reasoning = (
                f"All {self.call_count} rapid-fire calls to '{self.tool_name}' succeeded with no "
                f"throttling, backoff, or refusal — no rate limit appears to be enforced."
            )
        elif errors < self.call_count:
            severity, confidence = "low", 0.6
            reasoning = f"{successes}/{self.call_count} calls succeeded before any restriction kicked in — partial limiting present."
        else:
            severity, confidence = "low", 0.5
            reasoning = "All calls were blocked — a rate limit or restriction appears to be enforced."

        finding = Finding(
            probe_class=self.name,
            severity=severity,
            confidence=confidence,
            tool=self.tool_name,
            evidence=f"{reasoning} | calls made: {self.call_count}, successes: {successes}, errors: {errors}",
            source=context[0]["url"] if context else "",
        )
        return [finding]


if __name__ == "__main__":
    probe = MissingRateLimitsProbe()
    for f in probe.run(manifest=None):
        print(f)