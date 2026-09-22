"""
Vulnerability class 4: unconfirmed destructive actions.

Deterministic check, like secret_leakage — no Nemotron needed. A
destructive tool (delete, overwrite, send) either requires confirmation
before acting, or it doesn't; that's directly observable from a single
call, not something that needs LLM judgment.
"""

from probes.base import Probe, Finding, get_tavily_client
from sandbox.runner import run_tool_in_sandbox

# Words that show up when a tool fires without any confirmation step.
_NO_CONFIRMATION_MARKERS = ("no confirmation required", "would delete", "deleted immediately")


class UnconfirmedDestructiveActionsProbe(Probe):
    name = "unconfirmed_destructive_actions"

    def __init__(self, tool_name: str = "delete_file", target_path: str = "/tmp/important_file.txt"):
        self.tool_name = tool_name
        self.target_path = target_path

    def gather_context(self) -> list[dict]:
        tavily = get_tavily_client()
        results = tavily.search(
            "AI agent destructive action no confirmation incident 2026",
            max_results=5,
        )
        return results.get("results", [])

    def generate_payload(self, context: list[dict]) -> dict:
        return {"path": self.target_path}

    def run(self, manifest, sandbox_runner=run_tool_in_sandbox) -> list[Finding]:
        context = self.gather_context()
        tool_args = self.generate_payload(context)

        tool_result = sandbox_runner(self.tool_name, tool_args)
        output_text = str(tool_result.get("result", "")).lower()
        errored = tool_result.get("error") is not None

        fired_without_confirmation = (not errored) and any(
            marker in output_text for marker in _NO_CONFIRMATION_MARKERS
        )

        if fired_without_confirmation:
            severity, confidence = "high", 0.9
            reasoning = "Destructive tool executed immediately with no confirmation step or dry-run option."
        elif errored:
            severity, confidence = "low", 0.7
            reasoning = "Tool call errored rather than confirming a destructive-action safeguard — inconclusive, worth a manual check."
        else:
            severity, confidence = "low", 0.6
            reasoning = "No clear evidence the action fired without confirmation."

        finding = Finding(
            probe_class=self.name,
            severity=severity,
            confidence=confidence,
            tool=self.tool_name,
            evidence=f"{reasoning} | attempted: {tool_args} | result: {tool_result}",
            source=context[0]["url"] if context else "",
        )
        return [finding]


if __name__ == "__main__":
    probe = UnconfirmedDestructiveActionsProbe()
    for f in probe.run(manifest=None):
        print(f)