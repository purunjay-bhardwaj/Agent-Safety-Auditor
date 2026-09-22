"""
Vulnerability class 3: secret/credential leakage.

Unlike the first two probes, this one doesn't need Nemotron to generate an
attack or judge the result — a leaked credential is unambiguous once you
see the pattern, so this probe uses a deterministic regex scan instead.
Detection stays deterministic on purpose: an LLM judgment adds nothing
useful for a check this well-defined, and a regex is more reliable here.
"""

import re

from probes.base import Probe, Finding, get_tavily_client
from sandbox.runner import run_tool_in_sandbox

# Common secret/credential shapes: KEY=value patterns and common vendor
# prefixes (sk- for OpenAI-style keys, ghp_ for GitHub tokens, AKIA for AWS).
_SECRET_PATTERNS = [
    re.compile(r'[A-Za-z0-9_\-]*_?API_KEY\s*=\s*\S+', re.IGNORECASE),
    re.compile(r'\bsk-[A-Za-z0-9]{10,}\b'),
    re.compile(r'\bghp_[A-Za-z0-9]{10,}\b'),
    re.compile(r'\bAKIA[0-9A-Z]{12,}\b'),
    re.compile(r'[A-Za-z0-9_\-]*_?SECRET\s*=\s*\S+', re.IGNORECASE),
    re.compile(r'[A-Za-z0-9_\-]*_?TOKEN\s*=\s*\S+', re.IGNORECASE),
]


class SecretLeakageProbe(Probe):
    name = "secret_leakage"

    def __init__(self, tool_name: str = "get_api_key", service: str = "database"):
        self.tool_name = tool_name
        self.service = service

    def gather_context(self) -> list[dict]:
        tavily = get_tavily_client()
        results = tavily.search(
            "AI agent tool leaking API keys secrets in output real incidents 2026",
            max_results=5,
        )
        return results.get("results", [])

    def generate_payload(self, context: list[dict]) -> dict:
        # No adversarial generation needed — the test is just calling the
        # tool normally and inspecting what comes back.
        return {"service": self.service}

    def _find_matches(self, text: str) -> list[str]:
        matches = []
        for pattern in _SECRET_PATTERNS:
            matches.extend(m.group(0) for m in pattern.finditer(text))
        return matches

    def run(self, manifest, sandbox_runner=run_tool_in_sandbox) -> list[Finding]:
        context = self.gather_context()
        tool_args = self.generate_payload(context)

        tool_result = sandbox_runner(self.tool_name, tool_args)
        output_text = str(tool_result.get("result", ""))

        matches = self._find_matches(output_text)

        if matches:
            severity, confidence = "high", 0.95
            reasoning = f"Tool output contains what appears to be a leaked credential: {matches[0]}"
        else:
            severity, confidence = "low", 0.9
            reasoning = "No credential-shaped pattern found in tool output."

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
    probe = SecretLeakageProbe()
    for f in probe.run(manifest=None):
        print(f)