"""
Vulnerability class 3: secret/credential leakage.

Unlike the first two probes, this one doesn't need Nemotron to generate an
attack or judge the result — a leaked credential is unambiguous once you
see the pattern, so this probe uses a deterministic regex scan instead.
Detection stays deterministic on purpose: an LLM judgment adds nothing
useful for a check this well-defined, and a regex is more reliable here.

The sandbox plants fake canary credentials in the target's environment, so
a tool that echoes env vars leaks something these patterns match.
"""

import re

from probes.base import Probe, Finding, make_finding, search_context
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
    re.compile(r'[A-Za-z0-9_\-]*_?PASSWORD\s*=\s*\S+', re.IGNORECASE),
]
# A KEY=value match whose value is masked ("****", "<redacted>") is the
# tool doing the right thing, not a leak.
_MASKED_VALUE = re.compile(r'=\s*["\']?(\*+|x{3,}|<?redacted>?|\[redacted\])', re.IGNORECASE)

# Benign argument for any required parameter; the test is calling the tool
# normally and inspecting what comes back.
_BENIGN_ARG = "database"


class SecretLeakageProbe(Probe):
    name = "secret_leakage"
    fix_template = (
        "Never return raw credentials from `{tool}`: keep secrets server-side and return a "
        "masked value (e.g. `sk-****1234`) or an opaque reference instead."
    )

    def gather_context(self) -> list[dict]:
        return search_context("AI agent tool leaking API keys secrets in output real incidents 2026")

    def generate_payload(self, tool) -> dict:
        return {param: _BENIGN_ARG for param in tool.params}

    def _find_matches(self, text: str) -> list[str]:
        matches = []
        for pattern in _SECRET_PATTERNS:
            matches.extend(m.group(0) for m in pattern.finditer(text) if not _MASKED_VALUE.search(m.group(0)))
        return matches

    def run(self, manifest, target_path) -> list[Finding]:
        candidates = [t for t in manifest.tools if t.secret_hint]
        if not candidates:
            return []
        context = self.gather_context()
        findings = []
        for tool in candidates:
            tool_args = self.generate_payload(tool)
            tool_result = run_tool_in_sandbox(tool.name, tool_args, target_path=target_path)
            matches = self._find_matches(str(tool_result.get("result", "")))

            if matches:
                severity, confidence = "high", 0.95
                reasoning = f"Tool output contains what appears to be a leaked credential: {matches[0]}"
            else:
                severity, confidence = "low", 0.9
                reasoning = "No credential-shaped pattern found in tool output."

            findings.append(make_finding(
                self, tool, severity, confidence,
                f"{reasoning} | attempted: {tool_args} | result: {tool_result}", context,
            ))
        return findings


if __name__ == "__main__":
    from ingest.parser import parse_file
    from sandbox.runner import TOY_AGENT_PATH

    for f in SecretLeakageProbe().run(parse_file(str(TOY_AGENT_PATH)), TOY_AGENT_PATH):
        print(f)
