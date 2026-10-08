"""
Shared shape for every probe. Each vulnerability class (probes/prompt_injection.py,
probes/excessive_permissions.py, etc.) implements `Probe` so the report generator
can treat them uniformly.
"""

import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional

from dotenv import load_dotenv
from openai import OpenAI
from tavily import TavilyClient

load_dotenv()

@dataclass
class Finding:
    probe_class: str
    severity: str  # "low" | "medium" | "high"
    confidence: float
    tool: Optional[str] = None
    evidence: str = ""
    source: str = ""  # Tavily result cited for this finding, if any
    file: str = ""  # where the vulnerable tool is defined
    line: int = 0
    fix: str = ""  # suggested remediation for this specific tool


def llm_enabled() -> bool:
    """AUDITOR_OFFLINE=true skips Tavily/Nemotron and uses deterministic payloads and scoring."""
    return os.environ.get("AUDITOR_OFFLINE", "false").lower() != "true"


def get_nemotron_client() -> OpenAI:
    """Nemotron-3-Nano via Token Factory's OpenAI-compatible endpoint."""
    return OpenAI(
        api_key=os.environ["TOKEN_FACTORY_API_KEY"],
        base_url=os.environ.get("TOKEN_FACTORY_BASE_URL", "https://api.tokenfactory.nebius.com/v1"),
    )


def get_tavily_client() -> TavilyClient:
    return TavilyClient(api_key=os.environ["TAVILY_API_KEY"])


@lru_cache(maxsize=None)
def _cached_search(query: str) -> tuple:
    return tuple(get_tavily_client().search(query, max_results=5).get("results", []))


def search_context(query: str) -> list[dict]:
    """Tavily results for a probe's query, cached so multi-tool/multi-repo scans search once."""
    if not llm_enabled():
        return []
    return list(_cached_search(query))


def parse_verdict(raw: str) -> tuple[str, float, str]:
    """Parses Nemotron's {"severity", "confidence", "reasoning"} JSON verdict."""
    import json

    # Nemotron occasionally wraps JSON in markdown fences — strip them defensively.
    raw = (raw or "{}").strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        verdict = json.loads(raw)
        return verdict["severity"], float(verdict["confidence"]), verdict.get("reasoning", "")
    except (json.JSONDecodeError, KeyError, ValueError, TypeError):
        # If the verdict can't be parsed, fail toward reporting it as worth
        # a human look rather than silently scoring it "low".
        return "medium", 0.5, f"Could not parse model verdict; raw response: {raw[:200]}"


def _display_path(path: str) -> str:
    """Repo-relative path when the target lives under the working directory."""
    try:
        return os.path.relpath(path) if os.path.abspath(path).startswith(os.getcwd()) else path
    except ValueError:
        return path


def make_finding(probe: "Probe", tool_info, severity: str, confidence: float,
                 evidence: str, context: list[dict]) -> Finding:
    """Builds a Finding that points at the tool's definition and carries its suggested fix."""
    return Finding(
        probe_class=probe.name,
        severity=severity,
        confidence=confidence,
        tool=tool_info.name,
        evidence=evidence,
        source=context[0]["url"] if context else "",
        file=_display_path(tool_info.file),
        line=tool_info.line,
        fix=probe.fix_template.format(tool=tool_info.name) if severity != "low" else "",
    )


class Probe:
    """Base class every vulnerability-class probe implements."""

    name: str = "base"
    fix_template: str = ""  # formatted with {tool}

    def gather_context(self) -> list[dict]:
        """Step 1: Tavily search for current context relevant to this probe class."""
        raise NotImplementedError

    def generate_payload(self, context: list[dict]) -> str:
        """Step 2: Nemotron crafts the adversarial test case using that context."""
        raise NotImplementedError

    def run(self, manifest, target_path) -> list[Finding]:
        """Steps 3-4: run the payload against each relevant tool in the sandbox, score the result."""
        raise NotImplementedError
