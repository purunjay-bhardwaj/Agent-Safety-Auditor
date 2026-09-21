"""
Shared shape for every probe. Each vulnerability class (probes/prompt_injection.py,
probes/excessive_permissions.py, etc.) implements `Probe` so the report generator
can treat them uniformly.
"""

import os
from dataclasses import dataclass, field
from typing import Optional

from openai import OpenAI
from tavily import TavilyClient


@dataclass
class Finding:
    probe_class: str
    severity: str  # "low" | "medium" | "high"
    confidence: float
    tool: Optional[str] = None
    evidence: str = ""
    source: str = ""  # Tavily result cited for this finding, if any


def get_nemotron_client() -> OpenAI:
    """Nemotron-3-Nano via Token Factory's OpenAI-compatible endpoint."""
    return OpenAI(
        api_key=os.environ["TOKEN_FACTORY_API_KEY"],
        base_url=os.environ.get("TOKEN_FACTORY_BASE_URL", "https://api.tokenfactory.nebius.com/v1"),
    )


def get_tavily_client() -> TavilyClient:
    return TavilyClient(api_key=os.environ["TAVILY_API_KEY"])


class Probe:
    """Base class every vulnerability-class probe implements."""

    name: str = "base"

    def gather_context(self) -> list[dict]:
        """Step 1: Tavily search for current context relevant to this probe class."""
        raise NotImplementedError

    def generate_payload(self, context: list[dict]) -> str:
        """Step 2: Nemotron crafts the adversarial test case using that context."""
        raise NotImplementedError

    def run(self, manifest, sandbox_runner) -> list[Finding]:
        """Steps 3-4: run the payload in the sandbox, score the resulting trace."""
        raise NotImplementedError
