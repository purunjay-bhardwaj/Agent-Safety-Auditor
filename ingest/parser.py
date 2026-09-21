"""
Component 1: Repo ingestion.

Parses a target LangGraph agent's source into a manifest of tools,
their permission surface, and where untrusted input enters the graph.

Week 1 goal: run this against toy_agent/vulnerable_agent.py and get a
manifest back. Week 3 goal: generalize to arbitrary LangGraph repos via
AST parsing instead of the naive introspection below.
"""

import ast
import sys
from dataclasses import dataclass, field


@dataclass
class ToolInfo:
    name: str
    permissions: list = field(default_factory=list)
    scoped: bool = False


@dataclass
class Manifest:
    tools: list = field(default_factory=list)
    entry_points: list = field(default_factory=list)


# Naive keyword → permission mapping to get you started. Replace with real
# AST inspection of imports/calls (subprocess, open, requests, etc.) once
# you're past the toy agent.
PERMISSION_HINTS = {
    "subprocess": "shell_exec",
    "open(": "file_io",
    "requests.": "network",
    "urllib": "network",
}


def parse_file(path: str) -> Manifest:
    with open(path, "r") as f:
        source = f.read()

    tree = ast.parse(source, filename=path)
    manifest = Manifest()

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            perms = [perm for hint, perm in PERMISSION_HINTS.items() if hint in ast.unparse(node)]
            if perms:
                manifest.tools.append(ToolInfo(name=node.name, permissions=perms, scoped=False))

    return manifest


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "toy_agent/vulnerable_agent.py"
    result = parse_file(target)
    for tool in result.tools:
        print(f"{tool.name}: {tool.permissions} (scoped={tool.scoped})")
