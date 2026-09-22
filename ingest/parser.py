"""
Component 1: Repo ingestion.

Parses a target LangGraph agent's source into a manifest of tools, their
permission surface, and whether they show any sign of being scoped
(allowlists, validation checks) before granting a capability. Real
AST-based detection, not string/keyword guessing.
"""

import ast
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ToolInfo:
    name: str
    permissions: list = field(default_factory=list)
    scoped: bool = False
    file: str = ""


@dataclass
class Manifest:
    tools: list = field(default_factory=list)
    entry_points: list = field(default_factory=list)


# Maps a dotted call/attribute target to the permission category it implies.
_PERMISSION_CALLS = {
    "subprocess": "shell_exec",
    "os.system": "shell_exec",
    "os.popen": "shell_exec",
    "open": "file_io",
    "os.remove": "file_io",
    "os.unlink": "file_io",
    "shutil": "file_io",
    "pathlib": "file_io",
    "requests": "network",
    "httpx": "network",
    "urllib": "network",
    "aiohttp": "network",
    "socket": "network",
    "os.environ": "env_access",
    "os.getenv": "env_access",
}

# Heuristic markers suggesting a tool validates/restricts its input before
# acting, rather than executing it unconditionally.
_SCOPING_MARKERS = (
    "allowlist", "allowed_", "whitelist", "validate", "sanitize",
    "if cmd not in", "raise permissionerror", "raise valueerror",
)

_LANGGRAPH_TOOL_DECORATORS = {"tool"}
_LANGGRAPH_TOOL_FACTORIES = {"StructuredTool", "Tool"}
_ENTRY_NAME_HINTS = ("fetch", "read", "search", "query", "get_url", "download", "scrape")


def _call_root_name(node: ast.AST) -> str:
    """Walks an attribute chain to get a dotted name like 'subprocess.run'."""
    parts = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _detect_permissions(func_node: ast.FunctionDef) -> list:
    found = set()
    for node in ast.walk(func_node):
        target = None
        if isinstance(node, ast.Call):
            target = _call_root_name(node.func)
        elif isinstance(node, ast.Attribute):
            target = _call_root_name(node)
        if not target:
            continue
        for pattern, perm in _PERMISSION_CALLS.items():
            if target == pattern or target.startswith(pattern + "."):
                found.add(perm)
    return sorted(found)


def _detect_scoping(func_node: ast.FunctionDef) -> bool:
    """
    Looks for scoping/validation logic using actual code STRUCTURE —
    identifier names, attribute names, exception types — never the
    contents of string literals or the docstring. A function that merely
    returns or logs a string like "unsanitized" or "no allowlist" must
    not be flagged just because those words appear in text it produces;
    only real identifiers (variable/function names, raised exceptions)
    count as evidence of actual scoping logic.
    """
    tokens = []
    for node in ast.walk(func_node):
        if isinstance(node, ast.Name):
            tokens.append(node.id)
        elif isinstance(node, ast.Attribute):
            tokens.append(node.attr)
        elif isinstance(node, ast.ExceptHandler) and node.type is not None:
            try:
                tokens.append(ast.unparse(node.type))
            except Exception:
                pass
        elif isinstance(node, ast.Raise) and node.exc is not None:
            try:
                tokens.append(ast.unparse(node.exc))
            except Exception:
                pass
    code_text = " ".join(tokens).lower()
    return any(marker in code_text for marker in _SCOPING_MARKERS)


def _is_tool_function(func_node: ast.FunctionDef) -> bool:
    for decorator in func_node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id in _LANGGRAPH_TOOL_DECORATORS:
            return True
        if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name) \
                and decorator.func.id in _LANGGRAPH_TOOL_DECORATORS:
            return True
    return False


def parse_file(path: str) -> Manifest:
    source = Path(path).read_text()
    tree = ast.parse(source, filename=path)
    manifest = Manifest()

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            is_tool = _is_tool_function(node)
            # Fallback: undecorated, docstringed, public module-level functions
            # are plausible tool candidates too — covers toy/demo agents that
            # just register functions in a dict instead of using @tool.
            is_plausible = not node.name.startswith("_") and ast.get_docstring(node) is not None

            if is_tool or is_plausible:
                perms = _detect_permissions(node)
                name_hint = any(hint in node.name.lower() for hint in _ENTRY_NAME_HINTS)
                # Report if it touches something risky OR its name suggests
                # it's a plausible untrusted-input entry point even with no
                # detectable permission (common for mocked/abstracted I/O).
                if perms or name_hint:
                    manifest.tools.append(
                        ToolInfo(name=node.name, permissions=perms, scoped=_detect_scoping(node), file=path)
                    )

    # Entry points: tools with a detected network/file permission, PLUS a
    # name-based fallback (fetch/read/search/query/get_*) for tools whose
    # real I/O is mocked or abstracted and so has no detectable AST call —
    # common in toy/demo fixtures and thin wrapper functions.
    manifest.entry_points = [
        t.name for t in manifest.tools
        if "network" in t.permissions or "file_io" in t.permissions
        or any(hint in t.name.lower() for hint in _ENTRY_NAME_HINTS)
    ]
    return manifest


def parse_repo(repo_dir: str) -> Manifest:
    """Walks a directory and merges manifests from every .py file found."""
    combined = Manifest()
    for py_file in Path(repo_dir).rglob("*.py"):
        try:
            file_manifest = parse_file(str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue
        combined.tools.extend(file_manifest.tools)
        combined.entry_points.extend(file_manifest.entry_points)
    return combined


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "toy_agent/vulnerable_agent.py"
    target_path = Path(target)
    result = parse_repo(str(target_path)) if target_path.is_dir() else parse_file(str(target_path))
    for tool in result.tools:
        print(f"{tool.name} ({tool.file}): {tool.permissions} (scoped={tool.scoped})")
    print(f"Entry points: {result.entry_points}")