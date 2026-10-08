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
    line: int = 0  # line of the `def`, so findings can point at the exact tool
    params: list = field(default_factory=list)
    destructive: bool = False
    secret_hint: bool = False


@dataclass
class Manifest:
    tools: list = field(default_factory=list)
    entry_points: list = field(default_factory=list)
    has_agent_loop: bool = False  # target defines run_agent(), so behavior probes can drive it

    def get(self, tool_name: str):
        return next((t for t in self.tools if t.name == tool_name), None)


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

# Name tokens (split on "_") that mark a tool as destructive or secret-handling
# even when its real I/O is mocked and so has no detectable AST call.
_DESTRUCTIVE_NAME_TOKENS = {"delete", "remove", "rm", "drop", "wipe", "purge", "erase", "destroy", "cancel"}
_SECRET_NAME_TOKENS = {"key", "keys", "secret", "secrets", "token", "credential", "credentials",
                       "password", "env", "config", "creds"}
# Method/function names that delete files regardless of how they're reached
# (os.remove, Path(p).unlink(), shutil.rmtree, ...).
_DESTRUCTIVE_CALL_ATTRS = {"remove", "unlink", "rmtree", "rmdir"}


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


def _detect_destructive_calls(func_node: ast.FunctionDef) -> bool:
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            target = _call_root_name(node.func)
            if target.split(".")[-1] in _DESTRUCTIVE_CALL_ATTRS:
                return True
    return False


def _name_tokens(name: str) -> set:
    return set(name.lower().split("_"))


def _registered_tool_names(tree: ast.Module) -> set:
    """Function names referenced as values in a module-level TOOLS = {...} dict."""
    names = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict) \
                and any(isinstance(t, ast.Name) and t.id == "TOOLS" for t in node.targets):
            names.update(v.id for v in node.value.values if isinstance(v, ast.Name))
    return names


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
    registered = _registered_tool_names(tree)
    manifest.has_agent_loop = any(
        isinstance(n, ast.FunctionDef) and n.name == "run_agent" for n in tree.body
    )

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            is_tool = _is_tool_function(node) or node.name in registered
            # Fallback: undecorated, docstringed, public module-level functions
            # are plausible tool candidates too — covers toy/demo agents that
            # just register functions in a dict instead of using @tool.
            is_plausible = not node.name.startswith("_") and ast.get_docstring(node) is not None

            if is_tool or is_plausible:
                perms = _detect_permissions(node)
                tokens = _name_tokens(node.name)
                name_hint = any(hint in node.name.lower() for hint in _ENTRY_NAME_HINTS)
                destructive = _detect_destructive_calls(node) or bool(tokens & _DESTRUCTIVE_NAME_TOKENS)
                secret_hint = "env_access" in perms or bool(tokens & _SECRET_NAME_TOKENS)
                # Report if it touches something risky OR its name suggests
                # it's a plausible entry point, destructive action, or secret
                # source even with no detectable permission (common for
                # mocked/abstracted I/O).
                if perms or name_hint or destructive or secret_hint:
                    manifest.tools.append(ToolInfo(
                        name=node.name,
                        permissions=perms,
                        scoped=_detect_scoping(node),
                        file=path,
                        line=node.lineno,
                        params=[a.arg for a in node.args.args],
                        destructive=destructive,
                        secret_hint=secret_hint,
                    ))

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
        combined.has_agent_loop = combined.has_agent_loop or file_manifest.has_agent_loop
    return combined


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "toy_agent/vulnerable_agent.py"
    target_path = Path(target)
    result = parse_repo(str(target_path)) if target_path.is_dir() else parse_file(str(target_path))
    for tool in result.tools:
        print(f"{tool.name} ({tool.file}:{tool.line}): {tool.permissions} "
              f"(scoped={tool.scoped}, destructive={tool.destructive}, secret_hint={tool.secret_hint})")
    print(f"Entry points: {result.entry_points}")