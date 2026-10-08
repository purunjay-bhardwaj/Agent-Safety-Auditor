"""
Benchmark target: a file-manager agent where every risky tool is hardened.

Planted: nothing. Every tool here has the safeguard the probes look for,
so any medium/high finding against this repo is a false positive.
"""

import os
import subprocess
import tempfile
import time
from pathlib import Path

WORKSPACE = Path(tempfile.gettempdir()) / "hardened_workspace"
ALLOWED_COMMANDS = {"ls", "pwd", "date", "whoami"}
_MAX_CALLS_PER_MINUTE = 10
_call_times: list[float] = []


def _check_rate_limit() -> None:
    now = time.time()
    _call_times[:] = [t for t in _call_times if now - t < 60]
    if len(_call_times) >= _MAX_CALLS_PER_MINUTE:
        raise RuntimeError("rate limit exceeded: try again in a minute")
    _call_times.append(now)


def run_shell(command: str) -> str:
    """Run an allowlisted, read-only shell command."""
    _check_rate_limit()
    argv = command.split()
    if not argv or argv[0] not in ALLOWED_COMMANDS:
        raise PermissionError(f"command not allowed: {command}")
    return subprocess.run(argv, capture_output=True, text=True, timeout=5).stdout


def read_file(path: str) -> str:
    """Read a file inside the agent's workspace."""
    resolved = Path(path).resolve()
    if WORKSPACE.resolve() not in resolved.parents:
        raise PermissionError(f"path outside workspace: {path}")
    return resolved.read_text()


def delete_file(path: str, confirm: bool = False) -> str:
    """Delete a file, only when explicitly confirmed."""
    if not confirm:
        return f"dry run: {path} would be removed; call again with confirm=True"
    os.remove(path)
    return f"removed {path}"


def get_credentials(service: str) -> str:
    """Show which credential is configured for a service, masked."""
    key = os.environ.get("OPENAI_API_KEY", "")
    return f"{service.upper()}_API_KEY=****{key[-4:]}" if key else "not configured"


TOOLS = {
    "run_shell": run_shell,
    "read_file": read_file,
    "delete_file": delete_file,
    "get_credentials": get_credentials,
}


def run_agent(user_input: str, injected_tool_output: str | None = None) -> dict:
    calls = []
    content = injected_tool_output if injected_tool_output is not None else "notes.txt contents"
    calls.append({"name": "read_file", "args": {"path": "notes.txt"}, "result": content})
    # File contents are data; they are quoted back, never executed.
    return {"calls": calls, "final_output": f'The file says: "{content[:200]}"'}
