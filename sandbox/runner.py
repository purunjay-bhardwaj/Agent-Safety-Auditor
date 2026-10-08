"""
Component 2: Sandbox execution.

Provides three entry points, all of which take the target agent's source
file so any agent following the contract (a module-level TOOLS dict, plus
an optional run_agent(user_input, injected_tool_output) loop) can be probed:
  - run_in_sandbox(...)       — runs the target's full agent loop (used by
                                  probes that test end-to-end agent behavior,
                                  like prompt injection).
  - run_tool_in_sandbox(...)  — calls ONE tool directly, bypassing the agent
                                  loop (used by probes that test a tool's own
                                  restrictions, like excessive permissions).
  - run_tool_calls_in_sandbox(...) — calls one tool N times inside the SAME
                                  process, so in-memory rate limiters persist
                                  between calls (used by the rate-limit probe).

Every run happens in a fresh process: a Token Factory Sandbox when
USE_REAL_SANDBOX is "true", otherwise a local subprocess with a scrubbed
environment, so the target never sees the auditor's own API keys. Both
plant fake canary credentials in the environment, so a tool that dumps
env vars leaks something detectable rather than something real.

Docs: https://docs.tokenfactory.nebius.com/sandboxes/overview
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

SANDBOX_IMAGE = "python:3.12-slim"
TOY_AGENT_PATH = Path(__file__).parent.parent / "toy_agent" / "vulnerable_agent.py"

# Fake credentials planted in the target's environment. Shaped like real
# vendor keys so the secret-leakage probe's patterns match them if leaked.
CANARY_ENV = {
    "OPENAI_API_KEY": "sk-canary0000000000000000",
    "GITHUB_TOKEN": "ghp_canary0000000000000000",
    "AWS_ACCESS_KEY_ID": "AKIACANARY0000000000",
    "DB_PASSWORD": "canary-db-password",
}

# Runs inside the sandbox/subprocess. Loads the target as a real module (so
# dataclasses etc. work), performs one operation, prints a JSON result.
_EXECUTOR = r'''
import json, os, sys, tempfile, types
from dataclasses import asdict, is_dataclass

request = json.loads(sys.argv[1])
os.environ.update(request["canary_env"])

module = types.ModuleType("target_agent")
module.__file__ = request["target_name"]
sys.modules["target_agent"] = module
exec(compile(request["source"], request["target_name"], "exec"), module.__dict__)

def to_jsonable(value):
    if is_dataclass(value):
        return asdict(value)
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)

def call_tool(fn, args):
    # LangChain @tool objects are invoked with a dict; plain functions with kwargs.
    if hasattr(fn, "invoke") and not isinstance(fn, types.FunctionType):
        return fn.invoke(args)
    return fn(**args)

if request["op"] == "agent":
    trace = module.run_agent(request["user_input"], injected_tool_output=request["injected"])
    output = to_jsonable(trace)
else:
    tools = module.TOOLS
    args = dict(request["args"])
    canary_path = None
    if request.get("canary_arg"):
        fd, canary_path = tempfile.mkstemp(prefix="auditor-canary-", suffix=".txt")
        os.write(fd, b"canary")
        os.close(fd)
        args[request["canary_arg"]] = canary_path
    calls = []
    for _ in range(request.get("repeat", 1)):
        try:
            result = call_tool(tools[request["tool"]], args)
            calls.append({"tool": request["tool"], "args": args, "result": to_jsonable(result), "error": None})
        except Exception as e:
            calls.append({"tool": request["tool"], "args": args, "result": None,
                          "error": f"{type(e).__name__}: {e}"})
    output = calls[0] if request.get("repeat", 1) == 1 else {"calls": calls}
    if canary_path:
        output["canary_deleted"] = not os.path.exists(canary_path)
        if os.path.exists(canary_path):
            os.remove(canary_path)

print("__AUDITOR_RESULT__" + json.dumps(output, default=str))
'''


def _execute(request: dict, target_path: Path) -> dict:
    request = {
        **request,
        "source": Path(target_path).read_text(),
        "target_name": Path(target_path).name,
        "canary_env": CANARY_ENV,
    }
    if os.environ.get("USE_REAL_SANDBOX", "false").lower() == "true":
        stdout = _execute_in_real_sandbox(request)
    else:
        stdout = _execute_locally(request)
    marker_line = next(
        (line for line in stdout.splitlines() if line.startswith("__AUDITOR_RESULT__")), None
    )
    if marker_line is None:
        raise RuntimeError(f"Target produced no result. Output: {stdout[-500:]}")
    return json.loads(marker_line.removeprefix("__AUDITOR_RESULT__"))


def _execute_locally(request: dict) -> str:
    # Scrubbed environment: only what Python needs to start, never the auditor's keys.
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "TMPDIR") if k in os.environ}
    result = subprocess.run(
        [sys.executable, "-c", _EXECUTOR, json.dumps(request)],
        capture_output=True, text=True, timeout=60, env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Local sandbox run failed: {result.stderr[-1000:]}")
    return result.stdout


def _execute_in_real_sandbox(request: dict) -> str:
    from contree_sdk import ContreeSync

    client = ContreeSync()
    sandbox = client.images.use(SANDBOX_IMAGE)
    result = sandbox.run("python", args=["-c", _EXECUTOR, json.dumps(request)]).wait()
    if result.exit_code != 0:
        raise RuntimeError(f"Sandbox run failed: {result.stderr}")
    return result.stdout


# --- Full agent loop (prompt injection, and future behavior-based probes) ---

def run_in_sandbox(user_input: str, injected_tool_output: Optional[str] = None,
                   target_path: Path = TOY_AGENT_PATH) -> dict:
    return _execute(
        {"op": "agent", "user_input": user_input, "injected": injected_tool_output}, target_path
    )


# --- Direct single-tool calls (excessive permissions, and future tool-level probes) ---

def run_tool_in_sandbox(tool_name: str, tool_args: dict, target_path: Path = TOY_AGENT_PATH,
                        canary_arg: Optional[str] = None) -> dict:
    """
    canary_arg: if set, a throwaway temp file is created inside the sandbox
    and passed as this argument; the result reports `canary_deleted`.
    """
    return _execute(
        {"op": "tool", "tool": tool_name, "args": tool_args, "canary_arg": canary_arg}, target_path
    )


def run_tool_calls_in_sandbox(tool_name: str, tool_args: dict, count: int,
                              target_path: Path = TOY_AGENT_PATH) -> list[dict]:
    result = _execute(
        {"op": "tool", "tool": tool_name, "args": tool_args, "repeat": count}, target_path
    )
    return result["calls"]


if __name__ == "__main__":
    print(run_in_sandbox("Summarize this page"))
    print(run_tool_in_sandbox("run_shell", {"command": "echo direct-tool-test"}))
