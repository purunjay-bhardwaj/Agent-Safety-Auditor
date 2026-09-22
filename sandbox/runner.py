"""
Component 2: Sandbox execution.

Provides two entry points:
  - run_in_sandbox(...)       — runs the full toy agent loop (used by probes
                                  that test end-to-end agent behavior, like
                                  prompt injection).
  - run_tool_in_sandbox(...)  — calls ONE tool directly, bypassing the agent
                                  loop (used by probes that test a tool's own
                                  restrictions, like excessive permissions).

Both respect USE_REAL_SANDBOX: "true" routes through a real Token Factory
Sandbox, otherwise falls back to running locally for fast dev/testing.

Docs: https://docs.tokenfactory.nebius.com/sandboxes/overview
"""

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from toy_agent.vulnerable_agent import run_agent, TOOLS

load_dotenv()

SANDBOX_IMAGE = "python:3.12-slim"
TOY_AGENT_PATH = Path(__file__).parent.parent / "toy_agent" / "vulnerable_agent.py"


# --- Full agent loop (prompt injection, and future behavior-based probes) ---

def run_in_sandbox(user_input: str, injected_tool_output: Optional[str] = None) -> dict:
    if os.environ.get("USE_REAL_SANDBOX", "false").lower() == "true":
        return _run_in_real_sandbox(user_input, injected_tool_output)
    return _run_locally(user_input, injected_tool_output)


def _run_locally(user_input: str, injected_tool_output: Optional[str]) -> dict:
    trace = run_agent(user_input, injected_tool_output=injected_tool_output)
    return asdict(trace)


def _run_in_real_sandbox(user_input: str, injected_tool_output: Optional[str]) -> dict:
    from contree_sdk import ContreeSync

    client = ContreeSync()
    sandbox = client.images.use(SANDBOX_IMAGE)
    agent_source = TOY_AGENT_PATH.read_text()

    injected_literal = "None" if injected_tool_output is None else json.dumps(injected_tool_output)

    generated_code = f"""
import json
from dataclasses import asdict

agent_source = {json.dumps(agent_source)}
agent_ns = {{}}
exec(agent_source, agent_ns)
run_agent = agent_ns["run_agent"]

user_input = {json.dumps(user_input)}
injected_tool_output = {injected_literal}

trace = run_agent(user_input, injected_tool_output=injected_tool_output)
print(json.dumps(asdict(trace)))
"""
    result = sandbox.run("python", args=["-c", generated_code]).wait()
    if result.exit_code != 0:
        raise RuntimeError(f"Sandbox run failed: {result.stderr}")
    return json.loads(result.stdout)


# --- Direct single-tool calls (excessive permissions, and future tool-level probes) ---

def run_tool_in_sandbox(tool_name: str, tool_args: dict) -> dict:
    if os.environ.get("USE_REAL_SANDBOX", "false").lower() == "true":
        return _run_tool_in_real_sandbox(tool_name, tool_args)
    return _run_tool_locally(tool_name, tool_args)


def _run_tool_locally(tool_name: str, tool_args: dict) -> dict:
    tool_fn = TOOLS[tool_name]
    try:
        result = tool_fn(**tool_args)
        return {"tool": tool_name, "args": tool_args, "result": result, "error": None}
    except Exception as e:
        return {"tool": tool_name, "args": tool_args, "result": None, "error": str(e)}


def _run_tool_in_real_sandbox(tool_name: str, tool_args: dict) -> dict:
    from contree_sdk import ContreeSync

    client = ContreeSync()
    sandbox = client.images.use(SANDBOX_IMAGE)
    agent_source = TOY_AGENT_PATH.read_text()

    generated_code = f"""
import json

agent_source = {json.dumps(agent_source)}
agent_ns = {{}}
exec(agent_source, agent_ns)
TOOLS = agent_ns["TOOLS"]

tool_name = {json.dumps(tool_name)}
tool_args = json.loads({json.dumps(json.dumps(tool_args))})

try:
    result = TOOLS[tool_name](**tool_args)
    output = {{"tool": tool_name, "args": tool_args, "result": result, "error": None}}
except Exception as e:
    output = {{"tool": tool_name, "args": tool_args, "result": None, "error": str(e)}}

print(json.dumps(output))
"""
    result = sandbox.run("python", args=["-c", generated_code]).wait()
    if result.exit_code != 0:
        raise RuntimeError(f"Sandbox run failed: {result.stderr}")
    return json.loads(result.stdout)


if __name__ == "__main__":
    print(run_in_sandbox("Summarize this page"))
    print(run_tool_in_sandbox("run_shell", {"command": "echo direct-tool-test"}))