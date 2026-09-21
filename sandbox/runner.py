"""
Component 2: Sandbox execution.

Wraps a target agent run inside a Token Factory Sandbox and returns a
structured trace. Check the hackathon Resources tab for the actual
Token Factory Sandbox SDK before filling in `_execute_in_sandbox` — this
stub calls the target function directly so the rest of the pipeline can
be built and tested before that integration lands.
"""

import os
from dataclasses import asdict

from toy_agent.vulnerable_agent import run_agent, AgentTrace


def run_in_sandbox(user_input: str, injected_tool_output: str | None = None) -> dict:
    """
    Replace the body of this function with an actual Token Factory Sandbox
    call once you have the SDK: boot the sandbox, install target deps,
    invoke the agent inside it, and pull back the trace. Keep the return
    shape (a dict matching AgentTrace) so probes don't need to change.
    """
    trace: AgentTrace = _execute_in_sandbox(user_input, injected_tool_output)
    return asdict(trace)


def _execute_in_sandbox(user_input: str, injected_tool_output: str | None) -> AgentTrace:
    # TODO: swap for a real Token Factory Sandbox invocation.
    # For now this runs the toy agent locally so the pipeline is testable.
    return run_agent(user_input, injected_tool_output=injected_tool_output)


if __name__ == "__main__":
    print(run_in_sandbox("Summarize this page"))
