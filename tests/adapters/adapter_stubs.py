"""Stub framework objects for offline adapter testing.

Per the spec's test plan, every adapter is tested against stubs reproducing
the exact interface surface the adapter touches, so the deny path, the
refusal payload, and the malformed-JSON path are all covered with no
framework installed. The stubs are deliberately minimal: if an adapter
starts touching an attribute the stub lacks, the test breaks, which is the
correct signal that the adapter's real-framework surface grew.
"""

from __future__ import annotations

import types
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# OpenAI Agents SDK surface: agents.{ToolInputGuardrail, ToolGuardrailFunctionOutput, FunctionTool}
# ---------------------------------------------------------------------------


@dataclass
class StubToolInputGuardrail:
    guardrail_function: Any
    name: str


class StubGuardrailOutput:
    """Records which fork fired and with what, like the SDK's output type."""

    def __init__(self, verdict: str, message: str | None, output_info: Any) -> None:
        self.verdict = verdict
        self.message = message
        self.output_info = output_info

    @classmethod
    def allow(cls, output_info: Any = None) -> StubGuardrailOutput:
        return cls("allow", None, output_info)

    @classmethod
    def reject_content(cls, message: str, output_info: Any = None) -> StubGuardrailOutput:
        return cls("reject_content", message, output_info)


@dataclass
class StubFunctionTool:
    name: str
    tool_input_guardrails: list[Any] = field(default_factory=list)


def make_agents_module() -> types.ModuleType:
    module = types.ModuleType("agents")
    module.ToolInputGuardrail = StubToolInputGuardrail  # type: ignore[attr-defined]
    module.ToolGuardrailFunctionOutput = StubGuardrailOutput  # type: ignore[attr-defined]
    module.FunctionTool = StubFunctionTool  # type: ignore[attr-defined]
    return module


def make_old_agents_module() -> types.ModuleType:
    """An installed SDK from before tool guardrails existed: the names the
    adapter needs are missing, so `from agents import ...` raises
    ImportError (not ModuleNotFoundError), and the adapter must answer with
    its upgrade hint rather than its install hint."""
    return types.ModuleType("agents")


@dataclass
class StubGuardrailData:
    """The `data` argument the SDK passes to a guardrail function."""

    context: Any


@dataclass
class StubToolContext:
    tool_name: Any
    tool_arguments: Any
    context: Any = None  # the host's run context object


@dataclass
class StubAgent:
    tools: list[Any]


# ---------------------------------------------------------------------------
# LangChain surface: langchain_core.messages.ToolMessage
# ---------------------------------------------------------------------------


class StubToolMessage:
    def __init__(
        self,
        content: str,
        tool_call_id: str = "",
        name: str | None = None,
        status: str = "success",
    ) -> None:
        self.content = content
        self.tool_call_id = tool_call_id
        self.name = name
        self.status = status


def make_langchain_core_modules() -> tuple[types.ModuleType, types.ModuleType]:
    package = types.ModuleType("langchain_core")
    messages = types.ModuleType("langchain_core.messages")
    messages.ToolMessage = StubToolMessage  # type: ignore[attr-defined]
    package.messages = messages  # type: ignore[attr-defined]
    return package, messages


@dataclass
class StubToolCallRequest:
    tool_call: Any
