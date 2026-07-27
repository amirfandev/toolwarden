"""OpenAI Agents SDK adapter: the gate as a ToolInputGuardrail.

The SDK evaluates tool input guardrails after the model emits a function
call and before the tool body executes; ``reject_content`` skips execution
and hands the model the guardrail's message as the tool's output. That is
precisely the deny-time contract every toolwarden boundary follows (spec
9.2): the model learns it was denied, by which policies, with every reason,
and can retry compliantly. The payload is ``Refusal.to_tool_result()``,
byte-identical to what ``gate.wrap`` and the other adapters produce.

Honest guarantee, stated plainly:

- BLOCKS BEFORE EXECUTION for every ``FunctionTool`` the guardrail is
  attached to. This is not observe-only: on deny the tool body never runs.
- Attachment is per-tool opt-in, so a ``FunctionTool`` nobody attached the
  guardrail to is completely unguarded. ``assert_all_guarded`` turns that
  silent gap into a boot failure; call it after building the agent.
- OpenAI-hosted tools (web search, code interpreter, and their kin) execute
  on OpenAI infrastructure and never pass through tool input guardrails.
  This adapter cannot see them, let alone block them.
- The gate judges the model's raw argument JSON, before the SDK's pydantic
  coercion runs. Policies are written against raw values, which is the
  normalizers' natural grain; the recorded bet, and what would falsify it,
  is spec section 14, decision 5.
- This corner of the SDK has moved before. Pin ``openai-agents`` in the
  lockfile.

The principal is host authority, never model output. It comes from the run
context object the host passed to the Runner (invisible to the model, which
is what makes it a legitimate identity source) via ``principal_from_context``,
or defaults to ``{}``. There is no code path from tool arguments to it.

The SDK is imported only inside these functions, so importing this module
costs nothing and the core test suite runs without the framework installed.

Usage::

    guard = toolwarden_guardrail(gate, principal_from_context=lambda ctx: {
        "agent": "support-bot", "env": ctx.env,
    })
    refund = function_tool(issue_refund, tool_input_guardrails=[guard])
    agent = Agent(name="support", tools=[refund, ...])
    assert_all_guarded(agent, guard)   # boot failure beats a silent gap
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

from toolwarden.engine import Decision, Gate
from toolwarden.errors import GateConfigError

__all__ = ("assert_all_guarded", "toolwarden_guardrail")

_INSTALL_HINT = (
    "the OpenAI Agents SDK is not installed, so the openai_agents adapter cannot run. "
    "Install the toolwarden extra: pip install 'toolwarden[openai-agents]'"
)
_VERSION_HINT = (
    "the installed openai-agents package does not expose tool input guardrails "
    "(ToolInputGuardrail, ToolGuardrailFunctionOutput, FunctionTool at the top level); "
    "toolwarden needs a release that does. Upgrade: pip install --upgrade openai-agents"
)


def _sdk() -> tuple[Any, Any, Any]:
    """The three SDK types this adapter touches, or a clear error naming the fix.

    Inside a function, not at module level, so that importing the module
    never requires the framework, and the two failure modes stay distinct:
    not installed (install the extra) versus installed but too old to have
    tool guardrails (upgrade). ModuleNotFoundError is caught before its
    parent ImportError because the messages differ.
    """
    try:
        from agents import FunctionTool, ToolGuardrailFunctionOutput, ToolInputGuardrail
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(_INSTALL_HINT) from exc
    except ImportError as exc:
        raise ImportError(_VERSION_HINT) from exc
    return ToolInputGuardrail, ToolGuardrailFunctionOutput, FunctionTool


def toolwarden_guardrail(
    gate: Gate,
    *,
    principal_from_context: Callable[[Any], Mapping[str, Any]] | None = None,
) -> Any:
    """A ``ToolInputGuardrail`` that runs the gate on every attached tool call.

    ``principal_from_context`` receives the host's run context object (the
    ``context=`` argument to the Runner, reached through the SDK's context
    wrapper) and returns the principal mapping. If it raises, the exception
    propagates: the principal source is host code, and a host that cannot
    state who is acting should stop, the same stance the engine takes for a
    raising ``on_decision`` sink. If it returns a non-mapping, the engine's
    boundary validation denies the call MALFORMED_CALL, so even that host
    bug fails closed.

    The audit sink fires inside ``decide()`` / ``deny_malformed()``, so the
    record exists before the SDK sees the verdict.
    """
    guardrail_cls, output_cls, _ = _sdk()

    def _judge(data: Any) -> Any:
        ctx = getattr(data, "context", None)
        tool_name = getattr(ctx, "tool_name", None)
        raw_arguments = getattr(ctx, "tool_arguments", None)

        if principal_from_context is None:
            principal: Mapping[str, Any] = {}
        else:
            principal = principal_from_context(getattr(ctx, "context", None))

        decision = _decide_raw(
            gate, tool_name=tool_name, raw_arguments=raw_arguments, principal=principal
        )
        if decision.allowed:
            return output_cls.allow(output_info=decision.record())
        return output_cls.reject_content(
            message=decision.refusal().to_tool_result(),
            output_info=decision.record(),
        )

    return guardrail_cls(guardrail_function=_judge, name="toolwarden")


def _decide_raw(
    gate: Gate,
    *,
    tool_name: Any,
    raw_arguments: Any,
    principal: Mapping[str, Any],
) -> Decision:
    """Judge the raw pre-coercion call. Every malformed shape is a denial.

    The guardrail sees the model's argument JSON as a string; parsing it is
    this adapter's one piece of interpretation, and both ways it can fail
    (no usable tool name from the SDK, JSON that will not parse) become
    MALFORMED_CALL decisions through ``deny_malformed``, which runs the same
    finish path as every decision: the sink fires and the audit line exists.
    A payload that parses to a non-object falls through to ``decide()``,
    whose boundary validation denies it, so nothing here can turn a broken
    input into an allow.
    """
    if not isinstance(tool_name, str) or not tool_name:
        return gate.deny_malformed(
            "<unknown>", "guardrail data carried no usable tool name"
        )
    if raw_arguments is None or raw_arguments == "":
        # The SDK represents a call with no arguments as an empty string;
        # that is a well-formed call with empty args, not a parse failure.
        return gate.decide(tool=tool_name, args={}, principal=principal)
    try:
        parsed = json.loads(raw_arguments)
    except (TypeError, ValueError):
        # The reason names the failure, never the payload: malformed
        # argument JSON may still hold secrets, and this reason lands in
        # records and transcripts.
        return gate.deny_malformed(tool_name, "tool argument JSON would not parse")
    return gate.decide(tool=tool_name, args=parsed, principal=principal)


def assert_all_guarded(agent: Any, guard: Any) -> None:
    """Raise unless every ``FunctionTool`` on the agent carries ``guard``.

    Guardrail attachment is per-tool opt-in, which means the failure mode
    of forgetting one is silence: the tool works, nothing warns, and it is
    unguarded in production. Calling this at startup converts that silence
    into a ``GateConfigError`` naming every unguarded tool at once.

    The check is by object identity: pass the same guardrail object you
    attached. Two separately built guardrails wrap different closures and
    are not interchangeable evidence of coverage.

    Honest limits: only ``agent.tools`` is walked. Hosted tools cannot carry
    input guardrails and are not checked (they execute on OpenAI
    infrastructure, out of this library's reach). Tools served at runtime by
    MCP servers, or reached through handoffs to other agents, are not
    visible here; run this against every agent that owns tools.
    """
    _, _, function_tool_cls = _sdk()
    unguarded: list[str] = []
    for tool in getattr(agent, "tools", None) or ():
        if not isinstance(tool, function_tool_cls):
            continue
        attached = getattr(tool, "tool_input_guardrails", None) or ()
        if not any(entry is guard for entry in attached):
            unguarded.append(str(getattr(tool, "name", "<unnamed>")))
    if unguarded:
        raise GateConfigError(
            "FunctionTool(s) without the toolwarden guardrail: "
            + ", ".join(sorted(unguarded))
            + ". Attach it via tool_input_guardrails so denied calls are "
            "blocked before execution."
        )
