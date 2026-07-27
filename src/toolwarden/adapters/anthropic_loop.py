"""Anthropic tool-use loop adapter: gate, dispatch, and answer in one place.

``run_tool_uses`` executes the ``tool_use`` blocks of one assistant message
and returns the ``tool_result`` blocks for the next user turn. There is no
hidden dispatcher: this function IS the loop's dispatch step, so the mapping
the gate judges (``block.input``) is the very object an allowed tool
receives as keyword arguments, with nothing running between decide and
dispatch.

Honest guarantee, stated plainly:

- BLOCKS BEFORE EXECUTION for every tool dispatched through it. Of the
  three adapters this is the strongest guarantee, because the check and the
  call sit in the same function.
- It cannot see Anthropic server-side tools (they run on Anthropic
  infrastructure and their results never pass through host dispatch), nor
  any tool a host dispatches outside this function. Route every local tool
  through it, or it governs only some of them.
- Synchronous tools only. A tool that returns a coroutine gets an errored
  result naming the mismatch instead of an unawaited object leaking into
  the transcript.

This module never imports the SDK. Blocks are read duck-typed, attribute or
key access, so SDK message objects and their plain-dict form behave
identically, and the adapter stays stdlib only (the ``anthropic`` extra
installs the client a host needs for the surrounding loop, not for this
module).

Deny-time contract (spec 9.2): a denied block yields ``is_error: true``
carrying ``Refusal.to_tool_result()``, byte-identical to what ``gate.wrap``
and the other adapters produce, so the model learns which policies denied
and why, and the loop continues instead of crashing. Unknown tools take the
same path: the gate judges them (typically UNGOVERNED) and the refusal says
so. An allowed tool the host never provided is different: that is a host
configuration bug, not a policy denial, and it is reported as one. Tool
exceptions are the tool's own failures, distinct again.

Usage::

    while True:
        response = client.messages.create(model=..., messages=convo, tools=schema)
        convo.append({"role": "assistant", "content": response.content})
        if response.stop_reason != "tool_use":
            break
        results = run_tool_uses(gate, tools, response,
                                principal={"agent": "support-bot"})
        convo.append({"role": "user", "content": results})
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from toolwarden.engine import Gate, PrincipalSource

__all__ = ("run_tool_uses",)


def run_tool_uses(
    gate: Gate,
    tools: Mapping[str, Callable[..., Any]],
    message: Any,
    *,
    principal: PrincipalSource,
) -> list[dict[str, Any]]:
    """Judge and execute one assistant message's tool_use blocks.

    Returns one ``tool_result`` dict per ``tool_use`` block, in block order,
    ready to send as the next user turn's content. Non-tool_use blocks
    (text, thinking) are skipped.

    ``principal`` is host authority: a mapping, or a zero-arg callable
    evaluated once per block so it can reflect current host state. A raising
    callable propagates (host bug, and a host that cannot state who is
    acting should stop); a callable returning a non-mapping is denied
    MALFORMED_CALL by the engine's boundary validation, so even that bug
    fails closed. Model output never touches the principal.

    A message without an iterable content list raises TypeError: that is
    host wiring handing over the wrong object, not model input, and loud
    beats silently returning zero results.
    """
    content = _field(message, "content")
    if content is None or isinstance(content, (str, bytes)) or not isinstance(content, Iterable):
        raise TypeError(
            "message has no iterable content; pass the assistant message object "
            "(or its dict form) whose content list holds the tool_use blocks"
        )
    results: list[dict[str, Any]] = []
    for block in content:
        if _field(block, "type") != "tool_use":
            continue
        results.append(_run_one(gate, tools, block, principal))
    return results


def _run_one(
    gate: Gate,
    tools: Mapping[str, Callable[..., Any]],
    block: Any,
    principal: PrincipalSource,
) -> dict[str, Any]:
    """One block through the full contract: decide, then dispatch or refuse.

    The block's name and input go to ``decide()`` exactly as found; the
    engine's boundary validation owns every malformed shape (missing name,
    non-mapping input), so this function contains no allow/deny logic of
    its own. If the decision allows, the block was well-formed by
    construction and ``fn(**block.input)`` receives the judged mapping
    itself.
    """
    block_id = _field(block, "id")
    tool_use_id = block_id if isinstance(block_id, str) else ""
    name = _field(block, "name")
    args = _field(block, "input")

    resolved = principal() if callable(principal) else principal
    decision = gate.decide(tool=name, args=args, principal=resolved)
    if not decision.allowed:
        return _error_result(tool_use_id, decision.refusal().to_tool_result())

    fn = tools.get(name)
    if fn is None:
        # A policy permitted a tool the host never provided. Dressing this
        # up as a denial would send an operator hunting through policies
        # for a bug that lives in the host's tool table.
        return _error_result(
            tool_use_id,
            f"configuration error: policy allowed tool {name!r} but the host "
            "provided no implementation for it",
        )
    try:
        outcome = fn(**args)
    except Exception as exc:  # a tool crash must not kill the loop
        return _error_result(
            tool_use_id, f"tool {name!r} raised {type(exc).__name__}: {exc}"
        )
    if inspect.iscoroutine(outcome):
        outcome.close()
        return _error_result(
            tool_use_id,
            f"configuration error: tool {name!r} returned a coroutine; "
            "run_tool_uses is synchronous",
        )
    return {"type": "tool_result", "tool_use_id": tool_use_id, "content": _render(outcome)}


def _error_result(tool_use_id: str, content: str) -> dict[str, Any]:
    return {
        "type": "tool_result",
        "tool_use_id": tool_use_id,
        "content": content,
        "is_error": True,
    }


def _render(outcome: Any) -> str:
    """A content string from whatever the tool returned.

    Strings pass through untouched; everything else becomes JSON when it
    can and ``str()`` when it cannot. No redaction is attempted or implied:
    a tool's output is already destined for model context in any loop, and
    the gate governs calls, not results (spec section 13).
    """
    if isinstance(outcome, str):
        return outcome
    try:
        return json.dumps(outcome, ensure_ascii=True, default=str)
    except (TypeError, ValueError):
        return str(outcome)


def _field(obj: Any, name: str) -> Any:
    """One field, mapping access first, then attribute, else None.

    Mapping access wins because the dict form of a block is data, and a
    Mapping subclass could also carry unrelated attributes by those names;
    for SDK block objects, attribute access is the path that fires.
    """
    if isinstance(obj, Mapping):
        return obj.get(name)
    return getattr(obj, name, None)
