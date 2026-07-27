"""LangChain adapter: a handler for the ``wrap_tool_call`` middleware hook.

``toolwarden_tool_wrapper(gate, principal=...)`` returns the two-argument
handler LangChain's middleware layer expects: ``(request, handler)``. On
allow it invokes the wrapped handler with the request unchanged, so what
the gate judged is what the framework executes. On deny it short-circuits
with a ``ToolMessage`` whose content is ``Refusal.to_tool_result()`` and
whose status is ``"error"``: the tool never runs, and the model learns
which policies denied and why, in the payload every toolwarden boundary
emits.

Honest guarantee, stated plainly:

- BLOCKS BEFORE EXECUTION for every tool call routed through the agent's
  middleware chain the handler is installed in.
- Anything invoked outside that chain is invisible: a tool called directly
  via ``tool.invoke``, another agent without this middleware, or a model
  with tools bound outside the middleware-running agent. The hook governs
  the chain it is installed in, nothing more.
- The handler is synchronous, mirroring the gate. LangChain composes it
  into the sync execution path; an async-only deployment needs the async
  variant of the hook, which v0.1 does not ship.
- The hook's exact signature tracks the installed ``langchain`` version
  (``wrap_tool_call`` is a 1.x middleware concept; earlier majors lack it).
  Pin it in the lockfile.

The principal is host authority, supplied at wrap time, never model output:
tool arguments arrive in ``request.tool_call`` and there is no code path
from them to the principal.

Only ``langchain_core`` (the ToolMessage class) is imported, and only
inside the factory, so importing this module costs nothing and the core
test suite runs without the framework installed.

Usage::

    from langchain.agents import create_agent
    from langchain.agents.middleware import wrap_tool_call

    handler = toolwarden_tool_wrapper(gate, principal={"agent": "support-bot"})
    agent = create_agent(model, tools, middleware=[wrap_tool_call(handler)])
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from toolwarden.engine import Gate, PrincipalSource

__all__ = ("toolwarden_tool_wrapper",)

_INSTALL_HINT = (
    "langchain is not installed, so the langchain adapter cannot build its ToolMessage. "
    "Install the toolwarden extra: pip install 'toolwarden[langchain]' "
    "(the wrap_tool_call middleware hook needs langchain>=1.0)"
)


def _tool_message_cls() -> Any:
    """The ToolMessage class, or a clear error naming the extra to install.

    Imported inside a function, never at module level, so the adapter
    module itself imports cleanly with no framework present and the cost
    of the dependency lands exactly where the dependency is used.
    """
    try:
        from langchain_core.messages import ToolMessage
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(_INSTALL_HINT) from exc
    return ToolMessage


def toolwarden_tool_wrapper(
    gate: Gate,
    *,
    principal: PrincipalSource,
) -> Callable[[Any, Any], Any]:
    """A ``wrap_tool_call`` handler that runs the gate before every tool.

    ``principal`` is a mapping, or a zero-arg callable evaluated once per
    tool call so it can reflect current host state. A raising callable
    propagates (host bug; a host that cannot state who is acting should
    stop). A callable returning a non-mapping is denied MALFORMED_CALL by
    the engine's boundary validation, so even that bug fails closed.

    The handler contains no allow/deny logic of its own: the tool call's
    name and args go to ``decide()`` exactly as LangChain parsed them, and
    the engine's boundary validation owns every malformed shape. The audit
    sink fires inside ``decide()``, before the framework sees the verdict.
    """
    tool_message = _tool_message_cls()

    def toolwarden_wrap_tool_call(request: Any, handler: Any) -> Any:
        tool_call = getattr(request, "tool_call", None)
        if not isinstance(tool_call, Mapping):
            # Host wiring handed over something that is not a 1.x tool
            # call request. Raising is fail-closed (the tool does not run)
            # and loud, which a version mismatch should be.
            raise TypeError(
                "wrap_tool_call request has no tool_call mapping; this adapter "
                "is written against the langchain>=1.0 middleware hook"
            )
        # Deliberately untyped reads: a missing or ill-typed name or args
        # must reach decide(), whose boundary validation owns the denial.
        name: Any = tool_call.get("name")
        args: Any = tool_call.get("args")
        call_id: Any = tool_call.get("id")
        resolved = principal() if callable(principal) else principal
        decision = gate.decide(tool=name, args=args, principal=resolved)
        if decision.allowed:
            return handler(request)
        return tool_message(
            content=decision.refusal().to_tool_result(),
            tool_call_id=call_id if isinstance(call_id, str) else "",
            name=name if isinstance(name, str) else None,
            status="error",
        )

    return toolwarden_wrap_tool_call
