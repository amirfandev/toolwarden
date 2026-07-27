"""The wrap boundary: guarded callables standing between agent and tool.

`wrap_tools` is what `Gate.wrap` delegates to. For every tool it returns a
guard with the same signature that judges first and dispatches second, so
the host swaps `tools` for `gate.wrap(tools, ...)` and nothing else about
its dispatch changes. The properties that make the guard trustworthy:

  Same view. Arguments are bound through `inspect.signature(...).bind` with
  defaults applied, so the gate judges the named-argument view the tool
  would actually execute, whether the caller used positional or keyword
  style. A call that will not bind is a MALFORMED_CALL denial, not a
  TypeError: a call the tool could not have executed must not slip past
  policy on a technicality.

  Same objects. On allow, the guard calls `fn(*args, **kwargs)` with the
  very objects the gate judged; nothing runs between decide and dispatch
  in-process, so there is no window to swap a judged value.

  Principal by shape. The principal is host-supplied at wrap time, a
  mapping (frozen by copy) or a zero-arg callable evaluated per call.
  Model-controlled values land in `ToolCall.args` and nowhere else; there
  is no code path from tool arguments to principal.

  Deny fork. `on_deny="raise"` (default) raises `ToolDenied` carrying the
  full `Refusal`; `on_deny="result"` returns the `Refusal` object for hosts
  running their own loop. **Callers using "result" must isinstance-check
  every return value**: a Refusal mistaken for tool output is silent
  corruption, which is exactly why "raise" is the default. Either way the
  audit sink fired inside `decide()` before the fork, so the log line
  exists even if calling code swallows the exception or drops the return.
"""

from __future__ import annotations

import functools
import inspect
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Literal

from toolwarden.errors import CoverageError, GateConfigError
from toolwarden.refusal import Refusal, ToolDenied

if TYPE_CHECKING:
    from toolwarden.engine import Decision, Gate, PrincipalSource


def wrap_tools(
    gate: Gate,
    tools: Mapping[str, Callable[..., Any]] | Sequence[Callable[..., Any]],
    *,
    principal: PrincipalSource,
    on_deny: Literal["raise", "result"] = "raise",
) -> dict[str, Callable[..., Any]]:
    """Guarded versions of `tools`, keyed by tool name.

    Names come from mapping keys when a mapping is passed, else from
    `fn.__name__`; anything unnameable is a `GateConfigError` at wrap time,
    because the name is what routes the call to policy and an unroutable
    tool is unusable wiring, not a runtime condition. Coverage runs here
    against the wrapped names: this is the moment a boundary learns the
    real tool universe, and a strict gate refuses to hand back guards for a
    universe its policies do not cover.
    """
    if on_deny not in ("raise", "result"):
        raise GateConfigError(f"on_deny must be 'raise' or 'result', got {on_deny!r}")
    named = _named_tools(tools)

    report = gate.coverage(tuple(named))
    if not report.clean:
        if gate.strict:
            raise CoverageError(
                "coverage findings against the wrapped tools:\n" + report.render()
            )
        # Mirrors non-strict construction: every finding lands where an
        # operator will see it, then wrapping proceeds.
        print(report.render(), file=sys.stderr)

    resolve_principal = _principal_source(principal)
    return {
        name: _guard(gate, name, fn, resolve_principal, on_deny)
        for name, fn in named.items()
    }


def _named_tools(
    tools: Mapping[str, Callable[..., Any]] | Sequence[Callable[..., Any]],
) -> dict[str, Callable[..., Any]]:
    """Resolve the tool set to a name-to-callable dict, or refuse.

    Every rejection here is a wiring error, raised before any guard exists:
    a silently skipped or misnamed tool would be a tool the operator
    believes is governed and is not.
    """
    if isinstance(tools, str):
        raise GateConfigError("wrap() takes a mapping or a sequence of callables, not a string")
    if isinstance(tools, Mapping):
        named: dict[str, Callable[..., Any]] = {}
        for name, fn in tools.items():
            if not isinstance(name, str) or not name:
                raise GateConfigError("wrap() mapping keys must be non-empty tool name strings")
            if not callable(fn):
                raise GateConfigError(f"wrap() target for {name!r} is not callable")
            named[name] = fn
        return named
    if callable(tools):
        raise GateConfigError(
            "wrap() takes a mapping or a sequence of callables; "
            "to wrap a single tool, pass [fn] or {'name': fn}"
        )
    named = {}
    for fn in tools:
        if not callable(fn):
            raise GateConfigError(f"wrap() sequence entry is not callable: {type(fn).__name__}")
        name = getattr(fn, "__name__", "")
        if not isinstance(name, str) or not name or name == "<lambda>":
            raise GateConfigError(
                "wrap() target has no usable __name__ (a lambda or a partial); "
                "pass a mapping to name it explicitly"
            )
        if name in named:
            raise GateConfigError(
                f"wrap() sequence contains two callables named {name!r}; "
                "pass a mapping to disambiguate"
            )
        named[name] = fn
    return named


def _principal_source(principal: PrincipalSource) -> Callable[[], Mapping[str, Any]]:
    """One shape for both principal forms: a zero-arg resolver.

    A mapping is copied once at wrap time, so later mutation of the
    caller's dict cannot change the identity attached to in-flight guards.
    A callable is stored as-is and evaluated per call, which is how a host
    attaches a session-scoped identity (a request context, a rotating
    credential) without the gate ever holding it. Whatever the resolver
    returns is judged by `decide()`'s boundary validation, so a callable
    returning garbage is a MALFORMED_CALL denial, not a crash.
    """
    if callable(principal):
        return principal
    if isinstance(principal, Mapping):
        frozen: dict[str, Any] = dict(principal)
        return lambda: frozen
    raise GateConfigError(
        f"principal must be a mapping or a zero-arg callable, got {type(principal).__name__}"
    )


def _guard(
    gate: Gate,
    name: str,
    fn: Callable[..., Any],
    resolve_principal: Callable[[], Mapping[str, Any]],
    on_deny: Literal["raise", "result"],
) -> Callable[..., Any]:
    """Build the sync or async guard for one tool.

    The signature is taken once, at wrap time; a callable whose signature
    cannot be introspected is refused here, because without it the guard
    could not promise the gate sees the tool's named-argument view.
    """
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError) as exc:
        raise GateConfigError(
            f"cannot introspect the signature of tool {name!r} ({type(exc).__name__}); "
            "wrap() needs it to judge the named-argument view the tool would execute"
        ) from exc

    def judge(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Decision:
        """Bind, then decide. Both failure shapes are decisions, never raises.

        A **kwargs parameter is flattened back into the top-level view
        before deciding. `bound.arguments` nests the extra keywords in a
        dict under the parameter's name, and a normalizer looking for
        `phi_fields` cannot see `kwargs["phi_fields"]`; leaving the nest in
        place lets a tool's signature shape hide a governed argument from
        policy while still delivering it to the tool, which is a judgment
        gap, not a technicality. Flattening restores the caller's named
        view, the same view an adapter judges from raw argument JSON, and
        it cannot collide with a real parameter name because bind() would
        have assigned such a keyword to that parameter instead. A tuple
        under a *args parameter stays as-is: positional extras have no
        names to restore. The bind TypeError message names parameters,
        never values, so it is safe in a reason string.
        """
        try:
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
        except TypeError as exc:
            return gate.deny_malformed(name, f"arguments do not bind to {name}(): {exc}")
        arguments = dict(bound.arguments)
        for param in sig.parameters.values():
            if param.kind is inspect.Parameter.VAR_KEYWORD and param.name in arguments:
                extra = arguments.pop(param.name)
                arguments.update(extra)
                break
        return gate.decide(tool=name, args=arguments, principal=resolve_principal())

    def deliver_denial(decision: Decision) -> Refusal:
        refusal = decision.refusal()
        if on_deny == "raise":
            raise ToolDenied(refusal)
        return refusal

    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_guard(*args: Any, **kwargs: Any) -> Any:
            decision = judge(args, kwargs)  # deciding stays synchronous
            if decision.allowed:
                return await fn(*args, **kwargs)
            return deliver_denial(decision)

        return async_guard

    @functools.wraps(fn)
    def guard(*args: Any, **kwargs: Any) -> Any:
        decision = judge(args, kwargs)
        if decision.allowed:
            return fn(*args, **kwargs)
        return deliver_denial(decision)

    return guard
