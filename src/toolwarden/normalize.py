"""The @normalizer decorator, Normalizer, and the batch contract enforcer.

A normalizer is the only code that reads raw model-controlled arguments; it
turns them into typed facts or into `Unavailable`, and nothing else in the
system touches args again. The enforcement in `run_normalizers` exists
because normalizers are operator-written and therefore buggy in ordinary
ways, and every one of those ordinary bugs must land on the deny side:

  1. A normalizer runs iff `call.tool` is in its declared tools. No sniffing
     args to guess relevance; the declaration IS the routing, same as for
     policies.
  2. Its returned mapping must cover exactly its `provides`. A promised key
     it omitted becomes `Unavailable`; a key outside `provides` invalidates
     the whole batch to `Unavailable`, because a normalizer confused about
     its own output cannot be trusted about any of it.
  3. If it raises, every declared key becomes `Unavailable`. A normalizer
     bug is indistinguishable from hostile input, which is the correct
     paranoia.
  4. Graceful failure is returned, not raised: the normalizer puts an
     `Unavailable(fact, reason)` in its result mapping, and the reason is
     written for a compliance reader because it lands verbatim in the audit
     record.

No exception ever escapes this module's runner. The engine calls it inside
`decide()`, and an escape there would abort the decision instead of denying
it, which is exactly the fail-open path this library exists to close.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from toolwarden.errors import GateConfigError
from toolwarden.facts import FactKey, Unavailable
from toolwarden.types import ToolCall

NormalizerFn = Callable[[ToolCall], Mapping[FactKey[Any], object]]


@dataclass(frozen=True)
class Normalizer:
    """One registered fact producer: its declaration and its function.

    `provides` is a promise the engine holds it to on every run; see the
    module docstring for the batch contract. Validation lives in
    `__post_init__` so hand-built instances face the same checks as
    decorated ones.
    """

    name: str
    tools: tuple[str, ...]
    provides: tuple[FactKey[Any], ...]
    fn: NormalizerFn

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise GateConfigError("normalizer name must be a non-empty string")
        if not self.tools:
            raise GateConfigError(
                f"normalizer {self.name!r} declares no tools, so it would never run"
            )
        for tool in self.tools:
            if not isinstance(tool, str) or not tool:
                raise GateConfigError(
                    f"normalizer {self.name!r} has a tool name that is not a non-empty string"
                )
        if not self.provides:
            raise GateConfigError(
                f"normalizer {self.name!r} provides no facts, so it can have no effect"
            )
        seen: set[str] = set()
        for key in self.provides:
            if not isinstance(key, FactKey):
                raise GateConfigError(
                    f"normalizer {self.name!r} has a provides entry that is not a FactKey: "
                    f"{type(key).__name__}"
                )
            if key.name in seen:
                raise GateConfigError(
                    f"normalizer {self.name!r} lists fact {key.name!r} in provides twice"
                )
            seen.add(key.name)
        if not callable(self.fn):
            raise GateConfigError(f"normalizer {self.name!r}: fn is not callable")


def normalizer(
    name: str,
    *,
    tools: Sequence[str],
    provides: Sequence[FactKey[Any]],
) -> Callable[[NormalizerFn], Normalizer]:
    """Declare a normalizer over a function from `ToolCall` to a fact mapping.

    The decorated name becomes a `Normalizer` object for registration with
    `Gate(normalizers=[...])`. As with @policy, bare strings are rejected
    before tuple conversion so a forgotten pair of parentheses cannot turn
    one tool name into several one-letter ones.
    """
    if isinstance(tools, str):
        raise GateConfigError(
            f"normalizer {name!r}: tools must be a sequence of tool names, not a bare string"
        )
    if isinstance(provides, (str, FactKey)):
        raise GateConfigError(
            f"normalizer {name!r}: provides must be a sequence of FactKey, not a scalar"
        )

    def bind(fn: NormalizerFn) -> Normalizer:
        return Normalizer(
            name=name,
            tools=tuple(tools),
            provides=tuple(provides),
            fn=fn,
        )

    return bind


def run_normalizers(normalizers: Sequence[Normalizer], call: ToolCall) -> dict[str, object]:
    """Run every normalizer matching `call.tool` under the batch contract.

    Returns the fact table for this call: fact name to a computed value or
    an `Unavailable`. Never raises. The gate's construction checks forbid
    two normalizers providing the same fact for the same tool, so the
    batches never collide; if this function is used outside a gate with
    colliding providers, the later registration wins, which is why the gate
    refuses that wiring in the first place.
    """
    table: dict[str, object] = {}
    for nrm in normalizers:
        if call.tool not in nrm.tools:
            continue
        table.update(_run_batch(nrm, call))
    return table


def _run_batch(nrm: Normalizer, call: ToolCall) -> dict[str, object]:
    """One normalizer's output, forced into compliance with its declaration.

    Every failure path returns values; the reasons quote the normalizer's
    name so the audit record points at the code that broke.
    """
    declared = [key.name for key in nrm.provides]
    declared_set = frozenset(declared)

    def poisoned(reason: str) -> dict[str, object]:
        return {name: Unavailable(name, reason) for name in declared}

    try:
        produced = nrm.fn(call)
        if not isinstance(produced, Mapping):
            return poisoned(f"{nrm.name} returned {type(produced).__name__}, not a mapping")
        # Key inspection stays inside the try block: a hostile or buggy
        # Mapping subclass can raise during iteration, and a FactKey
        # subclass can raise from its `name` attribute (a plain FactKey
        # cannot, but `produced` is operator code and gets no benefit of
        # the doubt). Both must become values, or `decide()` raises and the
        # host's dispatch code decides what a crash means, which is the
        # fail-open path this module exists to close.
        by_name: dict[str, object] = {}
        for key, value in produced.items():
            key_name = key.name if isinstance(key, FactKey) else None
            if key_name is None or key_name not in declared_set:
                label = key_name if key_name is not None else type(key).__name__
                return poisoned(f"{nrm.name} produced undeclared fact {label}")
            by_name[key_name] = value
    except Exception as exc:
        return poisoned(f"{nrm.name} raised {type(exc).__name__}")

    return {
        name: (
            by_name[name]
            if name in by_name
            else Unavailable(name, f"{nrm.name} did not produce it")
        )
        for name in declared
    }
