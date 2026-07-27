"""The @policy decorator and the Policy record it produces.

A policy is data plus one pure function. The declaration (name, tools, needs,
permits) is not documentation: the engine routes on `tools`, pre-computes and
pre-checks `needs`, and holds the body to the `permits` contract. Putting the
declaration in the decorator instead of inside the body is what makes every
guarantee checkable at construction time, before the first call is judged.

Why `permits` exists at all: a forbid-rule ("prod is read-only") and a
permit-rule ("reads are in scope") have different blast radii when buggy. A
forbid-rule that accidentally returns Allow would silently widen access, so a
policy declared `permits=False` has that path closed: the engine converts its
Allow into a POLICY_ERROR denial. The flag also feeds the coverage report,
which can then distinguish a tool that merely has forbid rules from a tool
something can actually permit.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from toolwarden.errors import GateConfigError
from toolwarden.facts import FactKey, Facts
from toolwarden.types import Verdict


@dataclass(frozen=True)
class Policy:
    """One registered rule: its declaration and its body.

    `fn` is the decorated function, a pure map from `Facts` to `Verdict`.
    Validation lives in `__post_init__` rather than in the decorator so that
    a `Policy` built by hand (tests, loaders) is held to the same contract
    as a decorated one.
    """

    name: str
    tools: tuple[str, ...]
    needs: tuple[FactKey[Any], ...]
    permits: bool
    fn: Callable[[Facts], Verdict]

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise GateConfigError("policy name must be a non-empty string")
        if self.name == "engine":
            # "engine" is the attribution on engine-synthesized denials. A
            # policy carrying it could forge engine authorship in the audit
            # trail, so the name is reserved.
            raise GateConfigError('policy name "engine" is reserved for engine-synthesized denials')
        if not self.tools:
            raise GateConfigError(
                f"policy {self.name!r} declares no tools; a policy that governs "
                "nothing is dead wiring, not a rule"
            )
        for tool in self.tools:
            if not isinstance(tool, str) or not tool:
                raise GateConfigError(
                    f"policy {self.name!r} has a tool name that is not a non-empty string"
                )
        for key in self.needs:
            if not isinstance(key, FactKey):
                raise GateConfigError(
                    f"policy {self.name!r} has a needs entry that is not a FactKey: "
                    f"{type(key).__name__}"
                )
        if not isinstance(self.permits, bool):
            raise GateConfigError(f"policy {self.name!r}: permits must be a bool")
        if not callable(self.fn):
            raise GateConfigError(f"policy {self.name!r}: body is not callable")


def policy(
    name: str,
    *,
    tools: Sequence[str],
    needs: Sequence[FactKey[Any]] = (),
    permits: bool = True,
) -> Callable[[Callable[[Facts], Verdict]], Policy]:
    """Declare a policy over a function from `Facts` to `Verdict`.

    The decorated name becomes a `Policy` object, not a function: it is meant
    to be handed to `Gate(policies=[...])`, and the gate rejects anything
    that is not a `Policy`, which catches a forgotten decorator at
    construction instead of at the first misrouted call.

    `tools` and `needs` are rejected as bare strings before conversion,
    because `tuple("db_exec")` silently becomes seven one-letter tool names
    and every check downstream would then pass vacuously.
    """
    if isinstance(tools, str):
        raise GateConfigError(
            f"policy {name!r}: tools must be a sequence of tool names, not a bare string"
        )
    if isinstance(needs, (str, FactKey)):
        raise GateConfigError(f"policy {name!r}: needs must be a sequence of FactKey, not a scalar")

    def bind(fn: Callable[[Facts], Verdict]) -> Policy:
        return Policy(
            name=name,
            tools=tuple(tools),
            needs=tuple(needs),
            permits=permits,
            fn=fn,
        )

    return bind
