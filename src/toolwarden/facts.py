"""Typed fact keys, the Unavailable value, and the Facts view.

A fact is in exactly one of three states, and the states cannot be merged:

  Computed     A normalizer produced a value. "Absent but fine" is a value
               too: an empty tuple, `SqlClass.UNKNOWN`. The policy body sees
               the typed value.
  Unavailable  A normalizer could not trust the input, or raised. It is a
               VALUE, `Unavailable(fact, reason)`, never None and never an
               exception that escapes. The engine denies (UNPARSEABLE) on
               the policy's behalf; the body never runs.
  Undeclared   The policy never declared the fact in `needs`, or no
               normalizer covers it for a tool. `Gate(...)` refuses to
               construct on the coverage gap; a runtime read raises
               `UndeclaredFact`, which the engine converts to POLICY_ERROR.

The point of the split: a policy body only ever executes on facts that are
present and trusted. Every failure mode short of that is a deny that no
policy author had to remember to write. There is no path from unparseable
input to an allow.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any, Generic, TypeVar, cast

from toolwarden.errors import UndeclaredFact

T = TypeVar("T")


@dataclass(frozen=True)
class FactKey(Generic[T]):
    """A typed name for one fact. `T` is phantom: it exists only for mypy.

    `f[SQL_CLASS]` infers as `SqlClass` with zero casts because
    `Facts.__getitem__` is generic over the key. The name is the identity;
    two keys with the same name are the same fact, and the gate refuses to
    construct when two distinct key objects share a name, so a collision is
    a startup error rather than a silent aliasing bug. Any package mints
    keys in its own module; the fact namespace is open, the typing is not.
    """

    name: str


@dataclass(frozen=True)
class Unavailable:
    """A fact that was asked for and could not be computed. A value, not an
    absence, never None, never an exception.

    Returned by normalizers (inside their result mapping) or synthesized by
    the engine when a normalizer raises or breaks its batch contract. A
    policy body never sees one: the engine turns any Unavailable needed
    fact into an UNPARSEABLE denial before the body runs. `reason` is
    written for a compliance reader, because it lands verbatim in the audit
    record.
    """

    fact: str
    reason: str


class Facts:
    """The read-only view a policy body judges: the call, plus its declared
    facts, already computed and already trusted.

    Built by the engine per policy, restricted to that policy's `needs`.
    By the time a body holds one of these, the engine has proven every
    needed fact is Computed: any Unavailable fact already became an
    UNPARSEABLE denial and the body was never called. That prior proof is
    what lets `__getitem__` return a bare `T` instead of `T | Unavailable`,
    and it is why there is no `.get` with a failure-shaped return: failure
    handling lives in the engine, not in policy bodies.

    `args` and `principal` are visible for the cases that need them (an env
    check, a principal role), but policies should judge facts, not args:
    facts are what normalizers vetted and what the audit record logs.
    """

    __slots__ = ("_computed", "_needs", "args", "principal", "tool")

    def __init__(
        self,
        *,
        tool: str,
        args: Mapping[str, Any],
        principal: Mapping[str, Any],
        computed: Mapping[str, object],
        needs: Collection[str],
    ) -> None:
        """Engine-internal constructor.

        `computed` maps fact names to Computed values; `needs` is the set of
        fact names the owning policy declared. The engine guarantees every
        name in `needs` is present in `computed` with a non-Unavailable
        value before constructing this view.
        """
        self.tool = tool
        self.args = args
        self.principal = principal
        self._computed = computed
        self._needs = frozenset(needs)

    def __getitem__(self, key: FactKey[T]) -> T:
        """The declared fact's value, typed as `T`.

        Raises `UndeclaredFact` for any key outside the owning policy's
        `needs`; the engine converts that to a POLICY_ERROR denial, so an
        undeclared read is a deny, not a lookup that happens to work.
        Never returns `Unavailable`: the gate denied before this body ran.
        The isinstance check below is a tripwire for an engine bug, not a
        code path; if it ever fires, the raise escapes the policy body and
        becomes a POLICY_ERROR denial, which keeps even that failure
        fail-closed.
        """
        if key.name not in self._needs:
            raise UndeclaredFact(key.name)
        value = self._computed[key.name]
        if isinstance(value, Unavailable):
            raise TypeError(
                f"engine invariant violated: fact {key.name!r} is Unavailable "
                "inside a policy body"
            )
        return cast(T, value)
