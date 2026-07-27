"""The denial taxonomy and its canonical ordering.

`DenyKind` declaration order IS headline precedence: when a decision carries
several denials, the one whose kind appears first below is the headline
`outcome`. The order runs from "the call itself was broken" down to "nothing
governs this tool", so the headline always names the earliest failure in the
pipeline, which is the one an operator must fix first.

The sort helpers here exist so that the ordering is defined in exactly one
place. Registration order of policies and normalizers must never influence
any byte of any output; sorting every denial list with `denial_sort_key`
makes the headline a pure function of the denial set.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable
from dataclasses import dataclass


class DenyKind(enum.Enum):
    """Why a call was denied. Declaration order is headline precedence.

    MALFORMED_CALL: the call itself is structurally wrong (non-string tool,
        non-mapping args or principal, an unbindable `wrap()` invocation,
        unparseable model argument JSON in an adapter). Produced by the
        engine or an adapter before any normalizer runs.
    UNPARSEABLE: a fact a policy needs could not be computed. Produced by
        the engine on the policy's behalf; the reason carries the
        normalizer's own words. Fail-closed made visible and countable.
    POLICY_FORBADE: the fact computed fine and the rule said no. The only
        kind meaning the policy worked as intended against a real violation.
    POLICY_ERROR: the policy itself misbehaved (raised, read an undeclared
        fact, or violated its permits=False contract). A bug report, not a
        violation report, hence a different kind with a different owner.
    NO_PERMIT: policies govern the tool, none denied, none permitted. The
        allow side of the policy set has a gap.
    UNGOVERNED: no policy names the tool at all. The runtime twin of the
        coverage report's ungoverned list.
    """

    MALFORMED_CALL = "malformed_call"
    UNPARSEABLE = "unparseable"
    POLICY_FORBADE = "policy_forbade"
    POLICY_ERROR = "policy_error"
    NO_PERMIT = "no_permit"
    UNGOVERNED = "ungoverned"


@dataclass(frozen=True)
class Denial:
    """One reason the call must not run.

    `policy` is the policy the denial was issued on behalf of, or "engine"
    for engine-synthesized denials (MALFORMED_CALL, NO_PERMIT, UNGOVERNED).
    UNPARSEABLE and POLICY_ERROR carry a real policy name even though the
    engine minted them, because that is whose declared needs or whose body
    the failure belongs to.
    """

    kind: DenyKind
    policy: str
    reason: str


_KIND_PRECEDENCE: dict[DenyKind, int] = {
    kind: index for index, kind in enumerate(DenyKind)
}


def kind_precedence(kind: DenyKind) -> int:
    """Position of `kind` in the headline order, 0 being most severe.

    Derived from `DenyKind` declaration order rather than written out twice,
    so adding a kind cannot leave the precedence table stale.
    """
    return _KIND_PRECEDENCE[kind]


def denial_sort_key(denial: Denial) -> tuple[int, str, str]:
    """Canonical sort key: (kind precedence, policy, reason).

    Sorting by this key makes the first element of any denial list the
    headline outcome, deterministically, whatever order the denials were
    collected in.
    """
    return (_KIND_PRECEDENCE[denial.kind], denial.policy, denial.reason)


def sort_denials(denials: Iterable[Denial]) -> tuple[Denial, ...]:
    """All denials in canonical order, ready to store on a Decision."""
    return tuple(sorted(denials, key=denial_sort_key))
