"""The call being judged and the three verdicts a policy can return.

A policy body is a pure function from `Facts` to `Verdict`, and `Verdict` is
deliberately closed: `Allow`, `Deny(reason)`, or the `NOT_APPLICABLE`
singleton. There is no fourth value, no None, no exception-as-answer. The
engine treats anything else escaping a body as a POLICY_ERROR denial, so the
worst a confused policy can do is deny.

`Allow` and `Deny` carry no policy name. The engine attributes every verdict
to the policy whose body produced it, which means a policy cannot speak on
another policy's behalf and a copy-pasted body cannot smuggle a stale name
into the audit trail.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, ClassVar, Self, TypeAlias, cast


@dataclass(frozen=True)
class ToolCall:
    """One tool invocation as the gate judges it.

    `args` is model-controlled content and is treated as hostile: policies
    should judge facts computed from it by normalizers, not the raw values.
    `principal` is host-supplied identity metadata, never model-supplied;
    adapters own its construction and there is no code path from `args` into
    it. Authority is enforced by that shape, not by validation.
    """

    tool: str
    args: Mapping[str, Any]
    principal: Mapping[str, Any]


@dataclass(frozen=True)
class Allow:
    """Explicit permit. Policies return it bare; the engine records the
    policy name.

    A call is allowed only when at least one policy returns this and none
    denies. Abstention is never a permit, which is why `NOT_APPLICABLE`
    exists as a distinct value instead of overloading `Allow`.
    """


@dataclass(frozen=True)
class Deny:
    """Refusal from a policy body. Carries only the reason; the engine
    attributes the policy name and assigns kind POLICY_FORBADE.

    Any single `Deny` defeats every `Allow` for the call. Reasons are
    written for the transcript and the audit record both: name the rule and
    the observed fact, never raw argument values.
    """

    reason: str


class NotApplicable:
    """This policy does not govern this call. Not a permit.

    A singleton, exported as `NOT_APPLICABLE`, so identity comparison works
    and a policy cannot construct a second, unequal instance. Abstaining
    contributes nothing to the decision: a call reached only by abstentions
    is denied NO_PERMIT, because silence must never accumulate into an
    allow.
    """

    _instance: ClassVar[NotApplicable | None] = None

    def __new__(cls) -> Self:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cast(Self, cls._instance)

    def __repr__(self) -> str:
        return "NotApplicable"


NOT_APPLICABLE = NotApplicable()

Verdict: TypeAlias = Allow | Deny | NotApplicable
