"""Construction-time and policy-contract exceptions.

Every exception here is raised on the operator's side of the boundary, never
across it. `UndeclaredFact` escapes a policy body and is converted by the
engine into a POLICY_ERROR denial; the other three abort `Gate` construction
before the first call is ever judged. None of them can reach a caller of
`Gate.decide()`, because a gate that would raise them refuses to exist, and a
policy that raises inside `decide()` is caught and denied. That is the shape
of the safety argument: a bad configuration is loud at startup, a bad policy
is a deny at runtime, and neither is ever an allow.
"""

from __future__ import annotations


class UndeclaredFact(Exception):
    """A policy body read a fact it never declared in `needs`.

    Raised by `Facts.__getitem__`. Declaration is what lets the gate deny
    before the body runs when a fact is Unavailable, and what lets
    construction-time coverage checks prove every needed fact has a
    provider. An undeclared read would bypass both guarantees, so it is an
    error in the policy, not a lookup miss. The engine catches this and
    converts it to `Denial(POLICY_ERROR, ...)`: the buggy policy silences
    only itself, and its silence is a deny.
    """

    def __init__(self, fact: str) -> None:
        super().__init__(
            f"fact {fact!r} was read by a policy that did not declare it in needs"
        )
        self.fact = fact


class UncoveredFact(Exception):
    """A policy needs a fact that no registered normalizer provides for a tool.

    Raised at `Gate` construction. If this were tolerated, the fact would be
    permanently Unavailable at runtime and every governed call would die
    UNPARSEABLE, which is fail-closed but useless. Refusing to construct
    makes "not computed" unrepresentable at runtime.
    """

    def __init__(self, policy: str, fact: str, tool: str) -> None:
        super().__init__(
            f"policy {policy!r} needs fact {fact!r} for tool {tool!r}, "
            "but no registered normalizer provides it for that tool"
        )
        self.policy = policy
        self.fact = fact
        self.tool = tool


class CoverageError(Exception):
    """A strict gate saw an unclean coverage report.

    Raised at construction or wrap time when `strict=True` (the default) and
    the tool universe contains ungoverned tools, forbid-only tools, or
    phantom policy targets. The message names every finding, because an
    operator fixing coverage should see the whole gap at once, not one
    finding per restart.
    """


class GateConfigError(Exception):
    """The gate's wiring is unusable: duplicate policy or normalizer names,
    two distinct `FactKey` objects sharing a name, two normalizers providing
    the same fact for the same tool, or a `wrap()` target with no usable
    name.

    Raised before the first call. Ambiguous wiring cannot be resolved
    fail-closed at runtime because the ambiguity is about which code should
    have run, so the only safe answer is to refuse to start.
    """
