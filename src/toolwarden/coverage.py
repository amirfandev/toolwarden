"""Coverage: does the policy set actually govern the tool universe.

The runtime engine already denies ungoverned and unpermittable calls, so
coverage adds nothing to enforcement. What it adds is timing: every finding
here is a runtime deny surfaced at setup, when the operator is looking,
instead of in production, when the agent is. The three findings map to the
three ways an operator's mental model of "this tool is handled" can be wrong:

  ungoverned   No policy names the tool. Every call will die UNGOVERNED.
  forbid_only  Only permits=False policies name it. Worse than ungoverned,
               because it looks like coverage: someone wrote forbid rules
               and believes the tool is handled, yet every call dies
               NO_PERMIT.
  phantom      A policy names a tool outside the universe. A typo or a
               stale policy; either way the operator believes a rule is in
               force that binds to nothing.

`CoverageError`, `UncoveredFact`, and `GateConfigError` are re-exported here
because this is where the spec's layout places them; they are defined once in
`toolwarden.errors` so `isinstance` checks cannot split across two classes.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from toolwarden.errors import CoverageError, GateConfigError, UncoveredFact
from toolwarden.policy import Policy

__all__ = [
    "CoverageError",
    "CoverageReport",
    "GateConfigError",
    "ToolCoverage",
    "UncoveredFact",
    "audit_coverage",
]


@dataclass(frozen=True)
class ToolCoverage:
    """Which policies can permit and which can only forbid one tool.

    `permitted_by` lists the permits=True policies naming the tool (the ones
    capable of permitting; any of them can also deny). `forbidden_by` lists
    the permits=False policies, which can only deny or abstain. The split by
    declared capability, not by observed behavior, is deliberate: coverage
    is judged before any call exists to observe.
    """

    tool: str
    permitted_by: tuple[str, ...]
    forbidden_by: tuple[str, ...]


@dataclass(frozen=True)
class CoverageReport:
    """The full setup-time verdict on a policy set against a tool universe.

    Everything is canonically sorted at construction (tools and policy names
    lexicographic), so two reports over the same wiring are equal whatever
    order policies were registered in, mirroring the engine's own
    order-independence guarantee.
    """

    per_tool: tuple[ToolCoverage, ...]
    ungoverned: tuple[str, ...]
    forbid_only: tuple[str, ...]
    phantom: tuple[tuple[str, tuple[str, ...]], ...]

    @property
    def clean(self) -> bool:
        """True when nothing needs an operator's attention."""
        return not (self.ungoverned or self.forbid_only or self.phantom)

    def to_dict(self) -> dict[str, object]:
        """Plain-data form for CI pipelines that want to diff or gate on it."""
        return {
            "clean": self.clean,
            "per_tool": [
                {
                    "tool": tc.tool,
                    "permitted_by": list(tc.permitted_by),
                    "forbidden_by": list(tc.forbidden_by),
                }
                for tc in self.per_tool
            ],
            "ungoverned": list(self.ungoverned),
            "forbid_only": list(self.forbid_only),
            "phantom": [
                {"policy": name, "unknown_tools": list(unknown)}
                for name, unknown in self.phantom
            ],
        }

    def render(self) -> str:
        """Human rendering: one line per tool, findings prefixed with `!!`.

        The `!!` prefix keeps findings greppable in CI logs and visually
        loud in a terminal, which matters because the non-strict path prints
        this to stderr and proceeds.
        """
        ungoverned = set(self.ungoverned)
        forbid_only = set(self.forbid_only)
        pad = max((len(tc.tool) for tc in self.per_tool), default=0)
        lines: list[str] = []
        for tc in self.per_tool:
            flag = "!!" if tc.tool in ungoverned or tc.tool in forbid_only else "  "
            permit = ", ".join(tc.permitted_by) if tc.permitted_by else "-"
            forbid = ", ".join(tc.forbidden_by) if tc.forbidden_by else "-"
            note = ""
            if tc.tool in ungoverned:
                note = "  UNGOVERNED: no policy names this tool"
            elif tc.tool in forbid_only:
                note = "  FORBID-ONLY: nothing can permit, every call dies NO_PERMIT"
            lines.append(f"{flag} {tc.tool:<{pad}}  permit: {permit}  forbid: {forbid}{note}")
        for name, unknown in self.phantom:
            lines.append(f"!! policy {name!r} names unknown tool(s): {', '.join(unknown)}")
        return "\n".join(lines)


def audit_coverage(policies: Sequence[Policy], tools: Sequence[str]) -> CoverageReport:
    """Judge a policy set against a tool universe.

    Pure and side-effect free: raising on findings is the caller's decision
    (the gate's constructor and `wrap()` under strict=True), because the
    same report also serves non-strict incremental adoption and plain
    inspection.
    """
    if isinstance(tools, str):
        raise GateConfigError("tools must be a sequence of tool names, not a bare string")
    universe = sorted(set(tools))
    universe_set = set(universe)

    per_tool: list[ToolCoverage] = []
    ungoverned: list[str] = []
    forbid_only: list[str] = []
    for tool in universe:
        permitting = sorted(p.name for p in policies if tool in p.tools and p.permits)
        forbidding = sorted(p.name for p in policies if tool in p.tools and not p.permits)
        per_tool.append(ToolCoverage(tool, tuple(permitting), tuple(forbidding)))
        if not permitting and not forbidding:
            ungoverned.append(tool)
        elif not permitting:
            forbid_only.append(tool)

    phantom: list[tuple[str, tuple[str, ...]]] = []
    for pol in sorted(policies, key=lambda p: p.name):
        unknown = tuple(sorted(t for t in pol.tools if t not in universe_set))
        if unknown:
            phantom.append((pol.name, unknown))

    return CoverageReport(
        per_tool=tuple(per_tool),
        ungoverned=tuple(ungoverned),
        forbid_only=tuple(forbid_only),
        phantom=tuple(phantom),
    )
