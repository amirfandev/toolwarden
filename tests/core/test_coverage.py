"""The coverage report: setup-time surfacing of runtime denies.

`audit_coverage` is a pure query; these tests pin its three findings, the
per-tool permit/forbid split by declared capability, and the report's
renderings, because the non-strict adoption path leans entirely on an
operator reading this output.
"""

from __future__ import annotations

import pytest

from toolwarden import (
    NOT_APPLICABLE,
    Allow,
    CoverageReport,
    Deny,
    Facts,
    Gate,
    ToolCoverage,
    Verdict,
    policy,
)
from toolwarden.coverage import audit_coverage
from toolwarden.errors import GateConfigError


@policy("db_permit", tools=("db_exec",))
def db_permit(f: Facts) -> Verdict:
    return Allow()


@policy("db_forbid", tools=("db_exec",), permits=False)
def db_forbid(f: Facts) -> Verdict:
    return Deny("no")


@policy("email_forbid_only", tools=("send_email",), permits=False)
def email_forbid_only(f: Facts) -> Verdict:
    # Abstains for benign calls: exactly the shape whose runtime twin is
    # NO_PERMIT, since nothing on this tool can ever permit.
    return NOT_APPLICABLE


@policy("typo_target", tools=("send_faks",))
def typo_target(f: Facts) -> Verdict:
    return Allow()


ALL = [db_permit, db_forbid, email_forbid_only, typo_target]


def test_per_tool_split_is_by_declared_capability() -> None:
    report = audit_coverage(ALL, ["db_exec"])
    assert report.per_tool == (
        ToolCoverage(tool="db_exec", permitted_by=("db_permit",), forbidden_by=("db_forbid",)),
    )


def test_ungoverned_tool_reported() -> None:
    report = audit_coverage(ALL, ["db_exec", "orphan_tool"])
    assert report.ungoverned == ("orphan_tool",)
    assert not report.clean


def test_forbid_only_tool_reported() -> None:
    """Worse than ungoverned because it looks like coverage: forbid rules
    exist, someone believes the tool is handled, every call dies NO_PERMIT."""
    report = audit_coverage(ALL, ["db_exec", "send_email"])
    assert report.forbid_only == ("send_email",)
    assert not report.clean


def test_phantom_policy_reported_with_its_unknown_tools() -> None:
    report = audit_coverage(ALL, ["db_exec", "send_email"])
    assert report.phantom == (("typo_target", ("send_faks",)),)
    assert not report.clean


def test_clean_report() -> None:
    report = audit_coverage([db_permit, db_forbid], ["db_exec"])
    assert report.clean
    assert report.ungoverned == ()
    assert report.forbid_only == ()
    assert report.phantom == ()


def test_forbid_only_runtime_twin_is_no_permit() -> None:
    """The report's forbid_only finding and the runtime NO_PERMIT denial are
    the same gap seen at two times; cross-check them on one wiring."""
    gate = Gate([email_forbid_only], [], strict=False, tools=("send_email",))
    decision = gate.decide(tool="send_email", args={"to": []}, principal={})
    assert decision.allowed is False
    assert decision.outcome is not None
    assert decision.outcome.kind.value == "no_permit"


def test_ungoverned_runtime_twin_is_ungoverned_denial() -> None:
    gate = Gate([db_permit], [], strict=False, tools=("db_exec", "orphan_tool"))
    decision = gate.decide(tool="orphan_tool", args={}, principal={})
    assert decision.outcome is not None
    assert decision.outcome.kind.value == "ungoverned"


def test_render_marks_findings_with_bangs() -> None:
    report = audit_coverage(ALL, ["db_exec", "send_email", "orphan_tool"])
    text = report.render()
    lines = text.splitlines()
    assert any(line.startswith("!!") and "orphan_tool" in line and "UNGOVERNED" in line for line in lines)
    assert any(line.startswith("!!") and "send_email" in line and "FORBID-ONLY" in line for line in lines)
    assert any("typo_target" in line and "send_faks" in line for line in lines)
    # The healthy tool renders unflagged, with both columns populated.
    assert any(
        "db_exec" in line and "permit: db_permit" in line and "forbid: db_forbid" in line
        and not line.startswith("!!")
        for line in lines
    )


def test_to_dict_shape_for_ci() -> None:
    report = audit_coverage(ALL, ["db_exec", "send_email", "orphan_tool"])
    data = report.to_dict()
    assert data["clean"] is False
    assert data["ungoverned"] == ["orphan_tool"]
    assert {"tool": "db_exec", "permitted_by": ["db_permit"], "forbidden_by": ["db_forbid"]} in data["per_tool"]  # type: ignore[operator]
    assert data["phantom"] == [{"policy": "typo_target", "unknown_tools": ["send_faks"]}]


def test_report_is_order_independent() -> None:
    forward = audit_coverage(ALL, ["send_email", "db_exec"])
    backward = audit_coverage(list(reversed(ALL)), ["db_exec", "send_email"])
    assert forward == backward


def test_gate_coverage_is_a_pure_query_even_when_strict() -> None:
    gate = Gate([db_permit], [])
    report = gate.coverage(["db_exec", "orphan_tool"])
    assert isinstance(report, CoverageReport)
    assert report.ungoverned == ("orphan_tool",)  # returned, not raised


def test_bare_string_universe_rejected() -> None:
    with pytest.raises(GateConfigError, match="not a bare string"):
        audit_coverage(ALL, "db_exec")
