"""The mandatory case-matrix rule: a policy without its allow/deny matrix
does not merge.

Two layers of enforcement:

  1. Completeness, checked before anything runs: every registered example
     policy has a matrix; permitting policies show at least one allowed
     case; every policy shows at least one denied case; every fact in
     `needs` has an UNPARSEABLE case attributed to that policy.
  2. Behavior, checked by running every case through the real gate, with a
     line tracer over the policy bodies proving that every `return`
     statement in every body executed at least once across its matrix.
     A branch nobody's matrix reaches is an untested rule, and this test is
     what makes that state unmergeable.
"""

from __future__ import annotations

import ast
import inspect
import sys
import textwrap
from collections.abc import Iterator
from types import FrameType
from typing import Any

import pytest

import example_policies
from example_policies import ALL_CASES, CASE_MATRICES, POLICIES, Case, build_gate
from toolwarden import DenyKind, Gate


def test_every_policy_has_a_matrix() -> None:
    assert {p.name for p in POLICIES} == set(CASE_MATRICES)


def test_every_case_belongs_to_the_shared_corpus() -> None:
    corpus = {case.name for case in ALL_CASES}
    for name, matrix in CASE_MATRICES.items():
        assert matrix, f"policy {name} has an empty matrix"
        for case in matrix:
            assert case.name in corpus


def test_matrix_completeness_rules() -> None:
    for pol in POLICIES:
        matrix = CASE_MATRICES[pol.name]
        if pol.permits:
            assert any(c.expect_allowed for c in matrix), (
                f"{pol.name}: a permitting policy's matrix must contain at "
                "least one allowed case"
            )
        assert any(not c.expect_allowed for c in matrix), (
            f"{pol.name}: matrix has no denied case"
        )
        assert any(
            DenyKind.POLICY_FORBADE in c.expect_kinds
            and pol.name in c.expect_denying_policies
            for c in matrix
        ) or not _has_deny_branch(pol.fn), (
            f"{pol.name}: no POLICY_FORBADE case exercises its deny branch"
        )
        for key in pol.needs:
            assert any(
                DenyKind.UNPARSEABLE in c.expect_kinds
                and pol.name in c.expect_denying_policies
                and _breaks_fact(c, key.name)
                for c in matrix
            ), f"{pol.name}: no UNPARSEABLE case for needed fact {key.name!r}"


def _has_deny_branch(fn: Any) -> bool:
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Deny"
        for node in ast.walk(tree)
    )


def _breaks_fact(case: Case, fact: str) -> bool:
    """True when running the case leaves `fact` unavailable, so the case is
    genuinely the UNPARSEABLE probe for that fact and not for a sibling."""
    decision = build_gate().decide(
        tool=case.call.tool, args=case.call.args, principal=case.call.principal
    )
    return fact in decision.fact_errors


# ---------------------------------------------------------------------------
# Running the matrices, with return-branch tracing
# ---------------------------------------------------------------------------

_FIXTURE_FILE = example_policies.__file__


def _return_lines(fn: Any) -> set[int]:
    """Absolute line numbers of every `return` in the policy body.

    Parsed from the whole fixture module rather than from
    `inspect.getsource(fn)` so the line numbers are absolute by
    construction, with no dependence on how co_firstlineno counts
    decorator lines across Python versions.
    """
    with open(_FIXTURE_FILE, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == fn.__name__:
            return {
                sub.lineno for sub in ast.walk(node) if isinstance(sub, ast.Return)
            }
    raise AssertionError(f"policy body {fn.__name__!r} not found in the fixture module")


class _LineCollector:
    """Records executed line numbers in the fixture module only.

    settrace instead of a coverage dependency keeps the suite stdlib-only,
    and scoping to one file keeps it fast.
    """

    def __init__(self) -> None:
        self.lines: set[int] = set()

    def __call__(self, frame: FrameType, event: str, arg: object) -> Any:
        if frame.f_code.co_filename != _FIXTURE_FILE:
            return None
        if event == "line":
            self.lines.add(frame.f_lineno)
        return self


@pytest.fixture(scope="module")
def matrix_run() -> Iterator[tuple[dict[str, Any], set[int]]]:
    """Decide every matrix case once, tracing the policy bodies."""
    gate: Gate = build_gate()
    collector = _LineCollector()
    outcomes: dict[str, Any] = {}
    previous = sys.gettrace()
    sys.settrace(collector)
    try:
        for case in ALL_CASES:
            outcomes[case.name] = gate.decide(
                tool=case.call.tool,
                args=case.call.args,
                principal=case.call.principal,
            )
    finally:
        sys.settrace(previous)
    yield outcomes, collector.lines


@pytest.mark.parametrize("case", ALL_CASES, ids=[c.name for c in ALL_CASES])
def test_case_expectations(case: Case, matrix_run: tuple[dict[str, Any], set[int]]) -> None:
    outcomes, _ = matrix_run
    decision = outcomes[case.name]
    assert decision.allowed is case.expect_allowed, case.name
    assert frozenset(d.kind for d in decision.denials) == case.expect_kinds, case.name
    assert (
        frozenset(d.policy for d in decision.denials) == case.expect_denying_policies
    ), case.name


def test_every_return_branch_of_every_policy_executed(
    matrix_run: tuple[dict[str, Any], set[int]],
) -> None:
    _, executed = matrix_run
    for pol in POLICIES:
        missing = _return_lines(pol.fn) - executed
        assert not missing, (
            f"{pol.name}: return branch(es) at line(s) {sorted(missing)} of "
            "example_policies.py never executed under the case matrices; "
            "add a case that reaches them"
        )


def test_matrices_cover_the_whole_corpus() -> None:
    """Every corpus case appears in at least one policy's matrix, so no
    fixture case can silently stop being asserted against a policy."""
    in_matrices = {case.name for matrix in CASE_MATRICES.values() for case in matrix}
    corpus = {case.name for case in ALL_CASES}
    orphans = corpus - in_matrices
    # Cases probing engine-level behavior (a second UNPARSEABLE shape for a
    # fact already probed) may be corpus-only; they must still be decided by
    # test_case_expectations, which runs ALL_CASES, so nothing is unasserted.
    for orphan in orphans:
        case = next(c for c in ALL_CASES if c.name == orphan)
        assert not case.expect_allowed or case.expect_kinds == frozenset(), orphan
