"""Engine semantics: each rule of the decide sequence, tested on its own.

The gates here are purpose-built per test with rigged policies, because the
claim under test is about the engine's handling, not about any particular
policy being sensible.
"""

from __future__ import annotations

import itertools
from collections.abc import Mapping
from typing import Any

import pytest

from toolwarden import (
    NOT_APPLICABLE,
    Allow,
    Decision,
    Deny,
    DenyKind,
    Facts,
    Gate,
    ToolCall,
    Unavailable,
    Verdict,
    policy,
)
from toolwarden.errors import UndeclaredFact
from toolwarden.facts import FactKey
from toolwarden.normalize import Normalizer, normalizer
from toolwarden.policy import Policy
from toolwarden.types import NotApplicable

WORD: FactKey[str] = FactKey("word")


def _word_normalizer(record_runs: list[str] | None = None) -> Normalizer:
    @normalizer("wordish", tools=("t",), provides=(WORD,))
    def wordish(call: ToolCall) -> Mapping[FactKey[Any], object]:
        if record_runs is not None:
            record_runs.append(call.tool)
        return {WORD: str(call.args.get("word", ""))}

    return wordish


def _allow_all(name: str = "allow_all", tool: str = "t") -> Policy:
    @policy(name, tools=(tool,), needs=(WORD,))
    def allower(f: Facts) -> Verdict:
        return Allow()

    return allower


# ---------------------------------------------------------------------------
# Step 1: boundary validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "args", "principal", "expected_fragments"),
    [
        (42, {}, {}, ["tool is not a string (got int)"]),
        ("", {}, {}, ["tool name is empty"]),
        ("t", None, {}, ["args is not a mapping (got NoneType)"]),
        ("t", {}, "prod", ["principal is not a mapping (got str)"]),
        (
            None,
            "boom",
            [],
            [
                "tool is not a string (got NoneType)",
                "args is not a mapping (got str)",
                "principal is not a mapping (got list)",
            ],
        ),
    ],
)
def test_malformed_call_is_single_denial(
    tool: Any, args: Any, principal: Any, expected_fragments: list[str]
) -> None:
    gate = Gate([_allow_all()], [_word_normalizer()])
    decision = gate.decide(tool=tool, args=args, principal=principal)
    assert decision.allowed is False
    (denial,) = decision.denials  # several structural problems, ONE denial
    assert denial.kind is DenyKind.MALFORMED_CALL
    assert denial.policy == "engine"
    for fragment in expected_fragments:
        assert fragment in denial.reason
    # Reasons carry type names only; the payload itself must not leak.
    assert "boom" not in denial.reason
    assert decision.trail == ()
    assert decision.permits == ()


def test_malformed_call_runs_nothing_else() -> None:
    runs: list[str] = []
    body_ran: list[bool] = []

    @policy("observer", tools=("t",), needs=(WORD,))
    def observer(f: Facts) -> Verdict:
        body_ran.append(True)
        return Allow()

    gate = Gate([observer], [_word_normalizer(runs)])
    gate.decide(tool="t", args=None, principal={})  # type: ignore[arg-type]
    assert runs == []
    assert body_ran == []


# ---------------------------------------------------------------------------
# Step 2: routing
# ---------------------------------------------------------------------------


def test_ungoverned_tool_denies_by_default() -> None:
    gate = Gate([_allow_all(tool="t")], [_word_normalizer()])
    decision = gate.decide(tool="other_tool", args={}, principal={})
    assert decision.allowed is False
    (denial,) = decision.denials
    assert denial.kind is DenyKind.UNGOVERNED
    assert denial.policy == "engine"
    assert denial.reason == "no policy governs tool 'other_tool'"


def test_ungoverned_skips_normalizers_entirely() -> None:
    runs: list[str] = []
    gate = Gate([_allow_all(tool="t")], [_word_normalizer(runs)])
    gate.decide(tool="other_tool", args={}, principal={})
    assert runs == []


def test_policy_body_never_sees_undeclared_tool() -> None:
    """Routing is the declaration: the body provably does not run for a tool
    outside policy.tools, even when another policy governs that tool."""
    seen_tools: list[str] = []

    @policy("only_t", tools=("t",))
    def only_t(f: Facts) -> Verdict:
        seen_tools.append(f.tool)
        return Allow()

    @policy("only_u", tools=("u",))
    def only_u(f: Facts) -> Verdict:
        seen_tools.append(f.tool)
        return Allow()

    gate = Gate([only_t, only_u], [])
    gate.decide(tool="u", args={}, principal={})
    gate.decide(tool="t", args={}, principal={})
    assert seen_tools == ["u", "t"]


# ---------------------------------------------------------------------------
# Step 4: evaluation
# ---------------------------------------------------------------------------


def test_deny_overrides_permit() -> None:
    @policy("naysayer", tools=("t",), needs=(WORD,))
    def naysayer(f: Facts) -> Verdict:
        return Deny("the word is forbidden")

    gate = Gate([_allow_all(), naysayer], [_word_normalizer()])
    decision = gate.decide(tool="t", args={"word": "x"}, principal={})
    assert decision.allowed is False
    assert decision.permits == ("allow_all",)  # the permit existed and lost
    (denial,) = decision.denials
    assert denial.kind is DenyKind.POLICY_FORBADE
    assert denial.policy == "naysayer"
    assert denial.reason == "the word is forbidden"


def test_allowed_requires_explicit_permit() -> None:
    """All abstentions is a deny: silence never accumulates into an allow."""

    @policy("shrug_a", tools=("t",))
    def shrug_a(f: Facts) -> Verdict:
        return NOT_APPLICABLE

    @policy("shrug_b", tools=("t",))
    def shrug_b(f: Facts) -> Verdict:
        return NOT_APPLICABLE

    decision = Gate([shrug_a, shrug_b], []).decide(tool="t", args={}, principal={})
    assert decision.allowed is False
    (denial,) = decision.denials
    assert denial.kind is DenyKind.NO_PERMIT
    assert denial.policy == "engine"
    assert denial.reason == "policies govern 't' but none permitted this call"
    assert decision.trail == (("shrug_a", "not_applicable"), ("shrug_b", "not_applicable"))


def test_single_permit_allows() -> None:
    gate = Gate([_allow_all()], [_word_normalizer()])
    decision = gate.decide(tool="t", args={"word": "hello"}, principal={})
    assert decision.allowed is True
    assert decision.denials == ()
    assert decision.permits == ("allow_all",)
    assert decision.outcome is None
    assert decision.facts == {"word": "hello"}
    assert decision.fact_errors == {}


@pytest.mark.parametrize(
    ("body", "expected_reason"),
    [
        (lambda f: (_ for _ in ()).throw(RuntimeError("kaboom")), "policy raised RuntimeError"),
        (lambda f: f[WORD], "policy raised UndeclaredFact"),
        (lambda f: "yes", "policy returned str, not a Verdict"),
        (lambda f: None, "policy returned NoneType, not a Verdict"),
    ],
)
def test_policy_misbehavior_is_policy_error(body: Any, expected_reason: str) -> None:
    """A buggy policy silences only itself, and its silence is a deny."""
    from toolwarden.policy import Policy

    buggy = Policy(name="buggy", tools=("t",), needs=(), permits=True, fn=body)
    gate = Gate([buggy], [])
    decision = gate.decide(tool="t", args={}, principal={})
    assert decision.allowed is False
    (denial,) = decision.denials
    assert denial.kind is DenyKind.POLICY_ERROR
    assert denial.policy == "buggy"
    assert denial.reason == expected_reason
    assert decision.trail == (("buggy", "deny"),)


def test_permits_false_returning_allow_is_policy_error() -> None:
    @policy("forbidder", tools=("t",), permits=False)
    def forbidder(f: Facts) -> Verdict:
        return Allow()  # contract violation

    decision = Gate([forbidder], []).decide(tool="t", args={}, principal={})
    assert decision.allowed is False
    (denial,) = decision.denials
    assert denial.kind is DenyKind.POLICY_ERROR
    assert denial.policy == "forbidder"
    assert denial.reason == "permits=False policy returned Allow"
    assert decision.permits == ()  # the illegal Allow never took effect


def test_undeclared_fact_read_raises_inside_body_and_denies() -> None:
    """Facts.__getitem__ raises UndeclaredFact for a key outside needs, and
    the engine converts the escape into POLICY_ERROR."""
    caught: list[UndeclaredFact] = []

    @policy("nosy", tools=("t",))
    def nosy(f: Facts) -> Verdict:
        try:
            f[WORD]
        except UndeclaredFact as exc:
            caught.append(exc)
            raise
        return Allow()

    gate = Gate([nosy], [_word_normalizer()])
    decision = gate.decide(tool="t", args={"word": "x"}, principal={})
    assert len(caught) == 1
    assert caught[0].fact == "word"
    (denial,) = decision.denials
    assert denial.kind is DenyKind.POLICY_ERROR
    assert denial.reason == "policy raised UndeclaredFact"


def test_facts_view_exposes_call_and_typed_facts() -> None:
    seen: dict[str, Any] = {}

    @policy("inspector", tools=("t",), needs=(WORD,))
    def inspector(f: Facts) -> Verdict:
        seen["tool"] = f.tool
        seen["args"] = dict(f.args)
        seen["principal"] = dict(f.principal)
        seen["word"] = f[WORD]
        return Allow()

    gate = Gate([inspector], [_word_normalizer()])
    decision = gate.decide(tool="t", args={"word": "hi"}, principal={"env": "prod"})
    assert decision.allowed is True
    assert seen == {
        "tool": "t",
        "args": {"word": "hi"},
        "principal": {"env": "prod"},
        "word": "hi",
    }


def test_multi_fact_unparseable_reason_sorts_fact_names() -> None:
    """Two broken needed facts produce ONE denial whose reason lists both,
    name-sorted, so the reason string itself is canonical."""
    alpha: FactKey[str] = FactKey("alpha")
    zulu: FactKey[str] = FactKey("zulu")

    @normalizer("broken_pair", tools=("t",), provides=(zulu, alpha))
    def broken_pair(call: ToolCall) -> Mapping[FactKey[Any], object]:
        return {
            zulu: Unavailable("zulu", "z broke"),
            alpha: Unavailable("alpha", "a broke"),
        }

    @policy("needs_both", tools=("t",), needs=(zulu, alpha))
    def needs_both(f: Facts) -> Verdict:
        return Allow()

    decision = Gate([needs_both], [broken_pair]).decide(tool="t", args={}, principal={})
    (denial,) = decision.denials
    assert denial.reason == "fact alpha unavailable: a broke; fact zulu unavailable: z broke"


# ---------------------------------------------------------------------------
# Steps 5 and 6: aggregation and canonical ordering
# ---------------------------------------------------------------------------


def _mixed_policies() -> list[Policy]:
    @policy("p_allow", tools=("t",), needs=(WORD,))
    def p_allow(f: Facts) -> Verdict:
        return Allow()

    @policy("p_deny_b", tools=("t",), needs=(WORD,))
    def p_deny_b(f: Facts) -> Verdict:
        return Deny("reason b")

    @policy("p_deny_a", tools=("t",), needs=(WORD,))
    def p_deny_a(f: Facts) -> Verdict:
        return Deny("reason a")

    @policy("p_error", tools=("t",))
    def p_error(f: Facts) -> Verdict:
        raise ValueError("bug")

    return [p_allow, p_deny_b, p_deny_a, p_error]


def test_all_denials_reported_and_canonically_sorted() -> None:
    gate = Gate(_mixed_policies(), [_word_normalizer()])
    decision = gate.decide(tool="t", args={"word": "x"}, principal={})
    assert decision.allowed is False
    # ALL denials present, sorted by (kind precedence, policy, reason):
    # POLICY_FORBADE before POLICY_ERROR, and within a kind by policy name.
    assert [(d.kind, d.policy) for d in decision.denials] == [
        (DenyKind.POLICY_FORBADE, "p_deny_a"),
        (DenyKind.POLICY_FORBADE, "p_deny_b"),
        (DenyKind.POLICY_ERROR, "p_error"),
    ]
    assert decision.outcome == decision.denials[0]
    assert decision.permits == ("p_allow",)
    assert decision.trail == (
        ("p_allow", "allow"),
        ("p_deny_a", "deny"),
        ("p_deny_b", "deny"),
        ("p_error", "deny"),
    )


def test_registration_order_cannot_influence_any_byte() -> None:
    """Every permutation of policy and normalizer registration produces a
    byte-identical record body and an equal Decision (minus decision_id)."""
    policies = _mixed_policies()
    normalizers = [_word_normalizer()]
    reference: str | None = None
    reference_decision: Decision | None = None
    for perm in itertools.permutations(policies):
        gate = Gate(list(perm), normalizers)
        decision = gate.decide(tool="t", args={"word": "x"}, principal={})
        body = decision.record()
        if reference is None:
            reference = body
            reference_decision = decision
        assert body == reference
        assert reference_decision is not None
        assert decision.denials == reference_decision.denials
        assert decision.permits == reference_decision.permits
        assert decision.trail == reference_decision.trail


# ---------------------------------------------------------------------------
# Step 7: the sink
# ---------------------------------------------------------------------------


def test_on_decision_fires_on_allow_and_deny_and_malformed() -> None:
    seen: list[tuple[ToolCall, Decision]] = []
    gate = Gate(
        [_allow_all()],
        [_word_normalizer()],
        on_decision=lambda call, decision: seen.append((call, decision)),
    )
    allowed = gate.decide(tool="t", args={"word": "x"}, principal={})
    denied = gate.decide(tool="nope", args={}, principal={})
    malformed = gate.decide(tool="", args={}, principal={})
    minted = gate.deny_malformed("t", "adapter-side JSON parse failure")
    assert [d.decision_id for _, d in seen] == [
        allowed.decision_id,
        denied.decision_id,
        malformed.decision_id,
        minted.decision_id,
    ]
    for call, decision in seen:
        assert call is decision.call


def test_raising_sink_propagates() -> None:
    """A host that cannot log is a host that should stop."""

    def sink(call: ToolCall, decision: Decision) -> None:
        raise OSError("log disk full")

    gate = Gate([_allow_all()], [_word_normalizer()], on_decision=sink)
    with pytest.raises(OSError, match="log disk full"):
        gate.decide(tool="t", args={"word": "x"}, principal={})


# ---------------------------------------------------------------------------
# Decision surface
# ---------------------------------------------------------------------------


def test_deny_malformed_shape() -> None:
    gate = Gate([_allow_all()], [_word_normalizer()])
    decision = gate.deny_malformed("t", "argument JSON would not parse")
    assert decision.allowed is False
    (denial,) = decision.denials
    assert denial.kind is DenyKind.MALFORMED_CALL
    assert denial.policy == "engine"
    assert denial.reason == "argument JSON would not parse"
    assert decision.call.args == {}
    assert decision.call.principal == {}


def test_decision_id_is_unique_per_decision() -> None:
    gate = Gate([_allow_all()], [_word_normalizer()])
    first = gate.decide(tool="t", args={"word": "x"}, principal={})
    second = gate.decide(tool="t", args={"word": "x"}, principal={})
    assert first.decision_id != second.decision_id
    assert first.record() == second.record()  # id lives outside the body


def test_not_applicable_is_a_singleton() -> None:
    assert NotApplicable() is NOT_APPLICABLE
    assert repr(NOT_APPLICABLE) == "NotApplicable"
