"""Construction-time checks: everything wrong about the wiring is loud at
startup, before the first call is ever judged.

The dividing line under test: configuration defects raise here, on the
operator's side of the boundary, while everything at decide() time is a
denial. A gate that constructs is a gate whose runtime failure modes are all
denials, and these tests are the first half of that argument.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from toolwarden import (
    Allow,
    CoverageError,
    Facts,
    Gate,
    GateConfigError,
    ToolCall,
    UncoveredFact,
    Verdict,
    normalizer,
    policy,
)
from toolwarden.facts import FactKey
from toolwarden.normalize import Normalizer
from toolwarden.policy import Policy

ALPHA: FactKey[int] = FactKey("alpha")


def _provider(name: str = "alpha_provider", tools: tuple[str, ...] = ("t",)) -> Normalizer:
    @normalizer(name, tools=tools, provides=(ALPHA,))
    def provide(call: ToolCall) -> Mapping[FactKey[Any], object]:
        return {ALPHA: 1}

    return provide


def _permitter(name: str = "permitter", tools: tuple[str, ...] = ("t",)) -> Policy:
    @policy(name, tools=tools)
    def permit(f: Facts) -> Verdict:
        return Allow()

    return permit


# ---------------------------------------------------------------------------
# Names and identity
# ---------------------------------------------------------------------------


def test_duplicate_policy_names_rejected() -> None:
    with pytest.raises(GateConfigError, match="duplicate policy names: twin"):
        Gate([_permitter("twin"), _permitter("twin")], [])


def test_duplicate_normalizer_names_rejected() -> None:
    with pytest.raises(GateConfigError, match="duplicate normalizer names: twin"):
        Gate([], [_provider("twin"), _provider("twin", tools=("u",))])


def test_colliding_fact_keys_rejected() -> None:
    """Two DISTINCT FactKey objects with one name would silently alias two
    facts (the phantom types are invisible at runtime), so the gate refuses
    to exist. The check is identity, not equality: reusing the one shared
    key object is the supported pattern."""
    impostor: FactKey[str] = FactKey("alpha")  # equal by name, distinct object

    @policy("needs_impostor", tools=("t",), needs=(impostor,))
    def needs_impostor(f: Facts) -> Verdict:
        return Allow()

    with pytest.raises(GateConfigError, match="share the name 'alpha'"):
        Gate([needs_impostor], [_provider()])


def test_shared_fact_key_object_across_policies_is_fine() -> None:
    @policy("first", tools=("t",), needs=(ALPHA,))
    def first(f: Facts) -> Verdict:
        return Allow()

    @policy("second", tools=("t",), needs=(ALPHA,))
    def second(f: Facts) -> Verdict:
        return Allow()

    Gate([first, second], [_provider()])  # must not raise


def test_policy_name_engine_is_reserved() -> None:
    with pytest.raises(GateConfigError, match='"engine" is reserved'):
        _permitter("engine")


# ---------------------------------------------------------------------------
# Needs coverage: every (policy, fact, tool) triple has a provider
# ---------------------------------------------------------------------------


def _needy(tools: tuple[str, ...]) -> Policy:
    @policy("needy", tools=tools, needs=(ALPHA,))
    def needy(f: Facts) -> Verdict:
        return Allow()

    return needy


def test_uncovered_fact_no_normalizer_at_all() -> None:
    with pytest.raises(UncoveredFact) as excinfo:
        Gate([_needy(("t",))], [])
    assert excinfo.value.policy == "needy"
    assert excinfo.value.fact == "alpha"
    assert excinfo.value.tool == "t"


def test_uncovered_fact_provider_covers_other_tool_only() -> None:
    """The provider exists but not for this tool; per-tool coverage is the
    contract, because normalizers route on tool exactly as policies do."""
    with pytest.raises(UncoveredFact) as excinfo:
        Gate([_needy(("t", "u"))], [_provider(tools=("t",))])
    assert (excinfo.value.policy, excinfo.value.fact, excinfo.value.tool) == (
        "needy",
        "alpha",
        "u",
    )


def test_uncovered_fact_provider_covers_other_fact_only() -> None:
    beta: FactKey[int] = FactKey("beta")

    @normalizer("beta_provider", tools=("t",), provides=(beta,))
    def provide_beta(call: ToolCall) -> Mapping[FactKey[Any], object]:
        return {beta: 2}

    with pytest.raises(UncoveredFact):
        Gate([_needy(("t",))], [provide_beta])


def test_duplicate_providers_for_same_fact_and_tool_rejected() -> None:
    with pytest.raises(GateConfigError, match="both provide fact 'alpha' for tool 't'"):
        Gate([], [_provider("one"), _provider("two")])


def test_same_fact_different_tools_is_fine() -> None:
    Gate([], [_provider("one", tools=("t",)), _provider("two", tools=("u",))])


# ---------------------------------------------------------------------------
# Coverage against a declared tool universe
# ---------------------------------------------------------------------------


def test_strict_gate_refuses_ungoverned_tool_in_universe() -> None:
    with pytest.raises(CoverageError, match="UNGOVERNED"):
        Gate([_permitter(tools=("t",))], [], tools=("t", "orphan"))


def test_strict_gate_refuses_forbid_only_tool() -> None:
    @policy("forbidder", tools=("t",), permits=False)
    def forbidder(f: Facts) -> Verdict:
        return Allow()  # body irrelevant; capability is declared

    with pytest.raises(CoverageError, match="FORBID-ONLY"):
        Gate([forbidder], [], tools=("t",))


def test_strict_gate_refuses_phantom_policy_target() -> None:
    with pytest.raises(CoverageError, match="unknown tool"):
        Gate([_permitter(tools=("t", "send_faks"))], [], tools=("t",))


def test_coverage_error_names_every_finding_at_once() -> None:
    """An operator fixing coverage sees the whole gap, not one finding per
    restart."""

    @policy("forbid_u", tools=("u",), permits=False)
    def forbid_u(f: Facts) -> Verdict:
        return Allow()

    with pytest.raises(CoverageError) as excinfo:
        Gate(
            [_permitter(tools=("t", "send_faks")), forbid_u],
            [],
            tools=("t", "u", "orphan"),
        )
    text = str(excinfo.value)
    assert "orphan" in text and "UNGOVERNED" in text
    assert "FORBID-ONLY" in text
    assert "send_faks" in text


def test_non_strict_gate_prints_findings_and_proceeds(capsys: pytest.CaptureFixture[str]) -> None:
    gate = Gate([_permitter(tools=("t",))], [], tools=("t", "orphan"), strict=False)
    err = capsys.readouterr().err
    assert "!!" in err and "orphan" in err
    decision = gate.decide(tool="orphan", args={}, principal={})
    assert decision.allowed is False  # runtime default deny still stands


def test_clean_universe_constructs_silently(capsys: pytest.CaptureFixture[str]) -> None:
    Gate([_permitter(tools=("t",))], [], tools=("t",))
    assert capsys.readouterr().err == ""


# ---------------------------------------------------------------------------
# Decorator and argument validation
# ---------------------------------------------------------------------------


def test_bare_string_tools_rejected_by_policy_decorator() -> None:
    """tuple('db_exec') is seven one-letter tool names; the decorator
    refuses before that silent mangling can happen."""
    with pytest.raises(GateConfigError, match="not a bare string"):
        policy("oops", tools="db_exec")


def test_bare_string_tools_rejected_by_normalizer_decorator() -> None:
    with pytest.raises(GateConfigError, match="not a bare string"):
        normalizer("oops", tools="db_exec", provides=(ALPHA,))


def test_scalar_needs_and_provides_rejected() -> None:
    with pytest.raises(GateConfigError, match="needs must be a sequence"):
        policy("oops", tools=("t",), needs=ALPHA)  # type: ignore[arg-type]
    with pytest.raises(GateConfigError, match="provides must be a sequence"):
        normalizer("oops", tools=("t",), provides=ALPHA)  # type: ignore[arg-type]


def test_empty_tools_and_empty_provides_rejected() -> None:
    with pytest.raises(GateConfigError, match="declares no tools"):
        _permitter(tools=())
    with pytest.raises(GateConfigError, match="provides no facts"):
        normalizer("idle", tools=("t",), provides=())(lambda call: {})


def test_undecorated_functions_rejected_with_a_hint() -> None:
    def naked(f: Facts) -> Verdict:
        return Allow()

    with pytest.raises(GateConfigError, match="was the @policy decorator applied"):
        Gate([naked], [])  # type: ignore[list-item]
    with pytest.raises(GateConfigError, match="was the @normalizer decorator applied"):
        Gate([], [naked])  # type: ignore[list-item]


def test_non_callable_on_decision_rejected() -> None:
    with pytest.raises(GateConfigError, match="on_decision must be callable"):
        Gate([], [], on_decision="not callable")  # type: ignore[arg-type]
