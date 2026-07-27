"""The batch contract: every ordinary normalizer bug lands on the deny side.

Each of the four rules from the spec is violated deliberately by a rigged
normalizer, both at the `run_normalizers` level (the value produced) and
through a full gate (the UNPARSEABLE denial it becomes). The hostile-Mapping
case exists because `dict` is a contract, not a guarantee: a subclass can
lie during iteration, and that lie must become a value too.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from toolwarden import Allow, DenyKind, Facts, Gate, ToolCall, Unavailable, Verdict, policy
from toolwarden.facts import FactKey
from toolwarden.normalize import normalizer, run_normalizers

ALPHA: FactKey[int] = FactKey("alpha")
BETA: FactKey[int] = FactKey("beta")
ROGUE: FactKey[int] = FactKey("rogue")

CALL = ToolCall(tool="t", args={}, principal={})


def test_normalizer_runs_only_for_declared_tools() -> None:
    runs: list[str] = []

    @normalizer("scoped", tools=("t",), provides=(ALPHA,))
    def scoped(call: ToolCall) -> Mapping[FactKey[Any], object]:
        runs.append(call.tool)
        return {ALPHA: 1}

    table = run_normalizers([scoped], ToolCall(tool="other", args={}, principal={}))
    assert table == {}
    assert runs == []


def test_omitted_promised_key_becomes_unavailable() -> None:
    @normalizer("forgetful", tools=("t",), provides=(ALPHA, BETA))
    def forgetful(call: ToolCall) -> Mapping[FactKey[Any], object]:
        return {ALPHA: 1}  # BETA promised, never produced

    table = run_normalizers([forgetful], CALL)
    assert table["alpha"] == 1
    beta = table["beta"]
    assert isinstance(beta, Unavailable)
    assert beta.reason == "forgetful did not produce it"


def test_undeclared_extra_key_poisons_the_whole_batch() -> None:
    """A normalizer confused about its own output cannot be trusted about
    any of it: the honestly produced ALPHA is discarded too."""

    @normalizer("overreaching", tools=("t",), provides=(ALPHA,))
    def overreaching(call: ToolCall) -> Mapping[FactKey[Any], object]:
        return {ALPHA: 1, ROGUE: 2}

    table = run_normalizers([overreaching], CALL)
    alpha = table["alpha"]
    assert isinstance(alpha, Unavailable)
    assert alpha.reason == "overreaching produced undeclared fact rogue"
    assert "rogue" not in table  # the undeclared fact never enters the table


def test_non_factkey_key_poisons_the_batch() -> None:
    @normalizer("stringly", tools=("t",), provides=(ALPHA,))
    def stringly(call: ToolCall) -> Mapping[FactKey[Any], object]:
        return {"alpha": 1}  # type: ignore[dict-item]

    table = run_normalizers([stringly], CALL)
    alpha = table["alpha"]
    assert isinstance(alpha, Unavailable)
    assert "produced undeclared fact str" in alpha.reason


def test_raising_normalizer_poisons_every_declared_key() -> None:
    @normalizer("crasher", tools=("t",), provides=(ALPHA, BETA))
    def crasher(call: ToolCall) -> Mapping[FactKey[Any], object]:
        raise KeyError("boom")

    table = run_normalizers([crasher], CALL)
    for name in ("alpha", "beta"):
        value = table[name]
        assert isinstance(value, Unavailable)
        assert value.reason == "crasher raised KeyError"


def test_non_mapping_return_poisons_the_batch() -> None:
    @normalizer("listy", tools=("t",), provides=(ALPHA,))
    def listy(call: ToolCall) -> Mapping[FactKey[Any], object]:
        return [(ALPHA, 1)]  # type: ignore[return-value]

    table = run_normalizers([listy], CALL)
    alpha = table["alpha"]
    assert isinstance(alpha, Unavailable)
    assert alpha.reason == "listy returned list, not a mapping"


def test_mapping_that_raises_during_iteration_poisons_the_batch() -> None:
    class TwoFaced(dict):  # type: ignore[type-arg]
        """Passes the isinstance check, then lies during iteration."""

        def items(self) -> Any:
            raise RuntimeError("iteration ambush")

    @normalizer("ambushed", tools=("t",), provides=(ALPHA,))
    def ambushed(call: ToolCall) -> Mapping[FactKey[Any], object]:
        return TwoFaced({ALPHA: 1})

    table = run_normalizers([ambushed], CALL)
    alpha = table["alpha"]
    assert isinstance(alpha, Unavailable)
    assert alpha.reason == "ambushed raised RuntimeError"


def test_factkey_whose_name_raises_poisons_the_batch() -> None:
    """A produced key can defer its raise past the isinstance check: a
    FactKey subclass with object identity hashing and a `name` property
    that raises survives dict construction inside the normalizer and blows
    up only when the enforcer reads `key.name`. That read must sit inside
    the enforcer's try block; before it did, this exact shape escaped
    `Gate.decide()` as a RuntimeError."""

    class EvilKey(FactKey):  # type: ignore[type-arg]
        __hash__ = object.__hash__

        @property
        def name(self) -> str:  # type: ignore[override]
            raise RuntimeError("deferred ambush")

    evil = object.__new__(EvilKey)  # skip __init__: the property has no setter

    @normalizer("keyed", tools=("t",), provides=(ALPHA,))
    def keyed(call: ToolCall) -> Mapping[FactKey[Any], object]:
        return {evil: 1}

    table = run_normalizers([keyed], CALL)
    alpha = table["alpha"]
    assert isinstance(alpha, Unavailable)
    assert alpha.reason == "keyed raised RuntimeError"


def test_factkey_whose_name_raises_never_escapes_decide() -> None:
    """The same hostile key through a full gate: decide() must return an
    UNPARSEABLE denial, never raise."""

    class EvilKey(FactKey):  # type: ignore[type-arg]
        __hash__ = object.__hash__

        @property
        def name(self) -> str:  # type: ignore[override]
            raise RuntimeError("deferred ambush")

    evil = object.__new__(EvilKey)

    @normalizer("keyed", tools=("t",), provides=(ALPHA,))
    def keyed(call: ToolCall) -> Mapping[FactKey[Any], object]:
        return {evil: 1}

    @policy("wants_alpha", tools=("t",), needs=(ALPHA,))
    def wants_alpha(f: Facts) -> Verdict:
        return Allow()

    decision = Gate([wants_alpha], [keyed]).decide(tool="t", args={}, principal={})
    assert decision.allowed is False
    (denial,) = decision.denials
    assert denial.kind is DenyKind.UNPARSEABLE
    assert denial.reason == "fact alpha unavailable: keyed raised RuntimeError"


def test_honest_unavailable_passes_through_untouched() -> None:
    """Rule 4: graceful failure is returned, not raised, and the engine
    forwards the normalizer's own words without rewriting them."""
    honest = Unavailable("alpha", "input was a claim, not a value")

    @normalizer("graceful", tools=("t",), provides=(ALPHA,))
    def graceful(call: ToolCall) -> Mapping[FactKey[Any], object]:
        return {ALPHA: honest}

    table = run_normalizers([graceful], CALL)
    assert table["alpha"] is honest  # the same object, reason verbatim


def test_gate_turns_batch_violations_into_unparseable_denials() -> None:
    """Through a full gate, each contract violation surfaces as UNPARSEABLE
    with the batch enforcer's reason, and the body never runs."""

    @normalizer("crasher", tools=("t",), provides=(ALPHA,))
    def crasher(call: ToolCall) -> Mapping[FactKey[Any], object]:
        raise ValueError("boom")

    body_ran: list[bool] = []

    @policy("wants_alpha", tools=("t",), needs=(ALPHA,))
    def wants_alpha(f: Facts) -> Verdict:
        body_ran.append(True)
        return Allow()

    decision = Gate([wants_alpha], [crasher]).decide(tool="t", args={}, principal={})
    assert decision.allowed is False
    assert body_ran == []
    (denial,) = decision.denials
    assert denial.kind is DenyKind.UNPARSEABLE
    assert denial.reason == "fact alpha unavailable: crasher raised ValueError"
    assert decision.fact_errors == {"alpha": "crasher raised ValueError"}


def test_two_normalizers_for_one_tool_merge_their_facts() -> None:
    @normalizer("gives_alpha", tools=("t",), provides=(ALPHA,))
    def gives_alpha(call: ToolCall) -> Mapping[FactKey[Any], object]:
        return {ALPHA: 1}

    @normalizer("gives_beta", tools=("t",), provides=(BETA,))
    def gives_beta(call: ToolCall) -> Mapping[FactKey[Any], object]:
        return {BETA: 2}

    table = run_normalizers([gives_alpha, gives_beta], CALL)
    assert table == {"alpha": 1, "beta": 2}
