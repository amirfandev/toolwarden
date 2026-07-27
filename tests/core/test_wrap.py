"""wrap(): the guard standing between agent and tool.

The properties under test are the boundary's whole story: the gate judges
the same named-argument view the tool executes, denied calls never run the
tool, the principal is host authority the model cannot reach, and every
failure shape at the boundary is a denial or a construction error, never a
stray exception mid-dispatch.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from example_policies import PRINCIPAL_DEV, PRINCIPAL_PROD, build_gate
from support import assert_no_sentinels
from toolwarden import (
    Allow,
    CoverageError,
    DenyKind,
    Facts,
    Gate,
    GateConfigError,
    Refusal,
    ToolDenied,
    Verdict,
    policy,
)


def _db_tools() -> dict[str, Any]:
    calls: list[dict[str, Any]] = []

    def db_exec(query: str, limit: int = 10) -> dict[str, Any]:
        record = {"query": query, "limit": limit}
        calls.append(record)
        return record

    return {"fn": db_exec, "calls": calls}


@pytest.fixture()
def gate() -> Gate:
    return build_gate(strict=False)  # wrapping tool subsets is the point here


def test_allowed_call_executes_with_the_same_objects(gate: Gate) -> None:
    seen: list[Any] = []

    def db_exec(query: str, rows: list[int] | None = None) -> str:
        seen.append((query, rows))
        return "ok"

    guarded = gate.wrap({"db_exec": db_exec}, principal=PRINCIPAL_PROD)
    rows = [1, 2, 3]
    result = guarded["db_exec"]("SELECT id FROM orders", rows)
    assert result == "ok"
    query, got_rows = seen[0]
    assert got_rows is rows  # the very object the caller passed, not a copy


def test_positional_and_keyword_styles_judge_identically(gate: Gate) -> None:
    """The signature bind normalizes both call styles to one named view, so
    policy sees the same call either way."""
    records: list[str] = []
    sink_gate = build_gate(strict=False, on_decision=lambda c, d: records.append(d.record()))

    def db_exec(query: str, limit: int = 10) -> str:
        return "ok"

    guarded = sink_gate.wrap({"db_exec": db_exec}, principal=PRINCIPAL_PROD)
    guarded["db_exec"]("SELECT 1", 5)
    guarded["db_exec"](query="SELECT 1", limit=5)
    guarded["db_exec"]("SELECT 1", limit=5)
    assert records[0] == records[1] == records[2]


def test_defaults_are_applied_before_judging(gate: Gate) -> None:
    seen_args: list[dict[str, Any]] = []
    sink_gate = build_gate(
        strict=False, on_decision=lambda c, d: seen_args.append(dict(c.args))
    )

    def db_exec(query: str, limit: int = 10) -> str:
        return "ok"

    guarded = sink_gate.wrap({"db_exec": db_exec}, principal=PRINCIPAL_PROD)
    guarded["db_exec"]("SELECT 1")
    assert seen_args[0] == {"query": "SELECT 1", "limit": 10}


def test_var_keyword_arguments_are_flattened_into_the_judged_view(gate: Gate) -> None:
    """A tool signature with **kwargs must not hide a governed argument
    from policy. `sig.bind` nests extra keywords in a dict under the
    parameter name, where a normalizer looking for `phi_fields` cannot see
    them, while the tool still receives and acts on them. The guard
    flattens that nest back into the top-level view, so PHI mailed to an
    outsider through a **kwargs tool is denied, not silently untagged."""
    sent: list[dict[str, Any]] = []

    def send_email(to: list[str], **kwargs: Any) -> str:
        sent.append(kwargs)
        return "sent"

    guarded = gate.wrap({"send_email": send_email}, principal=PRINCIPAL_PROD)
    with pytest.raises(ToolDenied) as excinfo:
        guarded["send_email"](
            to=["records@gmail.com"], phi_fields=["dob"], body="chart attached"
        )
    assert sent == []
    kinds = {d.kind for d in excinfo.value.refusal.denials}
    assert DenyKind.POLICY_FORBADE in kinds
    deniers = {d.policy for d in excinfo.value.refusal.denials}
    assert "phi_minimum_necessary" in deniers


def test_var_keyword_flattening_judges_same_view_as_explicit_signature(gate: Gate) -> None:
    """The same logical call through an explicit signature and through
    **kwargs must produce byte-identical record bodies: the caller's named
    view is the judged view either way."""
    records: list[str] = []
    sink_gate = build_gate(strict=False, on_decision=lambda c, d: records.append(d.record()))

    def explicit(query: str, limit: int = 10) -> str:
        return "ok"

    def starry(**kwargs: Any) -> str:
        return "ok"

    guarded = sink_gate.wrap({"db_exec": explicit}, principal=PRINCIPAL_PROD)
    guarded["db_exec"](query="SELECT 1", limit=10)
    guarded = sink_gate.wrap({"db_exec": starry}, principal=PRINCIPAL_PROD)
    guarded["db_exec"](query="SELECT 1", limit=10)
    assert records[0] == records[1]


def test_denied_call_raises_tool_denied_and_never_runs_the_tool(gate: Gate) -> None:
    parts = _db_tools()
    guarded = gate.wrap({"db_exec": parts["fn"]}, principal=PRINCIPAL_PROD)
    with pytest.raises(ToolDenied) as excinfo:
        guarded["db_exec"]("DELETE FROM orders")
    assert parts["calls"] == []  # blocked BEFORE execution
    refusal = excinfo.value.refusal
    assert refusal.tool == "db_exec"
    assert refusal.denials[0].kind is DenyKind.POLICY_FORBADE
    assert "provable read" in str(excinfo.value)


def test_on_deny_result_returns_the_refusal_object(gate: Gate) -> None:
    parts = _db_tools()
    guarded = gate.wrap(
        {"db_exec": parts["fn"]}, principal=PRINCIPAL_PROD, on_deny="result"
    )
    outcome = guarded["db_exec"]("DELETE FROM orders")
    assert isinstance(outcome, Refusal)  # callers must isinstance-check
    assert parts["calls"] == []
    payload = outcome.to_tool_result()
    assert '"denied":true' in payload


def test_raise_and_result_modes_carry_identical_payloads(gate: Gate) -> None:
    import json

    parts = _db_tools()
    raiser = gate.wrap({"db_exec": parts["fn"]}, principal=PRINCIPAL_PROD)
    resulter = gate.wrap(
        {"db_exec": parts["fn"]}, principal=PRINCIPAL_PROD, on_deny="result"
    )
    with pytest.raises(ToolDenied) as excinfo:
        raiser["db_exec"]("DELETE FROM orders")
    returned = resulter["db_exec"]("DELETE FROM orders")
    a = json.loads(excinfo.value.refusal.to_tool_result())
    b = json.loads(returned.to_tool_result())
    a.pop("decision_id")
    b.pop("decision_id")
    assert a == b


def test_invalid_on_deny_rejected() -> None:
    gate = build_gate(strict=False)
    with pytest.raises(GateConfigError, match="on_deny must be 'raise' or 'result'"):
        gate.wrap({"db_exec": lambda query: None}, principal={}, on_deny="refuse")  # type: ignore[arg-type]


def test_unbindable_call_is_malformed_denial_not_typeerror(gate: Gate) -> None:
    parts = _db_tools()
    guarded = gate.wrap({"db_exec": parts["fn"]}, principal=PRINCIPAL_PROD)
    with pytest.raises(ToolDenied) as excinfo:
        guarded["db_exec"](nonexistent_kwarg="SELECT 1")
    assert parts["calls"] == []
    denial = excinfo.value.refusal.denials[0]
    assert denial.kind is DenyKind.MALFORMED_CALL
    assert "do not bind to db_exec()" in denial.reason
    # The bind error names parameters, never argument values.
    assert "SELECT 1" not in denial.reason


def test_unbindable_reason_never_carries_secret_values(gate: Gate) -> None:
    from support import SECRET_QUERY

    guarded = gate.wrap({"db_exec": _db_tools()["fn"]}, principal=PRINCIPAL_PROD)
    with pytest.raises(ToolDenied) as excinfo:
        guarded["db_exec"](SECRET_QUERY, SECRET_QUERY, SECRET_QUERY)
    assert_no_sentinels(str(excinfo.value), where="unbindable-call refusal")
    assert_no_sentinels(
        excinfo.value.refusal.to_tool_result(), where="unbindable-call payload"
    )


# ---------------------------------------------------------------------------
# Principal: host authority, out of the model's reach
# ---------------------------------------------------------------------------


def test_principal_comes_from_host_not_from_model_args() -> None:
    """A model-supplied env value in the args cannot displace the host's
    production principal: the deny stands."""
    gate = build_gate(strict=False)

    def db_exec(query: str, env: str = "development") -> str:
        return "ok"

    guarded = gate.wrap({"db_exec": db_exec}, principal=PRINCIPAL_PROD)
    with pytest.raises(ToolDenied):
        guarded["db_exec"]("DELETE FROM orders", env="development")


def test_judged_principal_is_exactly_the_host_mapping() -> None:
    seen: list[dict[str, Any]] = []

    @policy("principal_probe", tools=("probe",))
    def principal_probe(f: Facts) -> Verdict:
        seen.append(dict(f.principal))
        return Allow()

    gate = Gate([principal_probe], [])

    def probe(env: str = "x", principal: str = "model-supplied") -> str:
        return "ok"

    guarded = gate.wrap({"probe": probe}, principal={"agent": "bot"})
    guarded["probe"](env="evil", principal="model-supplied")
    assert seen == [{"agent": "bot"}]  # arg names cannot smuggle into principal


def test_mapping_principal_is_frozen_by_copy() -> None:
    seen: list[dict[str, Any]] = []

    @policy("probe", tools=("probe",))
    def probe_policy(f: Facts) -> Verdict:
        seen.append(dict(f.principal))
        return Allow()

    gate = Gate([probe_policy], [])
    mutable = {"env": "production"}
    guarded = gate.wrap({"probe": lambda: "ok"}, principal=mutable)
    mutable["env"] = "development"  # too late: wrap copied it
    guarded["probe"]()
    assert seen == [{"env": "production"}]


def test_callable_principal_evaluated_per_call() -> None:
    seen: list[dict[str, Any]] = []

    @policy("probe", tools=("probe",))
    def probe_policy(f: Facts) -> Verdict:
        seen.append(dict(f.principal))
        return Allow()

    gate = Gate([probe_policy], [])
    counter = {"n": 0}

    def principal() -> dict[str, Any]:
        counter["n"] += 1
        return {"call_number": counter["n"]}

    guarded = gate.wrap({"probe": lambda: "ok"}, principal=principal)
    guarded["probe"]()
    guarded["probe"]()
    assert seen == [{"call_number": 1}, {"call_number": 2}]


def test_callable_principal_returning_garbage_is_malformed_denial() -> None:
    @policy("probe", tools=("probe",))
    def probe_policy(f: Facts) -> Verdict:
        return Allow()

    gate = Gate([probe_policy], [])
    guarded = gate.wrap({"probe": lambda: "ok"}, principal=lambda: "not-a-mapping")  # type: ignore[arg-type,return-value]
    with pytest.raises(ToolDenied) as excinfo:
        guarded["probe"]()
    assert excinfo.value.refusal.denials[0].kind is DenyKind.MALFORMED_CALL


# ---------------------------------------------------------------------------
# Naming, coverage, and the async guard
# ---------------------------------------------------------------------------


def test_sequence_names_come_from_dunder_name() -> None:
    gate = build_gate(strict=False)

    def db_exec(query: str) -> str:
        return "ok"

    guarded = gate.wrap([db_exec], principal=PRINCIPAL_PROD)
    assert set(guarded) == {"db_exec"}


def test_lambda_in_sequence_rejected() -> None:
    gate = build_gate(strict=False)
    with pytest.raises(GateConfigError, match="no usable __name__"):
        gate.wrap([lambda query: "ok"], principal={})


def test_duplicate_sequence_names_rejected() -> None:
    gate = build_gate(strict=False)

    def db_exec(query: str) -> str:
        return "a"

    first = db_exec

    def db_exec(query: str) -> str:  # type: ignore[no-redef]  # noqa: F811
        return "b"

    with pytest.raises(GateConfigError, match="two callables named 'db_exec'"):
        gate.wrap([first, db_exec], principal={})


def test_strict_gate_refuses_to_wrap_a_subset() -> None:
    """Spec-literal consequence: against the wrapped universe, policies for
    unwrapped tools are phantom findings, and a strict gate refuses."""
    gate = build_gate()  # strict
    with pytest.raises(CoverageError):
        gate.wrap({"db_exec": lambda query: "ok"}, principal=PRINCIPAL_PROD)


def test_non_strict_gate_wraps_a_subset_with_stderr_report(
    capsys: pytest.CaptureFixture[str],
) -> None:
    gate = build_gate(strict=False)
    guarded = gate.wrap({"db_exec": lambda query: "ok"}, principal=PRINCIPAL_PROD)
    assert "!!" in capsys.readouterr().err
    assert set(guarded) == {"db_exec"}


def test_async_tool_gets_an_async_guard() -> None:
    gate = build_gate(strict=False)
    ran: list[str] = []

    async def db_exec(query: str) -> str:
        ran.append(query)
        return "ok"

    guarded = gate.wrap({"db_exec": db_exec}, principal=PRINCIPAL_PROD)

    async def scenario() -> None:
        result = await guarded["db_exec"]("SELECT 1")
        assert result == "ok"
        with pytest.raises(ToolDenied):
            await guarded["db_exec"]("DELETE FROM orders")

    asyncio.run(scenario())
    assert ran == ["SELECT 1"]  # the denied call never executed


def test_audit_sink_fires_before_the_guard_raises() -> None:
    order: list[str] = []
    gate = build_gate(
        strict=False, on_decision=lambda c, d: order.append(f"sink:{d.allowed}")
    )
    guarded = gate.wrap({"db_exec": lambda query: "ok"}, principal=PRINCIPAL_PROD)
    try:
        guarded["db_exec"]("DELETE FROM orders")
    except ToolDenied:
        order.append("raised")
    assert order == ["sink:False", "raised"]


def test_dev_principal_flips_the_same_call_to_no_permit() -> None:
    """Same args, different host principal, different decision: the
    principal is load-bearing and host-owned."""
    gate = build_gate(strict=False)
    guarded_dev = gate.wrap(
        {"db_exec": lambda query: "ok"}, principal=PRINCIPAL_DEV
    )
    with pytest.raises(ToolDenied) as excinfo:
        guarded_dev["db_exec"]("DELETE FROM orders")
    assert excinfo.value.refusal.denials[0].kind is DenyKind.NO_PERMIT
