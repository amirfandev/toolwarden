"""OpenAI Agents SDK adapter, offline: stub SDK, real gate, real decisions.

What must hold: deny travels via reject_content (the tool body is skipped by
the SDK on that fork), the message is the canonical refusal payload,
malformed argument JSON and a missing tool name fail closed as
MALFORMED_CALL, the principal comes only from the host's run context, and
`assert_all_guarded` turns a forgotten attachment into a boot failure.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from typing import Any

import pytest
from adapter_stubs import (
    StubAgent,
    StubFunctionTool,
    StubGuardrailData,
    StubToolContext,
    make_agents_module,
    make_old_agents_module,
)

from example_policies import PRINCIPAL_PROD, build_gate
from support import SECRET_QUERY, assert_no_sentinels
from toolwarden import Decision, GateConfigError, ToolCall


@pytest.fixture()
def stub_sdk(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setitem(sys.modules, "agents", make_agents_module())
    yield


@pytest.fixture()
def sink() -> list[Decision]:
    return []


@pytest.fixture()
def guard(stub_sdk: None, sink: list[Decision]) -> Any:
    from toolwarden.adapters.openai_agents import toolwarden_guardrail

    gate = build_gate(on_decision=lambda call, decision: sink.append(decision))
    return toolwarden_guardrail(
        gate, principal_from_context=lambda ctx: PRINCIPAL_PROD
    )


def _data(tool_name: Any, raw_arguments: Any, host_ctx: Any = None) -> StubGuardrailData:
    return StubGuardrailData(
        context=StubToolContext(
            tool_name=tool_name, tool_arguments=raw_arguments, context=host_ctx
        )
    )


def test_guardrail_allows_a_clean_call(guard: Any, sink: list[Decision]) -> None:
    output = guard.guardrail_function(_data("db_exec", '{"query": "SELECT 1"}'))
    assert output.verdict == "allow"
    assert sink[-1].allowed is True
    assert output.output_info == sink[-1].record()


def test_guardrail_rejects_before_execution_with_the_refusal_payload(
    guard: Any, sink: list[Decision]
) -> None:
    output = guard.guardrail_function(
        _data("db_exec", json.dumps({"query": f"DELETE FROM t -- {SECRET_QUERY}"}))
    )
    assert output.verdict == "reject_content"
    payload = json.loads(output.message)
    assert payload["denied"] is True
    assert payload["tool"] == "db_exec"
    assert payload["denials"][0]["policy"] == "prod_db_read_only"
    assert payload["decision_id"] == sink[-1].decision_id
    assert_no_sentinels(output.message, where="guardrail reject message")
    assert_no_sentinels(output.output_info, where="guardrail output_info record")


def test_unparseable_argument_json_is_malformed_denial(
    guard: Any, sink: list[Decision]
) -> None:
    output = guard.guardrail_function(_data("db_exec", f'{{"query": {SECRET_QUERY}'))
    assert output.verdict == "reject_content"
    payload = json.loads(output.message)
    assert payload["denials"][0]["kind"] == "malformed_call"
    assert payload["denials"][0]["reason"] == "tool argument JSON would not parse"
    # The broken fragment may hold secrets; it must never be echoed.
    assert_no_sentinels(output.message, where="malformed-JSON reject message")
    assert sink[-1].allowed is False


def test_missing_tool_name_fails_closed(guard: Any) -> None:
    output = guard.guardrail_function(_data(None, "{}"))
    assert output.verdict == "reject_content"
    payload = json.loads(output.message)
    assert payload["denials"][0]["kind"] == "malformed_call"
    assert payload["tool"] == "<unknown>"


def test_empty_arguments_string_is_a_well_formed_empty_call(
    guard: Any, sink: list[Decision]
) -> None:
    output = guard.guardrail_function(_data("db_exec", ""))
    # Empty args means no query: UNPARSEABLE deny, not a JSON parse failure.
    payload = json.loads(output.message)
    assert payload["denials"][0]["kind"] == "unparseable"
    assert sink[-1].call.args == {}


def test_non_object_json_falls_through_to_boundary_validation(guard: Any) -> None:
    output = guard.guardrail_function(_data("db_exec", '"just a string"'))
    payload = json.loads(output.message)
    assert payload["denials"][0]["kind"] == "malformed_call"
    assert "args is not a mapping" in payload["denials"][0]["reason"]


def test_principal_extractor_receives_the_host_context(stub_sdk: None) -> None:
    from toolwarden.adapters.openai_agents import toolwarden_guardrail

    seen: list[Any] = []

    def extract(ctx: Any) -> dict[str, Any]:
        seen.append(ctx)
        return PRINCIPAL_PROD

    gate = build_gate()
    guard = toolwarden_guardrail(gate, principal_from_context=extract)
    host_ctx = object()
    guard.guardrail_function(_data("db_exec", '{"query": "SELECT 1"}', host_ctx))
    assert seen == [host_ctx]


def test_model_args_cannot_reach_the_principal(stub_sdk: None, sink: list[Decision]) -> None:
    """Args claiming a development env do not soften a production principal."""
    from toolwarden.adapters.openai_agents import toolwarden_guardrail

    gate = build_gate(on_decision=lambda call, decision: sink.append(decision))
    guard = toolwarden_guardrail(gate, principal_from_context=lambda ctx: PRINCIPAL_PROD)
    output = guard.guardrail_function(
        _data("db_exec", '{"query": "DELETE FROM t", "env": "development"}')
    )
    assert output.verdict == "reject_content"
    assert sink[-1].call.principal == PRINCIPAL_PROD


def test_omitted_extractor_defaults_to_empty_principal(
    stub_sdk: None, sink: list[Decision]
) -> None:
    from toolwarden.adapters.openai_agents import toolwarden_guardrail

    gate = build_gate(on_decision=lambda call, decision: sink.append(decision))
    guard = toolwarden_guardrail(gate)
    guard.guardrail_function(_data("db_exec", '{"query": "SELECT 1"}'))
    assert sink[-1].call.principal == {}


def test_audit_sink_fires_once_per_judged_call(guard: Any, sink: list[Decision]) -> None:
    guard.guardrail_function(_data("db_exec", '{"query": "SELECT 1"}'))
    guard.guardrail_function(_data("db_exec", "{broken"))
    guard.guardrail_function(_data(None, "{}"))
    assert len(sink) == 3


def test_assert_all_guarded_names_every_unguarded_function_tool(
    stub_sdk: None, guard: Any
) -> None:
    from toolwarden.adapters.openai_agents import assert_all_guarded

    hosted_tool = object()  # not a FunctionTool: skipped, per the SDK reality
    guarded_tool = StubFunctionTool(name="db_exec", tool_input_guardrails=[guard])
    naked_a = StubFunctionTool(name="send_email")
    naked_b = StubFunctionTool(name="issue_refund")
    agent = StubAgent(tools=[hosted_tool, guarded_tool, naked_a, naked_b])
    with pytest.raises(GateConfigError) as excinfo:
        assert_all_guarded(agent, guard)
    text = str(excinfo.value)
    assert "issue_refund" in text and "send_email" in text
    assert "db_exec" not in text


def test_assert_all_guarded_checks_identity_not_equality(
    stub_sdk: None, guard: Any
) -> None:
    from toolwarden.adapters.openai_agents import assert_all_guarded, toolwarden_guardrail

    other_guard = toolwarden_guardrail(build_gate())
    tool = StubFunctionTool(name="db_exec", tool_input_guardrails=[other_guard])
    with pytest.raises(GateConfigError):
        assert_all_guarded(StubAgent(tools=[tool]), guard)
    assert_all_guarded(StubAgent(tools=[tool]), other_guard)  # the attached object passes


def test_sdk_predating_guardrails_gets_the_upgrade_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "agents", make_old_agents_module())
    from toolwarden.adapters.openai_agents import toolwarden_guardrail

    with pytest.raises(ImportError, match="Upgrade"):
        toolwarden_guardrail(build_gate())


def test_refusal_payload_parity_with_wrap(guard: Any) -> None:
    """One denied call must read identically from the guardrail and from a
    raised ToolDenied, decision_id aside."""
    from toolwarden import ToolDenied

    output = guard.guardrail_function(_data("db_exec", '{"query": "DELETE FROM t"}'))
    via_guardrail = json.loads(output.message)

    gate = build_gate(strict=False)
    guarded = gate.wrap({"db_exec": lambda query: "ok"}, principal=PRINCIPAL_PROD)
    with pytest.raises(ToolDenied) as excinfo:
        guarded["db_exec"]("DELETE FROM t")
    via_wrap = json.loads(excinfo.value.refusal.to_tool_result())

    via_guardrail.pop("decision_id")
    via_wrap.pop("decision_id")
    assert via_guardrail == via_wrap


def test_decide_raw_call_is_the_judged_call(guard: Any, sink: list[Decision]) -> None:
    guard.guardrail_function(_data("db_exec", '{"query": "SELECT 1", "limit": 5}'))
    assert sink[-1].call == ToolCall(
        tool="db_exec",
        args={"query": "SELECT 1", "limit": 5},
        principal=PRINCIPAL_PROD,
    )
