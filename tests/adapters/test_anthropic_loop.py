"""Anthropic tool-use loop adapter: the dispatcher itself, stdlib only.

This adapter needs no stub SDK because it imports none; blocks are read
duck-typed. Both the plain-dict form and an attribute-style object are
exercised, because SDK message objects arrive as the latter and the two
must behave identically.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import pytest

from example_policies import PRINCIPAL_PROD, build_gate
from support import SECRET_BODY, SECRET_QUERY, assert_no_sentinels
from toolwarden import Decision
from toolwarden.adapters.anthropic_loop import run_tool_uses


@dataclass
class Block:
    """Attribute-style tool_use block, standing in for an SDK object."""

    type: str
    id: str
    name: Any
    input: Any


@dataclass
class Message:
    content: list[Any] = field(default_factory=list)


def _tools() -> tuple[dict[str, Any], list[tuple[str, Any]]]:
    executed: list[tuple[str, Any]] = []

    def db_exec(query: str) -> dict[str, Any]:
        executed.append(("db_exec", query))
        return {"rows": 3}

    def send_email(to: list[str], body: str = "", **extra: Any) -> str:
        executed.append(("send_email", to))
        return "sent"

    return {"db_exec": db_exec, "send_email": send_email}, executed


def test_allowed_block_executes_and_returns_content() -> None:
    tools, executed = _tools()
    message = Message(
        content=[
            {"type": "text", "text": "let me check"},
            Block(type="tool_use", id="tu_1", name="db_exec", input={"query": "SELECT 1"}),
        ]
    )
    results = run_tool_uses(build_gate(), tools, message, principal=PRINCIPAL_PROD)
    assert results == [
        {"type": "tool_result", "tool_use_id": "tu_1", "content": '{"rows": 3}'}
    ]
    assert executed == [("db_exec", "SELECT 1")]


def test_denied_block_is_error_result_and_tool_never_runs() -> None:
    tools, executed = _tools()
    message = {
        "content": [
            {
                "type": "tool_use",
                "id": "tu_2",
                "name": "db_exec",
                "input": {"query": f"DELETE FROM t -- {SECRET_QUERY}"},
            }
        ]
    }
    results = run_tool_uses(build_gate(), tools, message, principal=PRINCIPAL_PROD)
    (result,) = results
    assert result["is_error"] is True
    assert result["tool_use_id"] == "tu_2"
    payload = json.loads(result["content"])
    assert payload["denied"] is True
    assert payload["denials"][0]["policy"] == "prod_db_read_only"
    assert executed == []
    assert_no_sentinels(result["content"], where="denied tool_result")


def test_unknown_tool_takes_the_ungoverned_deny_path() -> None:
    tools, executed = _tools()
    message = Message(
        content=[
            Block(type="tool_use", id="tu_3", name="mystery_tool", input={}),
        ]
    )
    results = run_tool_uses(build_gate(), tools, message, principal=PRINCIPAL_PROD)
    (result,) = results
    assert result["is_error"] is True
    payload = json.loads(result["content"])
    assert payload["denials"][0]["kind"] == "ungoverned"
    assert executed == []


def test_allowed_but_unimplemented_tool_is_a_config_error_not_a_refusal() -> None:
    """A policy permitted a tool the host never provided: that is a host
    bug, and dressing it as a policy denial would misdirect the operator."""
    tools, _ = _tools()
    del tools["db_exec"]
    message = Message(
        content=[Block(type="tool_use", id="tu_4", name="db_exec", input={"query": "SELECT 1"})]
    )
    results = run_tool_uses(build_gate(), tools, message, principal=PRINCIPAL_PROD)
    (result,) = results
    assert result["is_error"] is True
    assert "configuration error" in result["content"]
    assert "denied" not in result["content"]


def test_tool_exception_is_an_errored_result_distinct_from_denial() -> None:
    def db_exec(query: str) -> str:
        raise RuntimeError("connection lost")

    message = Message(
        content=[Block(type="tool_use", id="tu_5", name="db_exec", input={"query": "SELECT 1"})]
    )
    results = run_tool_uses(
        build_gate(), {"db_exec": db_exec}, message, principal=PRINCIPAL_PROD
    )
    (result,) = results
    assert result["is_error"] is True
    assert "tool 'db_exec' raised RuntimeError" in result["content"]


def test_coroutine_returning_tool_is_reported_as_config_bug() -> None:
    async def db_exec(query: str) -> str:
        return "never awaited"

    message = Message(
        content=[Block(type="tool_use", id="tu_6", name="db_exec", input={"query": "SELECT 1"})]
    )
    results = run_tool_uses(
        build_gate(), {"db_exec": db_exec}, message, principal=PRINCIPAL_PROD
    )
    (result,) = results
    assert result["is_error"] is True
    assert "returned a coroutine" in result["content"]
    assert "synchronous" in result["content"]


def test_malformed_block_input_denies_instead_of_crashing() -> None:
    tools, executed = _tools()
    message = Message(
        content=[Block(type="tool_use", id="tu_7", name="db_exec", input="not a mapping")]
    )
    (result,) = run_tool_uses(build_gate(), tools, message, principal=PRINCIPAL_PROD)
    assert result["is_error"] is True
    payload = json.loads(result["content"])
    assert payload["denials"][0]["kind"] == "malformed_call"
    assert executed == []


def test_block_order_is_preserved_and_non_tool_blocks_skipped() -> None:
    tools, _ = _tools()
    message = Message(
        content=[
            {"type": "text", "text": "first"},
            Block(type="tool_use", id="a", name="db_exec", input={"query": "SELECT 1"}),
            {"type": "thinking", "thinking": "..."},
            {
                "type": "tool_use",
                "id": "b",
                "name": "send_email",
                "input": {"to": ["x@ourcompany.com"], "body": SECRET_BODY},
            },
        ]
    )
    results = run_tool_uses(build_gate(), tools, message, principal=PRINCIPAL_PROD)
    assert [r["tool_use_id"] for r in results] == ["a", "b"]
    assert all("is_error" not in r for r in results)


def test_the_judged_mapping_is_the_dispatched_mapping() -> None:
    """block.input reaches the tool as the same object the gate judged:
    nothing runs between decide and dispatch that could swap it."""
    seen: list[Any] = []
    judged: list[Any] = []

    def db_exec(query: str) -> str:
        seen.append(query)
        return "ok"

    args_obj = {"query": "SELECT 1"}
    gate = build_gate(on_decision=lambda call, decision: judged.append(call.args))
    message = Message(content=[Block(type="tool_use", id="x", name="db_exec", input=args_obj)])
    run_tool_uses(gate, {"db_exec": db_exec}, message, principal=PRINCIPAL_PROD)
    assert judged[0] is args_obj
    assert seen == ["SELECT 1"]


def test_callable_principal_resolved_per_block() -> None:
    tools, _ = _tools()
    counter = {"n": 0}

    def principal() -> dict[str, Any]:
        counter["n"] += 1
        return dict(PRINCIPAL_PROD)

    message = Message(
        content=[
            Block(type="tool_use", id="a", name="db_exec", input={"query": "SELECT 1"}),
            Block(type="tool_use", id="b", name="db_exec", input={"query": "SELECT 2"}),
        ]
    )
    run_tool_uses(build_gate(), tools, message, principal=principal)
    assert counter["n"] == 2


def test_message_without_iterable_content_raises_loudly() -> None:
    tools, _ = _tools()
    with pytest.raises(TypeError, match="iterable content"):
        run_tool_uses(build_gate(), tools, "not a message", principal=PRINCIPAL_PROD)
    with pytest.raises(TypeError, match="iterable content"):
        run_tool_uses(build_gate(), tools, {"content": "text only"}, principal=PRINCIPAL_PROD)


def test_audit_sink_fires_per_block() -> None:
    tools, _ = _tools()
    sink: list[Decision] = []
    gate = build_gate(on_decision=lambda call, decision: sink.append(decision))
    message = Message(
        content=[
            Block(type="tool_use", id="a", name="db_exec", input={"query": "SELECT 1"}),
            Block(type="tool_use", id="b", name="db_exec", input={"query": "DROP TABLE t"}),
            Block(type="tool_use", id="c", name="mystery", input={}),
        ]
    )
    run_tool_uses(gate, tools, message, principal=PRINCIPAL_PROD)
    assert [d.allowed for d in sink] == [True, False, False]
