"""LangChain adapter, offline: stub ToolMessage, real gate, middleware shape.

The handler contract under test is `wrap_tool_call`'s: on allow the wrapped
handler runs with the request unchanged, on deny the tool never runs and a
status="error" ToolMessage carries the canonical refusal payload.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from typing import Any

import pytest
from adapter_stubs import StubToolCallRequest, StubToolMessage, make_langchain_core_modules

from example_policies import PRINCIPAL_PROD, build_gate
from support import SECRET_QUERY, assert_no_sentinels
from toolwarden import Decision


@pytest.fixture()
def stub_langchain(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    package, messages = make_langchain_core_modules()
    monkeypatch.setitem(sys.modules, "langchain_core", package)
    monkeypatch.setitem(sys.modules, "langchain_core.messages", messages)
    yield


@pytest.fixture()
def sink() -> list[Decision]:
    return []


@pytest.fixture()
def handler(stub_langchain: None, sink: list[Decision]) -> Any:
    from toolwarden.adapters.langchain import toolwarden_tool_wrapper

    gate = build_gate(on_decision=lambda call, decision: sink.append(decision))
    return toolwarden_tool_wrapper(gate, principal=PRINCIPAL_PROD)


def _request(name: Any, args: Any, call_id: Any = "call_1") -> StubToolCallRequest:
    return StubToolCallRequest(tool_call={"name": name, "args": args, "id": call_id})


def test_allowed_call_invokes_the_wrapped_handler_unchanged(
    handler: Any, sink: list[Decision]
) -> None:
    invoked: list[Any] = []

    def downstream(request: Any) -> str:
        invoked.append(request)
        return "tool ran"

    request = _request("db_exec", {"query": "SELECT 1"})
    result = handler(request, downstream)
    assert result == "tool ran"
    assert invoked[0] is request  # the very request object, not a copy
    assert sink[-1].allowed is True


def test_denied_call_short_circuits_with_an_error_tool_message(
    handler: Any, sink: list[Decision]
) -> None:
    invoked: list[Any] = []

    def downstream(request: Any) -> str:
        invoked.append(request)
        return "tool ran"

    request = _request("db_exec", {"query": f"DELETE FROM t -- {SECRET_QUERY}"})
    result = handler(request, downstream)
    assert invoked == []  # blocked BEFORE execution
    assert isinstance(result, StubToolMessage)
    assert result.status == "error"
    assert result.tool_call_id == "call_1"
    assert result.name == "db_exec"
    payload = json.loads(result.content)
    assert payload["denied"] is True
    assert payload["denials"][0]["policy"] == "prod_db_read_only"
    assert payload["decision_id"] == sink[-1].decision_id
    assert_no_sentinels(result.content, where="langchain ToolMessage content")


def test_missing_name_or_args_reaches_boundary_validation(handler: Any) -> None:
    result = handler(_request(None, None), lambda request: "ran")
    assert isinstance(result, StubToolMessage)
    payload = json.loads(result.content)
    assert payload["denials"][0]["kind"] == "malformed_call"
    assert result.name is None  # non-string name is not echoed as a name
    assert result.tool_call_id == "call_1"


def test_non_mapping_tool_call_raises_loudly(handler: Any) -> None:
    """Host wiring handed over a pre-1.x request shape: fail closed and
    loud, not with a quiet deny that hides a version mismatch."""

    class BadRequest:
        tool_call = None

    with pytest.raises(TypeError, match="langchain>=1.0"):
        handler(BadRequest(), lambda request: "ran")


def test_callable_principal_resolved_per_call(stub_langchain: None) -> None:
    from toolwarden.adapters.langchain import toolwarden_tool_wrapper

    counter = {"n": 0}

    def principal() -> dict[str, Any]:
        counter["n"] += 1
        return dict(PRINCIPAL_PROD)

    handler = toolwarden_tool_wrapper(build_gate(), principal=principal)
    handler(_request("db_exec", {"query": "SELECT 1"}), lambda request: "ran")
    handler(_request("db_exec", {"query": "SELECT 2"}), lambda request: "ran")
    assert counter["n"] == 2


def test_model_args_cannot_reach_the_principal(handler: Any, sink: list[Decision]) -> None:
    handler(
        _request("db_exec", {"query": "DELETE FROM t", "env": "development"}),
        lambda request: "ran",
    )
    assert sink[-1].allowed is False
    assert sink[-1].call.principal == PRINCIPAL_PROD


def test_audit_sink_fires_per_call(handler: Any, sink: list[Decision]) -> None:
    handler(_request("db_exec", {"query": "SELECT 1"}), lambda request: "ran")
    handler(_request("db_exec", {"query": "DROP TABLE t"}), lambda request: "ran")
    handler(_request("mystery", {}), lambda request: "ran")
    assert [d.allowed for d in sink] == [True, False, False]
