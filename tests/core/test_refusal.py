"""Refusal: the model-facing half of the deny-time contract.

The message format and the canonical payload are pinned byte-for-byte,
because every boundary (wrap, three adapters, the hook) promises to deliver
the SAME payload for the same denied decision, and that promise is only
testable if the bytes themselves are fixed here.
"""

from __future__ import annotations

import json

import pytest

from example_policies import build_gate
from toolwarden import Decision, Gate, Refusal, ToolDenied
from toolwarden.denial import Denial, DenyKind


@pytest.fixture(scope="module")
def gate() -> Gate:
    return build_gate()


def _prod_write(gate: Gate) -> Decision:
    return gate.decide(
        tool="db_exec",
        args={"query": "DELETE FROM orders"},
        principal={"agent": "support-bot", "env": "production"},
    )


def test_message_matches_spec_example_byte_for_byte(gate: Gate) -> None:
    refusal = _prod_write(gate).refusal()
    assert refusal.message() == (
        "denied by policy (prod_db_read_only [policy_forbade]: "
        "statement is not a provable read against the production database)"
    )


def test_message_lists_every_denial_in_canonical_order() -> None:
    refusal = Refusal(
        tool="t",
        denials=(
            Denial(DenyKind.UNPARSEABLE, "a_policy", "fact x unavailable: broken"),
            Denial(DenyKind.POLICY_FORBADE, "b_policy", "nope"),
        ),
        decision_id="abc123",
    )
    assert refusal.message() == (
        "denied by policy (a_policy [unparseable]: fact x unavailable: broken; "
        "b_policy [policy_forbade]: nope)"
    )


def test_to_tool_result_is_canonical_json(gate: Gate) -> None:
    decision = _prod_write(gate)
    payload = decision.refusal().to_tool_result()
    parsed = json.loads(payload)
    assert parsed == {
        "denied": True,
        "tool": "db_exec",
        "decision_id": decision.decision_id,
        "denials": [
            {
                "kind": "policy_forbade",
                "policy": "prod_db_read_only",
                "reason": "statement is not a provable read against the production database",
            }
        ],
    }
    # The exact serialization flags of the audit record: sorted keys, no
    # whitespace, ascii. Reserializing that way reproduces the bytes.
    assert payload == json.dumps(
        parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def test_refusal_carries_denials_never_facts_or_args(gate: Gate) -> None:
    import dataclasses

    decision = _prod_write(gate)
    refusal = decision.refusal()
    assert {field.name for field in dataclasses.fields(refusal)} == {
        "tool", "denials", "decision_id",
    }
    assert refusal.tool == "db_exec"
    assert refusal.denials == decision.denials
    assert refusal.decision_id == decision.decision_id


def test_decision_id_joins_transcript_to_audit_line(gate: Gate) -> None:
    decision = _prod_write(gate)
    line = json.loads(decision.record_line(ts="2026-01-01T00:00:00+00:00"))
    payload = json.loads(decision.refusal().to_tool_result())
    assert payload["decision_id"] == line["id"]


def test_tool_denied_wraps_the_refusal(gate: Gate) -> None:
    refusal = _prod_write(gate).refusal()
    exc = ToolDenied(refusal)
    assert exc.refusal is refusal
    assert str(exc) == refusal.message()
