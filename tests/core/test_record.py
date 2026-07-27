"""Audit records: redaction, shape summaries, digests, and the envelope.

The redaction rule under test is the spec's one-liner: facts are loggable,
args are not. Sentinel secrets planted in query text, message bodies, PHI
values, and a credential must be absent from every record body and every
envelope, across every case in the committed corpus, while the shape
summaries and digests still let a reviewer verify a stored line against a
replayed decision.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from example_policies import ALL_CASES, build_gate
from support import ALL_SENTINELS, SECRET_BODY, SECRET_CRED, assert_no_sentinels
from toolwarden import Decision, Gate


@pytest.fixture(scope="module")
def gate() -> Gate:
    return build_gate()


def _decide(gate: Gate, case_name: str) -> Decision:
    case = next(c for c in ALL_CASES if c.name == case_name)
    return gate.decide(
        tool=case.call.tool, args=case.call.args, principal=case.call.principal
    )


def test_no_sentinel_reaches_any_record_or_envelope(gate: Gate) -> None:
    """The whole corpus, every planted secret, body and envelope both."""
    for case in ALL_CASES:
        decision = gate.decide(
            tool=case.call.tool, args=case.call.args, principal=case.call.principal
        )
        assert_no_sentinels(decision.record(), where=f"record body of {case.name}")
        assert_no_sentinels(
            decision.record_line(ts="2026-01-01T00:00:00+00:00"),
            where=f"record_line of {case.name}",
        )


def test_no_sentinel_reaches_refusals(gate: Gate) -> None:
    for case in ALL_CASES:
        if case.expect_allowed:
            continue
        decision = gate.decide(
            tool=case.call.tool, args=case.call.args, principal=case.call.principal
        )
        refusal = decision.refusal()
        assert_no_sentinels(refusal.message(), where=f"refusal message of {case.name}")
        assert_no_sentinels(
            refusal.to_tool_result(), where=f"refusal payload of {case.name}"
        )


def test_record_is_byte_stable_across_runs(gate: Gate) -> None:
    for case in ALL_CASES:
        first = gate.decide(
            tool=case.call.tool, args=case.call.args, principal=case.call.principal
        )
        second = gate.decide(
            tool=case.call.tool, args=case.call.args, principal=case.call.principal
        )
        assert first.record() == second.record(), case.name


def test_arg_shape_summaries(gate: Gate) -> None:
    decision = gate.decide(
        tool="send_email",
        args={
            "to": ["a@ourcompany.com"],
            "subject": "hello",
            "body": SECRET_BODY,
            "count": 3,
            "urgent": True,
            "ratio": 0.5,
            "nothing": None,
            "meta": {"campaign": SECRET_CRED, "batch": 7},
            "blob": object(),
        },
        principal={"env": "production"},
    )
    body = json.loads(decision.record())
    args = body["call"]["args"]
    assert args["to"] == {"type": "list", "len": 1}
    assert args["subject"] == {
        "type": "str",
        "len": 5,
        "sha256_12": hashlib.sha256(b"hello").hexdigest()[:12],
    }
    assert args["body"]["type"] == "str"
    assert args["body"]["len"] == len(SECRET_BODY)
    assert args["count"] == {"type": "int"}
    assert args["urgent"] == {"type": "bool"}
    assert args["ratio"] == {"type": "float"}
    assert args["nothing"] == {"type": "null"}
    # Dict keys are schema and loggable; dict VALUES never appear.
    assert args["meta"] == {"type": "dict", "keys": ["batch", "campaign"]}
    assert args["blob"] == {"type": "object"}
    assert len(body["call"]["args_sha256"]) == 12


def test_args_sha256_stable_and_discriminating(gate: Gate) -> None:
    """Same args, same digest (replay can confirm "same call"); different
    args, different digest (the summary is not decorative)."""

    def digest(args: dict[str, object]) -> str:
        decision = gate.decide(tool="db_exec", args=args, principal={"env": "production"})
        value = json.loads(decision.record())["call"]["args_sha256"]
        assert isinstance(value, str)
        return value

    a1 = digest({"query": "SELECT 1"})
    a2 = digest({"query": "SELECT 1"})
    b = digest({"query": "SELECT 2"})
    assert a1 == a2
    assert a1 != b


def test_envelope_wraps_body_and_verifies(gate: Gate) -> None:
    decision = _decide(gate, "prod_write_denied")
    body = decision.record()
    line = decision.record_line(ts="2026-01-01T00:00:00+00:00")
    envelope = json.loads(line)
    assert envelope["ts"] == "2026-01-01T00:00:00+00:00"
    assert envelope["id"] == decision.decision_id
    # Re-serializing the embedded record with the pinned flags reproduces
    # the exact bytes the digest covers: offline verification works.
    reserialized = json.dumps(
        envelope["record"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    assert reserialized == body
    assert envelope["record_sha256"] == hashlib.sha256(body.encode()).hexdigest()


def test_ts_and_id_live_only_in_the_envelope(gate: Gate) -> None:
    decision = _decide(gate, "prod_write_denied")
    body = decision.record()
    assert decision.decision_id not in body
    parsed = json.loads(body)
    assert "ts" not in parsed and "id" not in parsed


def test_record_body_structure_matches_spec(gate: Gate) -> None:
    decision = _decide(gate, "email_phi_external_denied")
    body = json.loads(decision.record())
    assert body["v"] == 1
    assert set(body) == {
        "v", "call", "facts", "fact_errors", "trail", "denials", "permits",
        "outcome", "policyset_sha256",
    }
    # Facts render enums by value, frozensets as sorted lists, tuples as lists.
    assert body["facts"]["recipient_domains"] == ["gmail.com"]
    assert body["facts"]["phi_field_names"] == ["dob", "lab_result", "name"]
    assert body["fact_errors"] == {}
    assert body["trail"] == [
        {"policy": "internal_email_only", "verdict": "deny"},
        {"policy": "phi_minimum_necessary", "verdict": "deny"},
    ]
    assert body["outcome"]["allowed"] is False
    assert body["outcome"]["kind"] == "policy_forbade"
    assert body["outcome"]["policy"] == "internal_email_only"
    assert body["permits"] == []
    assert len(body["policyset_sha256"]) == 12
    assert body["policyset_sha256"] == gate.policyset_sha256


def test_allowed_record_outcome(gate: Gate) -> None:
    decision = _decide(gate, "prod_read_allowed")
    body = json.loads(decision.record())
    assert body["outcome"] == {"allowed": True, "policy": "db_read_scope"}
    assert body["permits"] == ["db_read_scope"]
    assert body["facts"]["sql_class"] == "read"  # enum by .value


def test_unavailable_facts_go_to_fact_errors_not_facts(gate: Gate) -> None:
    decision = _decide(gate, "prod_nonstring_query_unparseable")
    body = json.loads(decision.record())
    assert body["facts"] == {}
    assert body["fact_errors"] == {"sql_class": "query is missing or not a string"}


def test_principal_is_logged_as_is(gate: Gate) -> None:
    """Host-supplied identity metadata is logged verbatim by contract; that
    contract is exactly why no code path lets model args reach it."""
    decision = _decide(gate, "prod_read_allowed")
    body = json.loads(decision.record())
    assert body["call"]["principal"] == {"agent": "support-bot", "env": "production"}


def test_malformed_call_record_leaks_nothing(gate: Gate) -> None:
    secret_args = ["not-a-mapping", ALL_SENTINELS[0]]
    decision = gate.decide(tool="db_exec", args=secret_args, principal={})  # type: ignore[arg-type]
    body = decision.record()
    assert_no_sentinels(body, where="malformed-call record")
    parsed = json.loads(body)
    assert parsed["call"]["args"] == {}  # sanitized, not echoed


def test_serialization_is_pinned_ascii(gate: Gate) -> None:
    decision = gate.decide(
        tool="db_exec", args={"query": "SELECT 'café'"}, principal={"env": "production"}
    )
    body = decision.record()
    assert body.isascii()
