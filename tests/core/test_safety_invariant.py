"""The safety invariant, exhaustively: a bad input must never become an allow.

Every case here follows the same three-step proof, per shipped normalizer:

  1. The untrusted input makes the normalizer return `Unavailable` (a value,
     never an exception).
  2. A gate whose policy needs that fact denies UNPARSEABLE before the
     policy body runs.
  3. No path reaches an allow, under the most hostile possible policy: one
     that returns `Allow()` unconditionally. If the body ever ran, the call
     would be allowed; the assertion that it is denied and that the body
     never executed is the invariant itself, not a proxy for it.

The gates here are built per case with exactly one, maximally permissive
policy, so a pass cannot be explained by some other policy having denied.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from toolwarden import (
    Allow,
    DenyKind,
    Facts,
    Gate,
    ToolCall,
    Unavailable,
    Verdict,
    policy,
)
from toolwarden.facts import FactKey
from toolwarden.normalize import Normalizer, normalizer
from toolwarden.normalizers import (
    AMOUNT_USD,
    FAX_NUMBER,
    PHI_FIELDS,
    RECIPIENT_DOMAINS,
    SQL_CLASS,
    classify_sql,
    fax_number,
    phi_fields,
    recipient_domains,
    usd_amount,
)

# (case id, normalizer, tool, fact name, hostile args)
UNTRUSTED: list[tuple[str, Normalizer, str, str, dict[str, Any]]] = []


def _add(nrm: Normalizer, tool: str, fact: str, label: str, args: dict[str, Any]) -> None:
    UNTRUSTED.append((f"{fact}-{label}", nrm, tool, fact, args))


# classify_sql: anything that is not a string is not SQL.
_add(classify_sql, "db_exec", "sql_class", "missing", {})
_add(classify_sql, "db_exec", "sql_class", "none", {"query": None})
_add(classify_sql, "db_exec", "sql_class", "int", {"query": 7})
_add(classify_sql, "db_exec", "sql_class", "mongo-operator", {"query": {"$gt": ""}})
_add(classify_sql, "db_exec", "sql_class", "list", {"query": ["SELECT 1"]})
_add(classify_sql, "db_exec", "sql_class", "bool", {"query": True})
_add(classify_sql, "db_exec", "sql_class", "bytes", {"query": b"SELECT 1"})

# recipient_domains: one untrustworthy recipient poisons the whole fact.
_add(recipient_domains, "send_email", "recipient_domains", "missing", {})
_add(recipient_domains, "send_email", "recipient_domains", "string-not-list", {"to": "a@ourcompany.com"})
_add(recipient_domains, "send_email", "recipient_domains", "tuple-not-list", {"to": ("a@ourcompany.com",)})
_add(recipient_domains, "send_email", "recipient_domains", "empty-list", {"to": []})
_add(recipient_domains, "send_email", "recipient_domains", "int-entry", {"to": ["a@ourcompany.com", 42]})
_add(recipient_domains, "send_email", "recipient_domains", "none-entry", {"to": [None]})
_add(recipient_domains, "send_email", "recipient_domains", "double-at", {"to": ["a@b@ourcompany.com"]})
_add(recipient_domains, "send_email", "recipient_domains", "no-at", {"to": ["nodomain"]})
_add(recipient_domains, "send_email", "recipient_domains", "empty-domain", {"to": ["a@"]})
_add(recipient_domains, "send_email", "recipient_domains", "empty-local", {"to": ["@ourcompany.com"]})
_add(recipient_domains, "send_email", "recipient_domains", "double-dot", {"to": ["a@bad..example.com"]})
_add(recipient_domains, "send_email", "recipient_domains", "leading-dot", {"to": ["a@.example.com"]})
_add(recipient_domains, "send_email", "recipient_domains", "bad-chars", {"to": ["a@exa mple.com"]})

# usd_amount: bool is an int, NaN compares False against every cap, and a
# non-numeric string is a claim, not an amount.
_add(usd_amount, "issue_refund", "amount_usd", "missing", {})
_add(usd_amount, "issue_refund", "amount_usd", "bool", {"amount_usd": True})
_add(usd_amount, "issue_refund", "amount_usd", "string", {"amount_usd": "100"})
_add(usd_amount, "issue_refund", "amount_usd", "none", {"amount_usd": None})
_add(usd_amount, "issue_refund", "amount_usd", "nan", {"amount_usd": float("nan")})
_add(usd_amount, "issue_refund", "amount_usd", "inf", {"amount_usd": float("inf")})
_add(usd_amount, "issue_refund", "amount_usd", "overflow-int", {"amount_usd": 10**400})
_add(usd_amount, "issue_refund", "amount_usd", "list", {"amount_usd": [5]})
_add(usd_amount, "charge", "amount_usd", "charge-bool", {"amount_usd": True})

# phi_fields: present-but-broken is a claim about PHI that cannot be read.
# (Absent is NOT here: absent computes to (), the genuinely-untagged value.)
_add(phi_fields, "send_email", "phi_field_names", "string-tag", {"phi_fields": "patient_ssn"})
_add(phi_fields, "send_email", "phi_field_names", "int-entry", {"phi_fields": ["ssn", 7]})
_add(phi_fields, "send_email", "phi_field_names", "dict", {"phi_fields": {"ssn": True}})
_add(phi_fields, "send_email", "phi_field_names", "int", {"phi_fields": 5})
_add(phi_fields, "send_email", "phi_field_names", "none", {"phi_fields": None})
_add(phi_fields, "send_fax", "phi_field_names", "fax-string-tag", {"phi_fields": "patient_ssn"})

# fax_number: no usable destination string, no fact.
_add(fax_number, "send_fax", "fax_number", "missing", {})
_add(fax_number, "send_fax", "fax_number", "empty", {"fax_number": ""})
_add(fax_number, "send_fax", "fax_number", "int", {"fax_number": 15551230000})
_add(fax_number, "send_fax", "fax_number", "none", {"fax_number": None})
_add(fax_number, "send_fax", "fax_number", "list", {"fax_number": ["+15551230000"]})
_add(fax_number, "send_fax", "fax_number", "bytes", {"fax_number": b"+15551230000"})

_KEYS: dict[str, FactKey[Any]] = {
    "sql_class": SQL_CLASS,
    "recipient_domains": RECIPIENT_DOMAINS,
    "amount_usd": AMOUNT_USD,
    "phi_field_names": PHI_FIELDS,
    "fax_number": FAX_NUMBER,
}

_IDS = [case_id for case_id, *_ in UNTRUSTED]


@pytest.mark.parametrize(("case_id", "nrm", "tool", "fact", "args"), UNTRUSTED, ids=_IDS)
def test_untrusted_input_is_unavailable_not_exception(
    case_id: str, nrm: Normalizer, tool: str, fact: str, args: dict[str, Any]
) -> None:
    """Step 1: the normalizer answers with an Unavailable value, in-band."""
    produced = nrm.fn(ToolCall(tool=tool, args=args, principal={}))
    assert isinstance(produced, Mapping)
    value = produced[_KEYS[fact]]
    assert isinstance(value, Unavailable)
    assert value.fact == fact
    assert value.reason  # a compliance reader gets words, not an empty string


@pytest.mark.parametrize(("case_id", "nrm", "tool", "fact", "args"), UNTRUSTED, ids=_IDS)
def test_no_path_from_untrusted_input_to_allow(
    case_id: str, nrm: Normalizer, tool: str, fact: str, args: dict[str, Any]
) -> None:
    """Steps 2 and 3: engine denies UNPARSEABLE, the eager body never runs."""
    body_ran: list[bool] = []

    @policy("eager_allow", tools=(tool,), needs=(_KEYS[fact],))
    def eager_allow(f: Facts) -> Verdict:
        body_ran.append(True)
        return Allow()

    gate = Gate([eager_allow], [nrm])
    decision = gate.decide(tool=tool, args=args, principal={"env": "production"})

    assert decision.allowed is False
    assert decision.permits == ()
    assert body_ran == [], "policy body executed on an Unavailable fact"
    assert {d.kind for d in decision.denials} == {DenyKind.UNPARSEABLE}
    (denial,) = decision.denials
    assert denial.policy == "eager_allow"
    assert f"fact {fact} unavailable: " in denial.reason
    assert decision.outcome is not None
    assert decision.outcome.kind is DenyKind.UNPARSEABLE
    # The broken fact is in fact_errors, never in facts.
    assert fact in decision.fact_errors
    assert fact not in decision.facts
    assert decision.trail == (("eager_allow", "deny"),)


def test_raising_normalizer_cannot_produce_allow() -> None:
    """Engine-synthesized Unavailable (rule 3 of the batch contract) takes
    the same deny path as an honest one: even a crashing normalizer cannot
    open the gate."""
    key: FactKey[str] = FactKey("crash_fact")

    @normalizer("crasher", tools=("t",), provides=(key,))
    def crasher(call: ToolCall) -> Mapping[FactKey[Any], object]:
        raise ValueError("normalizer bug")

    body_ran: list[bool] = []

    @policy("eager", tools=("t",), needs=(key,))
    def eager(f: Facts) -> Verdict:
        body_ran.append(True)
        return Allow()

    decision = Gate([eager], [crasher]).decide(tool="t", args={}, principal={})
    assert decision.allowed is False
    assert body_ran == []
    (denial,) = decision.denials
    assert denial.kind is DenyKind.UNPARSEABLE
    assert "crasher raised ValueError" in denial.reason


def test_unavailable_is_a_value_type() -> None:
    """Unavailable is frozen data with the two documented fields."""
    import dataclasses

    unavailable = Unavailable("f", "why")
    assert unavailable.fact == "f"
    assert unavailable.reason == "why"
    with pytest.raises(dataclasses.FrozenInstanceError):
        unavailable.reason = "changed"  # type: ignore[misc]
