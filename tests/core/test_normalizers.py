"""Shipped normalizers against the adversarial and benign inputs of spec
section 12.

The Unavailable side of every normalizer is covered exhaustively in
test_safety_invariant.py; this file pins down the COMPUTED values, because a
misclassification that still computes is the failure mode the measured
prototype internals exist to prevent: 'update' inside a string literal must
stay a READ, a comment-split keyword must stay UNKNOWN, and a suffix-attack
address must never resolve to the company domain.
"""

from __future__ import annotations

from typing import Any

import pytest

from toolwarden import ToolCall, Unavailable
from toolwarden.normalizers import (
    AMOUNT_USD,
    FAX_NUMBER,
    PHI_FIELDS,
    RECIPIENT_DOMAINS,
    SQL_CLASS,
    SqlClass,
    classify_sql,
    fax_number,
    phi_fields,
    recipient_domains,
    usd_amount,
)


def _sql(query: str) -> object:
    call = ToolCall(tool="db_exec", args={"query": query}, principal={})
    return classify_sql.fn(call)[SQL_CLASS]


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        # Reads
        ("SELECT id FROM orders WHERE id = 42", SqlClass.READ),
        ("select id from orders", SqlClass.READ),
        ("WITH cte AS (SELECT 1) SELECT * FROM cte", SqlClass.READ),
        ("EXPLAIN SELECT 1", SqlClass.READ),
        ("SHOW TABLES", SqlClass.READ),
        ("VALUES (1, 2)", SqlClass.READ),
        # The false-positive guard: a write keyword inside a string literal
        # is data, not a statement, and must classify as a read.
        ("SELECT 'please UPDATE your records' FROM notices", SqlClass.READ),
        ('SELECT "DROP" FROM keywords', SqlClass.READ),
        # A write keyword inside a comment is stripped before scanning.
        ("/* UPDATE nothing */ SELECT 1", SqlClass.READ),
        ("SELECT 1 -- DELETE later", SqlClass.READ),
        # A doubled quote is an escape inside a literal, not a close-reopen.
        ("SELECT 'it''s fine; DROP nothing' FROM t", SqlClass.READ),
        # Writes
        ("DELETE FROM orders", SqlClass.WRITE),
        ("DeLeTe FROM orders", SqlClass.WRITE),
        ("INSERT INTO t VALUES (1)", SqlClass.WRITE),
        ("UPDATE t SET x = 1", SqlClass.WRITE),
        ("DROP TABLE users", SqlClass.WRITE),
        ("TRUNCATE TABLE logs", SqlClass.WRITE),
        ("ALTER TABLE t ADD COLUMN c int", SqlClass.WRITE),
        ("GRANT ALL ON t TO evil", SqlClass.WRITE),
        # A write keyword ANYWHERE outside literals and comments is a write.
        ("SELECT * FROM t; DROP TABLE t", SqlClass.WRITE),
        ("DELETE FROM t -- just checking", SqlClass.WRITE),
        ("-- innocent\nDROP TABLE x", SqlClass.WRITE),
        # The lexer-ordering attack: a quote inside a comment must not open
        # a phantom string literal that swallows the write between the
        # comments. The prototype's strings-then-comments regex layering
        # classified all three of these as READ, an allow in production.
        ("SELECT 1 /*'*/ ; DELETE FROM users /*'*/", SqlClass.WRITE),
        ("SELECT * FROM t /* ' */ ; DELETE FROM t /* ' */", SqlClass.WRITE),
        ("SELECT 1 -- '\nDELETE FROM users -- '", SqlClass.WRITE),
        # The mirror-image hole: a comment opener inside a real literal
        # must not swallow the code after the literal closes.
        ("SELECT '--' FROM t; DROP TABLE t", SqlClass.WRITE),
        ("SELECT '/*' FROM t; DROP TABLE t", SqlClass.WRITE),
        # Unterminated constructs run to end of input, as in a SQL lexer.
        # An unterminated construct with no visible write is UNKNOWN, not READ:
        # the query is a syntax error in a real engine, and the gate refuses to
        # certify as a read anything it cannot prove was not a hidden write.
        ("SELECT 1 /* DELETE FROM t", SqlClass.UNKNOWN),
        # A visible write keyword is definitive even before an unterminated tail.
        ("DELETE FROM t WHERE note = 'unterminated", SqlClass.WRITE),
        # `#` is NOT treated as a comment: it is a line comment in MySQL but the
        # bitwise-XOR operator in PostgreSQL, so blanking a `#` line would hide a
        # real write after the operator. A write after `#` stays visible (WRITE).
        ("SELECT 5 # 3; DELETE FROM users", SqlClass.WRITE),
        # A stray quote after `#` opens a literal that never closes: UNKNOWN,
        # denied, never a read (corpus a30 form).
        ("SELECT 1 # ' \n INSERT INTO t VALUES(1)", SqlClass.UNKNOWN),
        # Paired phantom literals from an unmodeled quoting construct must not
        # hide a write and read. MySQL backtick identifiers are modeled, so the
        # `'` inside them is inert and the DELETE stays visible: WRITE.
        ("SELECT 1 AS `a'b`; DELETE FROM users; SELECT 2 AS `c'd`", SqlClass.WRITE),
        # PostgreSQL dollar-quoting is out of the modeled grammar; the surviving
        # `$` sigils force UNKNOWN rather than reading as a hidden DELETE.
        ("SELECT $$a'b$$; DELETE FROM users; SELECT $$c'd$$", SqlClass.UNKNOWN),
        # MySQL executable comments (`/*! ... */`, version-gated `/*!50000 ... */`)
        # are run by the server. Their interior is scanned as code, not blanked,
        # so a write inside is visible (WRITE), while a version-gated read stays a
        # read. An ordinary `/* ... */` comment remains inert.
        ("SELECT 1 /*! DELETE FROM t */", SqlClass.WRITE),
        ("SELECT 1 /*!50000 DELETE FROM t */", SqlClass.WRITE),
        ("SELECT 1 /*!40001 SQL_NO_CACHE */ SELECT 2", SqlClass.READ),
        ("SELECT 1 /* just a note DELETE */", SqlClass.READ),
        # A lone backtick identifier in a read is modeled and stays a read.
        ("SELECT `id` FROM `orders`", SqlClass.READ),
        # T-SQL bracket identifiers are out of grammar: UNKNOWN, denied.
        ("SELECT [id] FROM [orders]", SqlClass.UNKNOWN),
        # Unknowns: cannot be proven a read, denied by write-restricting policy.
        ("DR/**/OP TABLE users", SqlClass.UNKNOWN),
        ("", SqlClass.UNKNOWN),
        ("   ", SqlClass.UNKNOWN),
        ("BEGIN; COMMIT", SqlClass.UNKNOWN),
        ("CALL do_things()", SqlClass.UNKNOWN),
        ("'just a string'", SqlClass.UNKNOWN),
    ],
)
def test_classify_sql(query: str, expected: SqlClass) -> None:
    assert _sql(query) is expected


def _domains(to: Any) -> object:
    call = ToolCall(tool="send_email", args={"to": to}, principal={})
    return recipient_domains.fn(call)[RECIPIENT_DOMAINS]


def test_email_suffix_attack_never_resolves_to_the_company_domain() -> None:
    """The classic hole: the raw string contains 'ourcompany.com', but the
    real domain is attacker-controlled. The fact must compute to a domain
    that whole-domain comparison rejects; a substring or suffix check would
    have passed it."""
    domains = _domains(["evil@sub.ourcompany.com.attacker.com"])
    assert domains == frozenset({"sub.ourcompany.com.attacker.com"})
    assert "ourcompany.com" not in domains
    assert not frozenset({"ourcompany.com"}) & domains


@pytest.mark.parametrize(
    ("to", "expected"),
    [
        (["a@ourcompany.com"], frozenset({"ourcompany.com"})),
        (["A@OurCompany.COM"], frozenset({"ourcompany.com"})),
        (["  a@ourcompany.com  "], frozenset({"ourcompany.com"})),
        (
            ["a@ourcompany.com", "b@gmail.com"],
            frozenset({"ourcompany.com", "gmail.com"}),
        ),
        (["x@sub.ourcompany.com"], frozenset({"sub.ourcompany.com"})),
    ],
)
def test_recipient_domains_computed(to: list[str], expected: frozenset[str]) -> None:
    assert _domains(to) == expected


def _amount(args: dict[str, Any]) -> object:
    call = ToolCall(tool="issue_refund", args=args, principal={})
    return usd_amount.fn(call)[AMOUNT_USD]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (500, 500.0),  # the boundary value computes exactly
        (500.01, 500.01),
        (0, 0.0),
        (-3, -3.0),
        (42.5, 42.5),
    ],
)
def test_usd_amount_computed(raw: Any, expected: float) -> None:
    value = _amount({"amount_usd": raw})
    assert isinstance(value, float)
    assert value == expected


def test_usd_amount_boundary_semantics_against_a_500_cap() -> None:
    """The comparison a cap policy performs, run against computed values:
    exactly 500 is under the cap, the next representable step above is not."""
    at_cap = _amount({"amount_usd": 500})
    just_over = _amount({"amount_usd": 500.01})
    assert isinstance(at_cap, float) and isinstance(just_over, float)
    assert not at_cap > 500
    assert just_over > 500


def _phi(args: dict[str, Any]) -> object:
    call = ToolCall(tool="send_email", args=args, principal={})
    return phi_fields.fn(call)[PHI_FIELDS]


def test_phi_absent_computes_to_empty_tuple() -> None:
    """Absent means genuinely untagged, a computed value, not a failure.
    (Present-but-broken is Unavailable; that split IS the fix for the
    prototype's PHI-blind-allow bug and is proven in the safety suite.)"""
    assert _phi({}) == ()
    assert _phi({"to": ["a@ourcompany.com"]}) == ()


def test_phi_list_computes_to_tuple_in_given_order() -> None:
    assert _phi({"phi_fields": ["dob", "lab_result", "name"]}) == (
        "dob",
        "lab_result",
        "name",
    )
    assert _phi({"phi_fields": []}) == ()


def _fax(args: dict[str, Any]) -> object:
    call = ToolCall(tool="send_fax", args=args, principal={})
    return fax_number.fn(call)[FAX_NUMBER]


def test_fax_number_passes_through_exactly() -> None:
    """No format normalization: an allow-list compares exact strings, and a
    lenient rewrite would silently widen what an entry matches."""
    assert _fax({"fax_number": "+1 (555) 123-0000"}) == "+1 (555) 123-0000"
    assert _fax({"fax_number": "+15551230000"}) == "+15551230000"


def test_fax_number_whitespace_only_is_computed_not_unavailable() -> None:
    """Documented edge: only the empty string is untrusted; whitespace
    passes through to the policy's exact comparison (and fails it there)."""
    value = _fax({"fax_number": " "})
    assert value == " "
    assert not isinstance(value, Unavailable)
