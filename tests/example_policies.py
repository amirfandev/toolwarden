"""The worked example policies and their mandatory case matrices.

This is the committed fixture behind `test_case_matrix.py`, the corpus for
the determinism and redaction tests, and the reference wiring for the wrap,
adapter, and hook tests. The six policies mirror the spec's worked examples
(section 1 and the healthcare taste, section 13) against the five shipped
normalizers, and every policy registers its allow/deny matrix right here,
next to its definition, because the rule is that a policy without a matrix
does not merge.

Sentinel secrets from `support` are planted in the case arguments on
purpose: the same cases that prove decision correctness also prove that no
argument value ever reaches a record, a refusal, or a transcript.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from support import SECRET_BODY, SECRET_CRED, SECRET_PHI, SECRET_QUERY
from toolwarden import (
    NOT_APPLICABLE,
    Allow,
    Deny,
    DenyKind,
    Facts,
    Gate,
    ToolCall,
    Verdict,
    policy,
)
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

COMPANY = "ourcompany.com"

# v0.1 keeps the covered-entity set to the company itself: the one worked
# healthcare policy is a taste, and a real covered-entity registry is the
# v0.2 pack's problem. With this set, "PHI to a covered entity" and "PHI
# kept internal" are the same case, and the permit still comes from
# internal_email_only.
COVERED_ENTITY_DOMAINS = frozenset({COMPANY})

APPROVED_FAX_NUMBERS = frozenset({"+15551230000", "+15551230001"})

PRINCIPAL_PROD = {"agent": "support-bot", "env": "production"}
PRINCIPAL_DEV = {"agent": "support-bot", "env": "development"}


@policy("prod_db_read_only", tools=("db_exec",), needs=(SQL_CLASS,), permits=False)
def prod_db_read_only(f: Facts) -> Verdict:
    if f.principal.get("env") != "production":
        return NOT_APPLICABLE
    if f[SQL_CLASS] is not SqlClass.READ:  # WRITE and UNKNOWN both land here
        return Deny("statement is not a provable read against the production database")
    return NOT_APPLICABLE  # the permit comes from db_read_scope


@policy("db_read_scope", tools=("db_exec",), needs=(SQL_CLASS,))
def db_read_scope(f: Facts) -> Verdict:
    if f[SQL_CLASS] is SqlClass.READ:
        return Allow()
    return NOT_APPLICABLE


@policy("internal_email_only", tools=("send_email",), needs=(RECIPIENT_DOMAINS,))
def internal_email_only(f: Facts) -> Verdict:
    external = f[RECIPIENT_DOMAINS] - {COMPANY}
    if external:
        return Deny(
            f"recipient domain(s) outside {COMPANY}: {', '.join(sorted(external))}"
        )
    return Allow()


@policy(
    "phi_minimum_necessary",
    tools=("send_email",),
    needs=(PHI_FIELDS, RECIPIENT_DOMAINS),
    permits=False,
)
def phi_minimum_necessary(f: Facts) -> Verdict:
    tagged = f[PHI_FIELDS]
    if not tagged:
        return NOT_APPLICABLE  # genuinely untagged; nothing to minimize
    uncovered = f[RECIPIENT_DOMAINS] - COVERED_ENTITY_DOMAINS
    if uncovered:
        return Deny(
            f"PHI ({', '.join(sorted(tagged))}) addressed to non-covered-entity "
            f"domain(s): {', '.join(sorted(uncovered))}"
        )
    return NOT_APPLICABLE  # covered recipients; the permit comes from internal_email_only


@policy("refund_cap", tools=("issue_refund",), needs=(AMOUNT_USD,))
def refund_cap(f: Facts) -> Verdict:
    amount = f[AMOUNT_USD]
    if amount > 500:
        return Deny(f"amount {amount:.2f} USD exceeds the 500 USD cap")
    return Allow()


@policy("fax_allowlist", tools=("send_fax",), needs=(FAX_NUMBER,))
def fax_allowlist(f: Facts) -> Verdict:
    if f[FAX_NUMBER] in APPROVED_FAX_NUMBERS:
        return Allow()
    return Deny("fax destination is not on the approved fax allowlist")


POLICIES = (
    prod_db_read_only,
    db_read_scope,
    internal_email_only,
    phi_minimum_necessary,
    refund_cap,
    fax_allowlist,
)

NORMALIZERS = (classify_sql, recipient_domains, usd_amount, phi_fields, fax_number)

# "charge" is in usd_amount's declared tools but no example policy governs
# it, so it stays out of the declared universe: a normalizer covering an
# ungoverned tool is idle capacity, not a coverage finding.
TOOL_UNIVERSE = ("db_exec", "send_email", "issue_refund", "send_fax")


def build_gate(**overrides: object) -> Gate:
    """The example gate, strict by default, built fresh per call.

    Fresh construction matters to the determinism tests: two gates built
    from the same declarations must agree on every byte of every output.
    """
    kwargs: dict[str, object] = {
        "tools": TOOL_UNIVERSE,
        "strict": True,
    }
    kwargs.update(overrides)
    return Gate(list(POLICIES), list(NORMALIZERS), **kwargs)  # type: ignore[arg-type]


@dataclass(frozen=True)
class Case:
    """One row of a policy's allow/deny matrix, per the spec's shape."""

    name: str
    call: ToolCall
    expect_allowed: bool
    expect_kinds: frozenset[DenyKind] = field(default_factory=frozenset)
    expect_denying_policies: frozenset[str] = field(default_factory=frozenset)


def _case(
    name: str,
    tool: str,
    args: Mapping[str, Any],
    principal: Mapping[str, Any],
    *,
    allowed: bool,
    kinds: frozenset[DenyKind] = frozenset(),
    deniers: frozenset[str] = frozenset(),
) -> Case:
    return Case(
        name=name,
        call=ToolCall(tool=tool, args=args, principal=principal),
        expect_allowed=allowed,
        expect_kinds=kinds,
        expect_denying_policies=deniers,
    )


_FORBADE = frozenset({DenyKind.POLICY_FORBADE})
_UNPARSEABLE = frozenset({DenyKind.UNPARSEABLE})
_NO_PERMIT = frozenset({DenyKind.NO_PERMIT})

ALL_CASES: tuple[Case, ...] = (
    # db_exec
    _case(
        "prod_read_allowed",
        "db_exec",
        {"query": f"SELECT id FROM orders WHERE note = '{SECRET_QUERY}'"},
        PRINCIPAL_PROD,
        allowed=True,
    ),
    _case(
        "prod_write_denied",
        "db_exec",
        {"query": f"DELETE FROM orders -- {SECRET_QUERY}"},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_FORBADE,
        deniers=frozenset({"prod_db_read_only"}),
    ),
    _case(
        "prod_write_word_in_literal_allowed",
        "db_exec",
        {"query": "SELECT 'please UPDATE your records' FROM notices"},
        PRINCIPAL_PROD,
        allowed=True,
    ),
    _case(
        "prod_comment_split_evasion_denied",
        "db_exec",
        {"query": "DR/**/OP TABLE users"},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_FORBADE,
        deniers=frozenset({"prod_db_read_only"}),
    ),
    _case(
        "prod_multi_statement_denied",
        "db_exec",
        {"query": "SELECT * FROM t; DROP TABLE t"},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_FORBADE,
        deniers=frozenset({"prod_db_read_only"}),
    ),
    _case(
        "prod_mixed_case_write_denied",
        "db_exec",
        {"query": "DeLeTe FROM orders"},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_FORBADE,
        deniers=frozenset({"prod_db_read_only"}),
    ),
    _case(
        "prod_empty_query_denied",
        "db_exec",
        {"query": ""},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_FORBADE,
        deniers=frozenset({"prod_db_read_only"}),
    ),
    _case(
        "dev_write_no_permit",
        "db_exec",
        {"query": "DROP TABLE scratch"},
        PRINCIPAL_DEV,
        allowed=False,
        kinds=_NO_PERMIT,
        deniers=frozenset({"engine"}),
    ),
    _case(
        "prod_nonstring_query_unparseable",
        "db_exec",
        {"query": {"$gt": ""}},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_UNPARSEABLE,
        deniers=frozenset({"prod_db_read_only", "db_read_scope"}),
    ),
    _case(
        "prod_missing_query_unparseable",
        "db_exec",
        {"table": "orders"},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_UNPARSEABLE,
        deniers=frozenset({"prod_db_read_only", "db_read_scope"}),
    ),
    # send_email
    _case(
        "email_internal_allowed",
        "send_email",
        {
            "to": ["colleague@ourcompany.com"],
            "subject": "quarterly numbers",
            "body": f"see attached {SECRET_BODY}",
            "api_key": SECRET_CRED,
        },
        PRINCIPAL_PROD,
        allowed=True,
    ),
    _case(
        "email_external_denied",
        "send_email",
        {"to": ["contact@gmail.com"], "body": SECRET_BODY},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_FORBADE,
        deniers=frozenset({"internal_email_only"}),
    ),
    _case(
        "email_mixed_recipients_denied",
        "send_email",
        {"to": ["a@ourcompany.com", "b@gmail.com"], "body": SECRET_BODY},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_FORBADE,
        deniers=frozenset({"internal_email_only"}),
    ),
    _case(
        "email_suffix_attack_denied",
        "send_email",
        {"to": ["evil@sub.ourcompany.com.attacker.com"], "body": SECRET_BODY},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_FORBADE,
        deniers=frozenset({"internal_email_only"}),
    ),
    _case(
        "email_to_string_unparseable",
        "send_email",
        {"to": "a@ourcompany.com", "body": SECRET_BODY},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_UNPARSEABLE,
        deniers=frozenset({"internal_email_only", "phi_minimum_necessary"}),
    ),
    _case(
        "email_nonstring_entry_unparseable",
        "send_email",
        {"to": ["a@ourcompany.com", 42], "body": SECRET_BODY},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_UNPARSEABLE,
        deniers=frozenset({"internal_email_only", "phi_minimum_necessary"}),
    ),
    _case(
        "email_double_at_unparseable",
        "send_email",
        {"to": ["a@b@ourcompany.com"], "body": SECRET_BODY},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_UNPARSEABLE,
        deniers=frozenset({"internal_email_only", "phi_minimum_necessary"}),
    ),
    _case(
        "email_empty_to_unparseable",
        "send_email",
        {"to": [], "body": SECRET_BODY},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_UNPARSEABLE,
        deniers=frozenset({"internal_email_only", "phi_minimum_necessary"}),
    ),
    _case(
        "email_phi_external_denied",
        "send_email",
        {
            "to": ["records@gmail.com"],
            "phi_fields": ["dob", "lab_result", "name"],
            "patient_dob": SECRET_PHI,
            "body": SECRET_BODY,
        },
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_FORBADE,
        deniers=frozenset({"internal_email_only", "phi_minimum_necessary"}),
    ),
    _case(
        "email_phi_internal_allowed",
        "send_email",
        {
            "to": ["clinician@ourcompany.com"],
            "phi_fields": ["dob"],
            "patient_dob": SECRET_PHI,
        },
        PRINCIPAL_PROD,
        allowed=True,
    ),
    _case(
        "email_phi_string_tag_unparseable",
        "send_email",
        {
            "to": ["clinician@ourcompany.com"],
            "phi_fields": "patient_ssn",
            "patient_dob": SECRET_PHI,
        },
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_UNPARSEABLE,
        deniers=frozenset({"phi_minimum_necessary"}),
    ),
    _case(
        "email_phi_bad_entries_unparseable",
        "send_email",
        {"to": ["clinician@ourcompany.com"], "phi_fields": ["ssn", 7]},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_UNPARSEABLE,
        deniers=frozenset({"phi_minimum_necessary"}),
    ),
    # issue_refund
    _case(
        "refund_at_cap_allowed",
        "issue_refund",
        {"amount_usd": 500, "note": SECRET_BODY},
        PRINCIPAL_PROD,
        allowed=True,
    ),
    _case(
        "refund_under_cap_allowed",
        "issue_refund",
        {"amount_usd": 42.5},
        PRINCIPAL_PROD,
        allowed=True,
    ),
    _case(
        "refund_just_over_cap_denied",
        "issue_refund",
        {"amount_usd": 500.01},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_FORBADE,
        deniers=frozenset({"refund_cap"}),
    ),
    _case(
        "refund_750_denied",
        "issue_refund",
        {"amount_usd": 750},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_FORBADE,
        deniers=frozenset({"refund_cap"}),
    ),
    _case(
        "refund_bool_unparseable",
        "issue_refund",
        {"amount_usd": True},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_UNPARSEABLE,
        deniers=frozenset({"refund_cap"}),
    ),
    _case(
        "refund_string_unparseable",
        "issue_refund",
        {"amount_usd": "100"},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_UNPARSEABLE,
        deniers=frozenset({"refund_cap"}),
    ),
    _case(
        "refund_nan_unparseable",
        "issue_refund",
        {"amount_usd": float("nan")},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_UNPARSEABLE,
        deniers=frozenset({"refund_cap"}),
    ),
    # send_fax
    _case(
        "fax_approved_allowed",
        "send_fax",
        {"fax_number": "+15551230000", "document": SECRET_PHI},
        PRINCIPAL_PROD,
        allowed=True,
    ),
    _case(
        "fax_unapproved_denied",
        "send_fax",
        {"fax_number": "+15559999999", "document": SECRET_PHI},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_FORBADE,
        deniers=frozenset({"fax_allowlist"}),
    ),
    _case(
        "fax_empty_number_unparseable",
        "send_fax",
        {"fax_number": "", "document": SECRET_PHI},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_UNPARSEABLE,
        deniers=frozenset({"fax_allowlist"}),
    ),
    _case(
        "fax_missing_number_unparseable",
        "send_fax",
        {"document": SECRET_PHI},
        PRINCIPAL_PROD,
        allowed=False,
        kinds=_UNPARSEABLE,
        deniers=frozenset({"fax_allowlist"}),
    ),
)

_BY_NAME = {case.name: case for case in ALL_CASES}


def _matrix(*names: str) -> tuple[Case, ...]:
    return tuple(_BY_NAME[name] for name in names)


# One matrix per policy, keyed by policy name. Cases are shared between
# matrices when one call exercises several policies at once; the
# completeness rules (an allowed case, a POLICY_FORBADE case, an
# UNPARSEABLE case per needed fact, every return branch executed) are
# checked per policy in test_case_matrix.py.
CASE_MATRICES: dict[str, tuple[Case, ...]] = {
    "prod_db_read_only": _matrix(
        "prod_read_allowed",
        "prod_write_denied",
        "prod_comment_split_evasion_denied",
        "prod_empty_query_denied",
        "dev_write_no_permit",
        "prod_nonstring_query_unparseable",
    ),
    "db_read_scope": _matrix(
        "prod_read_allowed",
        "prod_write_word_in_literal_allowed",
        "prod_write_denied",
        "dev_write_no_permit",
        "prod_missing_query_unparseable",
    ),
    "internal_email_only": _matrix(
        "email_internal_allowed",
        "email_external_denied",
        "email_mixed_recipients_denied",
        "email_suffix_attack_denied",
        "email_to_string_unparseable",
    ),
    "phi_minimum_necessary": _matrix(
        "email_internal_allowed",
        "email_phi_internal_allowed",
        "email_phi_external_denied",
        "email_phi_string_tag_unparseable",
        "email_to_string_unparseable",
    ),
    "refund_cap": _matrix(
        "refund_at_cap_allowed",
        "refund_just_over_cap_denied",
        "refund_bool_unparseable",
    ),
    "fax_allowlist": _matrix(
        "fax_approved_allowed",
        "fax_unapproved_denied",
        "fax_empty_number_unparseable",
    ),
}
