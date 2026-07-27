"""The policy sets the evidence corpus is judged against.

Two gates are built here, deliberately separate:

`build_gate()` is the worked example set: the six policies from the spec's
usage example over the five shipped normalizers, with a strict tool
universe. This is the gate a reader is meant to copy.

`build_rigged_gate()` exists only to produce POLICY_ERROR evidence. The
corpus must cover every DenyKind, and POLICY_ERROR is by definition the
kind a correct policy never produces, so the misbehaving policies live in
their own gate on their own tool names instead of polluting the example
set. Each one commits exactly one contract violation: raising, returning
Allow under permits=False, returning a non-Verdict, and reading an
undeclared fact.

The healthcare angle in v0.1 is exactly one policy, phi_minimum_necessary;
the fax allow-list is its permitting counterpart on send_fax. The spike
expressed both inside a single function switching on call.tool; here they
are two policies because the Facts model checks needs coverage per (policy,
fact, tool), and RECIPIENT_DOMAINS exists only for send_email while
FAX_NUMBER exists only for send_fax.
"""

from __future__ import annotations

from typing import cast

import _path  # noqa: F401

from toolwarden import (
    NOT_APPLICABLE,
    Allow,
    Deny,
    FactKey,
    Facts,
    Gate,
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

COMPANY_DOMAIN = "ourcompany.com"
COVERED_ENTITY_DOMAINS = frozenset({COMPANY_DOMAIN, "stmarys-hospital.org"})
COVERED_ENTITY_FAX = frozenset({"+15551230001", "+15551230002"})
SPEND_CAP_USD = 500.0

TOOL_UNIVERSE = ("db_exec", "send_email", "issue_refund", "charge", "send_fax")


@policy("prod_db_read_only", tools=("db_exec",), needs=(SQL_CLASS,), permits=False)
def prod_db_read_only(f: Facts) -> Verdict:
    """Production is read-only. WRITE and UNKNOWN both land in the deny
    branch: not provably a read is treated as a write."""
    if f.principal.get("env") != "production":
        return NOT_APPLICABLE
    if f[SQL_CLASS] is not SqlClass.READ:
        return Deny("statement is not a provable read against the production database")
    return NOT_APPLICABLE  # the permit comes from db_read_scope


@policy("db_read_scope", tools=("db_exec",), needs=(SQL_CLASS,))
def db_read_scope(f: Facts) -> Verdict:
    """Provable reads are permitted; everything else abstains, so an
    unpermitted write dies NO_PERMIT even outside production."""
    if f[SQL_CLASS] is SqlClass.READ:
        return Allow()
    return NOT_APPLICABLE


@policy("internal_email_only", tools=("send_email",), needs=(RECIPIENT_DOMAINS,))
def internal_email_only(f: Facts) -> Verdict:
    """Every recipient domain must be the company domain, compared whole."""
    external = f[RECIPIENT_DOMAINS] - {COMPANY_DOMAIN}
    if external:
        return Deny(
            f"recipient domain(s) outside {COMPANY_DOMAIN}: {', '.join(sorted(external))}"
        )
    return Allow()


@policy("spend_cap", tools=("issue_refund", "charge"), needs=(AMOUNT_USD,))
def spend_cap(f: Facts) -> Verdict:
    """Money movement at or under the cap is permitted; above it is denied.
    The boundary is exact: 500.00 passes, 500.01 does not."""
    amount = f[AMOUNT_USD]
    if amount > SPEND_CAP_USD:
        return Deny(f"amount {amount:.2f} USD exceeds the 500 USD cap")
    return Allow()


@policy(
    "phi_minimum_necessary",
    tools=("send_email",),
    needs=(PHI_FIELDS, RECIPIENT_DOMAINS),
    permits=False,
)
def phi_minimum_necessary(f: Facts) -> Verdict:
    """PHI-tagged email may only address covered-entity domains. Forbid
    only: the permit still has to come from internal_email_only, so PHI to
    an external covered entity remains denied by that policy."""
    tagged = f[PHI_FIELDS]
    if not tagged:
        return NOT_APPLICABLE
    uncovered = f[RECIPIENT_DOMAINS] - COVERED_ENTITY_DOMAINS
    if uncovered:
        return Deny(
            f"PHI ({', '.join(sorted(tagged))}) addressed to non-covered-entity "
            f"domain(s): {', '.join(sorted(uncovered))}"
        )
    return NOT_APPLICABLE


@policy("fax_covered_entity", tools=("send_fax",), needs=(PHI_FIELDS, FAX_NUMBER))
def fax_covered_entity(f: Facts) -> Verdict:
    """Faxes are permitted, except PHI to a number off the allow list. The
    reason never echoes the number: it is a model-supplied value and reason
    strings land in both the transcript and the audit record."""
    tagged = f[PHI_FIELDS]
    if tagged and f[FAX_NUMBER] not in COVERED_ENTITY_FAX:
        return Deny(
            f"PHI ({', '.join(sorted(tagged))}) addressed to a fax number "
            "outside the covered-entity allow list"
        )
    return Allow()


def build_gate() -> Gate:
    """The example gate, strict, against the declared tool universe."""
    return Gate(
        policies=[
            prod_db_read_only,
            db_read_scope,
            internal_email_only,
            spend_cap,
            phi_minimum_necessary,
            fax_covered_entity,
        ],
        normalizers=[classify_sql, recipient_domains, usd_amount, phi_fields, fax_number],
        tools=TOOL_UNIVERSE,
        strict=True,
    )


def build_gate_reversed() -> Gate:
    """The same policy set registered in reverse order.

    Exists so recompute.py can assert the spec's order-independence claim
    on real corpus decisions: every record body must be byte-identical to
    the forward gate's, and policyset_sha256 must match.
    """
    return Gate(
        policies=[
            fax_covered_entity,
            phi_minimum_necessary,
            spend_cap,
            internal_email_only,
            db_read_scope,
            prod_db_read_only,
        ],
        normalizers=[fax_number, phi_fields, usd_amount, recipient_domains, classify_sql],
        tools=tuple(reversed(TOOL_UNIVERSE)),
        strict=True,
    )


# ---------------------------------------------------------------------------
# The rigged gate: deliberate contract violations, one per POLICY_ERROR path.
# ---------------------------------------------------------------------------

# Minted but never declared in any needs, so construction cannot see it;
# reading it from a body is the undeclared-fact violation.
_RIG_PHANTOM: FactKey[object] = FactKey("rig_phantom")


@policy("rig_crash", tools=("rig_crash",))
def rig_crash(f: Facts) -> Verdict:
    """Raises unconditionally. The engine must convert this to POLICY_ERROR
    naming only the exception type, never the message."""
    raise ValueError("deliberate crash for the evidence corpus")


@policy("rig_allow_companion", tools=("rig_crash",))
def rig_allow_companion(f: Facts) -> Verdict:
    """Permits everything on the crashing tool, so the rig_crash case also
    proves that one denial defeats a standing permit."""
    return Allow()


@policy("rig_illegal_allow", tools=("rig_illegal_allow",), permits=False)
def rig_illegal_allow(f: Facts) -> Verdict:
    """Violates its permits=False contract by returning Allow."""
    return Allow()


@policy("rig_non_verdict", tools=("rig_non_verdict",))
def rig_non_verdict(f: Facts) -> Verdict:
    """Returns a bare string instead of a Verdict. The cast exists to smuggle
    the wrong type past mypy, because being wrong is this policy's job."""
    return cast(Verdict, "approved")


@policy("rig_undeclared", tools=("rig_undeclared",))
def rig_undeclared(f: Facts) -> Verdict:
    """Reads a fact outside its (empty) needs; UndeclaredFact must become a
    POLICY_ERROR denial, never an escaping exception."""
    _ = f[_RIG_PHANTOM]
    return Allow()


def build_rigged_gate() -> Gate:
    """No tool universe and no normalizers: coverage checks are beside the
    point here, and every needs list is empty by design."""
    return Gate(
        policies=[rig_crash, rig_allow_companion, rig_illegal_allow, rig_non_verdict, rig_undeclared],
        normalizers=[],
    )


def build_rigged_gate_reversed() -> Gate:
    """Reverse-order twin of the rigged gate, for the same byte-identity check."""
    return Gate(
        policies=[rig_undeclared, rig_non_verdict, rig_illegal_allow, rig_allow_companion, rig_crash],
        normalizers=[],
    )
