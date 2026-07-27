"""The six worked policies, the set a reader is meant to copy and adapt.

Two things to notice before copying:

First, permits are explicit. `prod_db_read_only` is a forbid-only policy
(permits=False): it can veto but never authorize, so a production read
still needs `db_read_scope` to say yes. Denying is not the same as
declining to permit, and the engine holds a permits=False policy to that
contract at runtime.

Second, policies judge facts, not raw arguments. Every rule below reads a
typed fact a shipped normalizer computed (`f[SQL_CLASS]`, not
`call.args["query"]`), which is what makes "the query could not be parsed"
a deny instead of a crash or a shrug.

The healthcare taste for v0.1 is exactly one policy, `phi_minimum_necessary`,
plus its permitting counterpart on the fax tool. The full HIPAA/ADHICS pack
is v0.2.

This module is importable on its own; `demo.py` next to it wires the gate
and runs calls through it. The same six policies are replayed against the
labelled corpus by `evidence/recompute.py` and pinned by the case matrices
in `tests/example_policies.py`.
"""

from __future__ import annotations

from toolwarden import (
    NOT_APPLICABLE,
    Allow,
    Deny,
    Facts,
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


ALL_POLICIES = (
    prod_db_read_only,
    db_read_scope,
    internal_email_only,
    spend_cap,
    phi_minimum_necessary,
    fax_covered_entity,
)
