"""Runnable end-to-end demo: the six worked policies guarding fake tools.

    python3 examples/demo.py

Stdlib only, no install step: run from a clone and it finds the checked-out
source. It builds the gate from `policies.py`, wraps two pretend tools, and
walks the paths that matter: an allowed read, a denied production write
(including the comment-quote evasion the classifier lexes through), a
denied external email, a PHI email kept internal, and an unparseable input
that the engine denies before any policy body runs. Every decision, allow
and deny, is printed as its audit envelope line at the end.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
for _entry in (str(_REPO / "src"), str(_REPO / "examples")):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)

from policies import ALL_POLICIES, TOOL_UNIVERSE  # noqa: E402

from toolwarden import Decision, Gate, ToolCall, ToolDenied  # noqa: E402
from toolwarden.normalizers import (  # noqa: E402
    classify_sql,
    fax_number,
    phi_fields,
    recipient_domains,
    usd_amount,
)


def db_exec(query: str) -> list[dict[str, object]]:
    """Stand-in for a real database call."""
    return [{"id": 42, "status": "shipped"}]


def send_email(to: list[str], subject: str = "", body: str = "", **kwargs: object) -> str:
    """Stand-in for a real mail gateway."""
    return f"queued for {len(to)} recipient(s)"


def issue_refund(amount_usd: float, order: str = "") -> str:
    return f"refunded {amount_usd:.2f} USD"


def charge(amount_usd: float, customer: str = "") -> str:
    return f"charged {amount_usd:.2f} USD"


def send_fax(fax_number: str, document: str = "", **kwargs: object) -> str:
    return f"faxed {document!r}"


AUDIT_LINES: list[str] = []


def sink(call: ToolCall, decision: Decision) -> None:
    ts = datetime.now(UTC).isoformat()
    AUDIT_LINES.append(decision.record_line(ts=ts))


def main() -> int:
    gate = Gate(
        policies=list(ALL_POLICIES),
        normalizers=[classify_sql, recipient_domains, usd_amount, phi_fields, fax_number],
        tools=TOOL_UNIVERSE,
        on_decision=sink,
    )
    print(f"gate constructed, policyset {gate.policyset_sha256}\n")

    # Wrapping re-runs coverage against exactly these names: leave one out
    # and a strict gate refuses to wrap rather than let a policy bind to
    # nothing.
    guarded = gate.wrap(
        {
            "db_exec": db_exec,
            "send_email": send_email,
            "issue_refund": issue_refund,
            "charge": charge,
            "send_fax": send_fax,
        },
        principal={"agent": "support-bot", "env": "production"},
    )

    calls: list[tuple[str, str, dict[str, object]]] = [
        ("read in production", "db_exec",
         {"query": "SELECT id, status FROM orders WHERE id = 42"}),
        ("write in production", "db_exec",
         {"query": "DELETE FROM orders"}),
        ("comment-quote evasion", "db_exec",
         {"query": "SELECT 1 /*'*/ ; DELETE FROM orders /*'*/"}),
        ("email to a colleague", "send_email",
         {"to": ["alice@ourcompany.com"], "subject": "standup", "body": "moved to 10"}),
        ("email to an outsider", "send_email",
         {"to": ["contact@gmail.com"], "subject": "hi", "body": "the numbers"}),
        ("PHI kept internal", "send_email",
         {"to": ["dr.rahim@ourcompany.com"], "body": "labs attached",
          "phi_fields": ["lab_results"]}),
        ("unparseable recipient list", "send_email",
         {"to": "not-a-list", "body": "hi"}),
        ("refund under the cap", "issue_refund",
         {"amount_usd": 120.0, "order": "A-1001"}),
        ("refund over the cap", "issue_refund",
         {"amount_usd": 750.0, "order": "A-1002"}),
        ("PHI fax to an unknown number", "send_fax",
         {"fax_number": "+15559998888", "document": "chart.pdf",
          "phi_fields": ["patient_name"]}),
    ]

    for label, tool, args in calls:
        try:
            result = guarded[tool](**args)
            print(f"ALLOWED {label}: {result!r}")
        except ToolDenied as exc:
            print(f"DENIED  {label}:")
            print(f"        {exc.refusal.message()}")
        print()

    print(f"--- audit trail ({len(AUDIT_LINES)} decisions, allow and deny alike) ---")
    for line in AUDIT_LINES:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
