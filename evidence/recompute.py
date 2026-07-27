"""Replay the evidence corpus through the real gate and write results.json.

Offline, stdlib only, no install step: run `python3 evidence/recompute.py`
from a clone. Every published number in this repo comes out of this script;
none is typed by hand.

What one run does:

1. Builds the worked example gate and the rigged POLICY_ERROR gate from
   policies.py, each twice, the second time with policies and normalizers
   registered in reverse order.
2. Decides every case in corpus.jsonl and adversarial.jsonl and compares
   the decision against the case's expectation: allowed flag, the set of
   DenyKinds, and the set of denying policies.
3. Confirms the reversed-registration gate produced a byte-identical
   record body for every case, and the same policyset fingerprint.
4. Greps every emitted record body, envelope line, refusal message, and
   refusal tool-result payload for the planted sentinel secrets. Raw
   argument values must never appear in any of them.
5. Writes results.json: outcome and DenyKind counts, an expected-versus-
   actual confusion view, and the headline safety number, the count of
   adversarial calls that were allowed. That count must be zero; a single
   adversarial allow fails the run loudly and exits nonzero.

results.json is deterministic (no timestamps, no ids, sorted keys), so a
re-run that changes nothing produces a byte-identical file, and a re-run
that changes anything shows up in the diff.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import _path  # noqa: F401
from policies import (
    build_gate,
    build_gate_reversed,
    build_rigged_gate,
    build_rigged_gate_reversed,
)

from toolwarden import Decision, DenyKind, Gate

_HERE = Path(__file__).resolve().parent

SENTINEL = "ZX9-CANARY"

# A fixed timestamp for envelope rendering: the envelope is scanned for
# secret leakage, and using a constant keeps this script free of wall-clock
# input, per the corpus determinism rule.
FIXED_TS = "1970-01-01T00:00:00+00:00"


def load_cases(path: Path) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                cases.append(json.loads(line))
    return cases


def decide_case(gate: Gate, entry: dict[str, Any]) -> Decision:
    return gate.decide(
        tool=entry["tool"],
        args=entry["args"],
        principal=entry["principal"],
    )


def actual_view(decision: Decision) -> dict[str, Any]:
    return {
        "allowed": decision.allowed,
        "kinds": sorted({d.kind.value for d in decision.denials}),
        "denied_by": sorted({d.policy for d in decision.denials}),
    }


def sentinel_occurrences(decision: Decision) -> int:
    texts = [decision.record(), decision.record_line(ts=FIXED_TS)]
    if decision.denials:
        refusal = decision.refusal()
        texts.append(refusal.message())
        texts.append(refusal.to_tool_result())
    return sum(text.count(SENTINEL) for text in texts)


def main() -> int:
    corpus = load_cases(_HERE / "corpus.jsonl")
    adversarial = load_cases(_HERE / "adversarial.jsonl")
    cases = corpus + adversarial

    gates: dict[str, tuple[Gate, Gate]] = {
        "main": (build_gate(), build_gate_reversed()),
        "rigged": (build_rigged_gate(), build_rigged_gate_reversed()),
    }
    for name, (fwd, rev) in gates.items():
        if fwd.policyset_sha256 != rev.policyset_sha256:
            print(f"FAILURE: {name} gate fingerprint depends on registration order",
                  file=sys.stderr)
            return 1

    mismatches: list[dict[str, Any]] = []
    adversarial_allowed_ids: list[str] = []
    confusion = Counter[str]()
    headline_kinds = Counter[str]()
    denial_kinds = Counter[str]()
    denials_by_policy = Counter[str]()
    permits_by_policy = Counter[str]()
    outcomes = Counter[str]()
    order_mismatches: list[str] = []
    secret_leaks = 0

    for entry in cases:
        fwd, rev = gates[entry["gate"]]
        decision = decide_case(fwd, entry)
        actual = actual_view(decision)
        expect = entry["expect"]

        for field in ("allowed", "kinds", "denied_by"):
            if actual[field] != expect[field]:
                mismatches.append({
                    "id": entry["id"],
                    "field": field,
                    "expected": expect[field],
                    "actual": actual[field],
                })

        expected_word = "allow" if expect["allowed"] else "deny"
        actual_word = "allow" if decision.allowed else "deny"
        confusion[f"expected_{expected_word}__actual_{actual_word}"] += 1
        outcomes[actual_word] += 1

        if entry["set"] == "adversarial" and decision.allowed:
            adversarial_allowed_ids.append(entry["id"])

        if decision.outcome is not None:
            headline_kinds[decision.outcome.kind.value] += 1
        for denial in decision.denials:
            denial_kinds[denial.kind.value] += 1
            denials_by_policy[denial.policy] += 1
        for permit in decision.permits:
            permits_by_policy[permit] += 1

        secret_leaks += sentinel_occurrences(decision)

        # Order independence on real corpus traffic: same call, same policy
        # set, reversed registration, byte-identical record body.
        if decide_case(rev, entry).record() != decision.record():
            order_mismatches.append(entry["id"])

    all_kinds = sorted(kind.value for kind in DenyKind)
    kinds_covered = sorted(k for k in all_kinds if headline_kinds.get(k, 0) > 0)
    kinds_missing = sorted(k for k in all_kinds if headline_kinds.get(k, 0) == 0)

    checks = {
        "expectation_mismatches_empty": not mismatches,
        "adversarial_allowed_zero": not adversarial_allowed_ids,
        "secret_leaks_zero": secret_leaks == 0,
        "order_independent_records": not order_mismatches,
        "all_deny_kinds_covered": not kinds_missing,
    }

    results: dict[str, Any] = {
        "headline": {
            "adversarial_total": len(adversarial),
            "adversarial_allowed": len(adversarial_allowed_ids),
            "adversarial_allowed_ids": sorted(adversarial_allowed_ids),
        },
        "totals": {
            "cases": len(cases),
            "corpus": len(corpus),
            "adversarial": len(adversarial),
            "allowed": outcomes.get("allow", 0),
            "denied": outcomes.get("deny", 0),
        },
        "confusion": {
            "expected_allow__actual_allow": confusion.get("expected_allow__actual_allow", 0),
            "expected_allow__actual_deny": confusion.get("expected_allow__actual_deny", 0),
            "expected_deny__actual_allow": confusion.get("expected_deny__actual_allow", 0),
            "expected_deny__actual_deny": confusion.get("expected_deny__actual_deny", 0),
        },
        "expectation_mismatches": mismatches,
        "headline_kind_counts": dict(sorted(headline_kinds.items())),
        "denial_kind_counts": dict(sorted(denial_kinds.items())),
        "deny_kinds_covered": kinds_covered,
        "deny_kinds_missing": kinds_missing,
        "denials_by_policy": dict(sorted(denials_by_policy.items())),
        "permits_by_policy": dict(sorted(permits_by_policy.items())),
        "secret_leak_occurrences": secret_leaks,
        "record_body_mismatches_across_registration_orders": len(order_mismatches),
        "policyset_sha256_main": gates["main"][0].policyset_sha256,
        "policyset_sha256_rigged": gates["rigged"][0].policyset_sha256,
        "checks": checks,
        "checks_passed": all(checks.values()),
    }

    out = _HERE / "results.json"
    out.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"cases: {len(cases)} ({len(corpus)} corpus, {len(adversarial)} adversarial)")
    print(f"allowed: {results['totals']['allowed']}  denied: {results['totals']['denied']}")
    print(f"headline kinds: {results['headline_kind_counts']}")
    print(f"adversarial allowed: {len(adversarial_allowed_ids)} (must be 0)")
    print(f"secret leak occurrences: {secret_leaks} (must be 0)")
    print(f"record mismatches across registration orders: {len(order_mismatches)} (must be 0)")
    print(f"expectation mismatches: {len(mismatches)}")
    print(f"results written to {out}")

    if not results["checks_passed"]:
        failed = sorted(name for name, ok in checks.items() if not ok)
        print(f"CORPUS FAILURE: {', '.join(failed)}", file=sys.stderr)
        if adversarial_allowed_ids:
            print("ADVERSARIAL CALLS ALLOWED: " + ", ".join(sorted(adversarial_allowed_ids)),
                  file=sys.stderr)
        for mismatch in mismatches:
            print(f"  mismatch {mismatch['id']}.{mismatch['field']}: "
                  f"expected {mismatch['expected']}, got {mismatch['actual']}",
                  file=sys.stderr)
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
