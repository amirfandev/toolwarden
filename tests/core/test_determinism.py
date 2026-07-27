"""Determinism: registration order, rebuilds, and Python versions cannot
move a byte.

Three claims, in increasing strength:

  1. Shuffled registration orders of the same declarations produce
     byte-identical record bodies (seeded permutations, count fixed here).
  2. A reconstructed gate with an equal policyset_sha256 replays the
     identical body and record_sha256, which is the replay-verification
     story the audit design rests on.
  3. The bodies match a committed golden file, so a byte drift between
     Python versions or across an accidental behavior change fails CI
     instead of passing quietly. The golden file is regenerated only by
     tests/core/gen_golden.py, deliberately.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from example_policies import ALL_CASES, NORMALIZERS, POLICIES, Case, build_gate
from toolwarden import Gate
from toolwarden.audit import record_sha256

GOLDEN = Path(__file__).resolve().parent / "data" / "records.golden.jsonl"

# Fixed permutation budget: 6! * 5! orderings exist; twenty seeded samples
# plus identity and full reversal keep the test fast while still varying
# every relative order many times over.
PERMUTATION_COUNT = 20
SEED = 1337


def _permuted_gates() -> list[Gate]:
    rng = random.Random(SEED)
    gates = [build_gate()]
    gates.append(
        Gate(
            list(reversed(POLICIES)),
            list(reversed(NORMALIZERS)),
            tools=("db_exec", "send_email", "issue_refund", "send_fax"),
        )
    )
    for _ in range(PERMUTATION_COUNT):
        policies = list(POLICIES)
        normalizers = list(NORMALIZERS)
        rng.shuffle(policies)
        rng.shuffle(normalizers)
        gates.append(
            Gate(
                policies,
                normalizers,
                tools=("db_exec", "send_email", "issue_refund", "send_fax"),
            )
        )
    return gates


def _decide(gate: Gate, case: Case) -> str:
    return gate.decide(
        tool=case.call.tool, args=case.call.args, principal=case.call.principal
    ).record()


def test_policyset_sha256_identical_across_registration_orders() -> None:
    digests = {gate.policyset_sha256 for gate in _permuted_gates()}
    assert len(digests) == 1


def test_record_bodies_identical_across_registration_orders() -> None:
    gates = _permuted_gates()
    for case in ALL_CASES:
        bodies = {_decide(gate, case) for gate in gates}
        assert len(bodies) == 1, f"{case.name}: registration order moved a byte"


def test_reconstructed_gate_replays_identical_bytes() -> None:
    first = build_gate()
    second = build_gate()
    assert first.policyset_sha256 == second.policyset_sha256
    for case in ALL_CASES:
        body_a = _decide(first, case)
        body_b = _decide(second, case)
        assert body_a == body_b
        assert record_sha256(body_a) == record_sha256(body_b)


@pytest.mark.skipif(not GOLDEN.exists(), reason="golden file not generated yet")
def test_record_bodies_match_committed_golden() -> None:
    golden = {
        entry["name"]: entry["body"]
        for entry in map(json.loads, GOLDEN.read_text().splitlines())
    }
    gate = build_gate()
    assert set(golden) == {case.name for case in ALL_CASES}
    for case in ALL_CASES:
        assert _decide(gate, case) == golden[case.name], (
            f"{case.name}: record body drifted from the committed golden; "
            "if the change is deliberate, rerun tests/core/gen_golden.py"
        )


def test_golden_file_exists() -> None:
    """The golden comparison must never silently vanish from the suite."""
    assert GOLDEN.exists(), "run tests/core/gen_golden.py and commit the output"


def test_policyset_sha256_moves_when_the_policy_set_changes() -> None:
    full = build_gate()
    fewer = Gate(list(POLICIES[:-1]), list(NORMALIZERS))
    assert full.policyset_sha256 != fewer.policyset_sha256


def test_policyset_sha256_moves_when_a_normalizer_changes() -> None:
    """A normalizer edit changes decisions, so the fingerprint must move
    even with every policy untouched."""
    from collections.abc import Mapping
    from typing import Any

    from toolwarden.facts import FactKey
    from toolwarden.normalize import normalizer
    from toolwarden.normalizers import SQL_CLASS, SqlClass
    from toolwarden.types import ToolCall

    @normalizer("classify_sql", tools=("db_exec",), provides=(SQL_CLASS,))
    def classify_sql(call: ToolCall) -> Mapping[FactKey[Any], object]:
        return {SQL_CLASS: SqlClass.READ}  # a lax edit: everything is a read

    doctored = Gate(
        list(POLICIES), [classify_sql, *NORMALIZERS[1:]]
    )
    assert doctored.policyset_sha256 != build_gate().policyset_sha256
