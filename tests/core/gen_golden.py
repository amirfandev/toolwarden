"""Regenerate the committed golden record bodies for test_determinism.py.

Run manually after a deliberate change to the example policies, the shipped
normalizers, or the record format:

    python tests/core/gen_golden.py

The golden file is the committed expectation that record bodies are
byte-stable across runs, registration orders, and Python versions; the test
never writes it, only this script does, so a drift is a failure instead of
a silent refresh.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_TESTS = Path(__file__).resolve().parent.parent
for _entry in (str(_TESTS.parent / "src"), str(_TESTS)):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)

GOLDEN = Path(__file__).resolve().parent / "data" / "records.golden.jsonl"


def generate() -> str:
    from example_policies import ALL_CASES, build_gate

    gate = build_gate()
    lines = []
    for case in ALL_CASES:
        decision = gate.decide(
            tool=case.call.tool, args=case.call.args, principal=case.call.principal
        )
        lines.append(json.dumps({"name": case.name, "body": decision.record()}))
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN.write_text(generate(), encoding="utf-8")
    print(f"wrote {GOLDEN}")
