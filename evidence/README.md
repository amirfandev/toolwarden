# Evidence

Every number this repo publishes about its own behavior comes from one
command, run offline, stdlib only, no install step and no key:

```
python3 evidence/recompute.py
```

It replays the committed corpus (`corpus.jsonl`, `adversarial.jsonl`)
through the worked policy gate in `policies.py`, checks every case against
its labelled expectation, and writes `results.json`. The corpus files are
themselves regenerable, deterministically, with:

```
python3 evidence/make_corpus.py
```

Both scripts are byte-stable: rerunning either on any supported Python
(3.11 through 3.14 were verified) reproduces the committed files exactly.

## What a passing run proves

- The headline safety number: zero adversarial calls allowed. The
  adversarial set is the evasion catalogue of spec section 12: SQL comment
  evasion, stacked and case-mangled writes, the domain suffix attack, the
  string-not-list PHI tag (the prototype's real bug), malformed recipients,
  bool and Infinity amounts, and boundary probing with malformed and
  ungoverned calls. One adversarial allow fails the run and exits nonzero.
- Every case's decision matches its label: allowed flag, the set of
  DenyKinds, and the set of denying policies. Every one of the six
  DenyKinds is exercised, and every policy appears on both its allow and
  its deny side.
- Order independence: every decision's record body is byte-identical when
  the same policies and normalizers are registered in reverse order.
- Redaction: sentinel secrets planted in the arguments of every case never
  appear in any record body, envelope line, refusal message, or refusal
  tool-result payload.

`results.json` carries the counts (per outcome, per DenyKind, per policy),
the expected-versus-actual confusion view, and a `checks` block naming each
of the assertions above. It contains no timestamps and no ids, so it diffs
cleanly and a re-run that changes nothing changes no bytes.

The false-positive guard (a write keyword inside a string literal, which
must be ALLOWED as a read) lives in `corpus.jsonl` with an expected allow;
the adversarial file holds only expected denies so that "zero adversarial
allows" stays a statement about the whole file.
