# Design decisions

Decisions made for v0.1, each with the alternative that lost and why. The
implementation specification is the contract; this file records where
judgment was exercised, so a future reader can tell a choice from an
accident.

## Python-native engine, not Cedar

A Cedar policy set was prototyped alongside the Python one. Cedar buys a
formally analyzable policy language and pays for it with a runtime
dependency, a schema layer between facts and policies, and a second
language for operators to learn. v0.1 needs custom normalizers (SQL
classification is not expressible in Cedar) next to its policies, in one
language, testable with pytest. The reversal path is a `.cedar` exporter,
deliberately zero code now; it becomes worth building only if the
Python-native decision is falsified by real policy sets outgrowing
function-per-rule.

## `FactKey[T]` mapping access, not dataclass attributes

`f[SQL_CLASS]` instead of `f.sql_class`. A dataclass of facts is closed: a
v0.2 healthcare pack could not add facts without editing core. Keys minted
in any module keep the fact set open while `Facts.__getitem__`, generic
over `FactKey[T]`, keeps mypy inference exact with zero casts. The price is
bracket syntax. A typo'd key is a construction-time error (coverage
checking), not a silent fallthrough.

## Three states, no `wants`

A fact is Computed, Unavailable, or Undeclared. Policies declare `needs`;
an Unavailable needed fact is an engine-level deny before the body runs.
The earlier design also had `wants` (fact-or-Unavailable passed into the
body) and `Facts.get`. Both were cut: no shipped policy used them, and they
reopen the exact mishandling path `needs` closes, a body that receives a
failure value and forgets to treat it as one. Reinstated only when a real
policy demonstrably needs to branch on "could not compute".

## Policy bugs become POLICY_ERROR denials, not exceptions

An exception escaping `decide()` propagates into host dispatch code, where
a blanket `except` can swallow it and continue, which is fail-open. So a
raising body, an undeclared fact read, a non-Verdict return, and a
`permits=False` policy returning `Allow` all convert to
`Denial(POLICY_ERROR, ...)`. A buggy policy silences only itself and its
silence is a deny. The falsifier: deployments running for weeks with
nonzero POLICY_ERROR counts nobody notices. Watch the kind counters.

## The SQL classifier lexes in one pass, deviating from the spec

Spec section 5 specifies the prototype's order: strip string literals, then
block comments, then line comments, as independent regex substitutions.
That ordering is a demonstrated fail-open: a quote inside a comment opened
a phantom string literal that swallowed a write keyword between two
comments, so `SELECT 1 /*'*/ ; DELETE FROM users /*'*/` classified as a
provable read and was allowed in production. The reverse ordering has the
mirror-image hole for `--` or `/*` inside a real literal. No sequence of
whole-text passes over three interacting lexical layers is sound, so
`_strip_sql_noise` consumes strings and comments left to right, in the
order they actually open, the way a SQL lexer does. It models three
quote-delimited spans, `'...'`, `"..."`, and MySQL backtick identifiers
`` `...` ``, and two comment forms, `--` and `/* */`. Backticks are modeled
rather than passed through so a `'` inside a quoted identifier stays inert;
otherwise two such quotes pair into a phantom literal that swallows a write
between them (`` SELECT 1 AS `a'b`; DELETE FROM users; SELECT 2 AS `c'd` ``).
`#` is deliberately NOT a comment: it is a line comment in MySQL but the
integer bitwise-XOR operator in PostgreSQL, so blanking a `#` line would hide
a real write after the operator (`SELECT 5 # 3; DELETE FROM users`). Passed
through as an ordinary character, a write after `#` stays visible and a stray
quote after `#` runs a literal off the end; both deny. The MySQL executable
comment `/*! ... */` is the mirror hazard: MySQL runs its contents while
every other engine treats it as inert, so blanking it (as a plain `/* */` is
blanked) would classify `SELECT 1 /*! DELETE FROM t */` as a read. Its
interior is therefore scanned as code, marker and version-gate digits
skipped, so the write inside is visible; a version-gated read stays a read.

Three backstops make the class safe beyond the constructs enumerated. A
visible write keyword outranks everything, so a real write is never
downgraded. Any construct that runs off the end unterminated forces UNKNOWN,
because the lexer then cannot prove what it swallowed was not a write. And any
character left in the stripped code outside the modeled read grammar, a
dollar sign, a bracket, any dialect quote or comment introducer this lexer
does not parse, also forces UNKNOWN: such a character could reinterpret a
quote the scanner already resolved. The last two together close the family of
"unrecognized construct reinterprets a quote" holes, the paired-phantom
variants included, because an unmodeled introducer either runs a literal off
the end or survives into the stripped code as a non-grammar character. This is
the one place v0.1 knowingly implements against the spec's letter, because the
spec's own invariant (a bad input must never become an allow) outranks its
description of the mechanism. The prototype's "0 mismatches over 21 cases"
measurement stands but its corpus contained no comment-embedded quote; the
class is now pinned by unit tests and four adversarial corpus cases (`--`,
`/* */`, the spaced block variant, and the MySQL `#` variant).

## Digest honesty

Audit records summarize string arguments as type, length, and a truncated
unsalted sha256 prefix. For low-entropy values (a short subject line, a
known-format account id) that digest is brute-forceable offline, and the
recorded length narrows the guessing space further. v0.1 states this
tradeoff instead of hiding it: the digests exist to correlate and verify,
not to protect a value from a determined reader of the log. The recorded
future option is a per-deployment keyed digest, which turns the log's
digests into MACs at the cost of a key to manage.

## Byte-stable record body, envelope-only timestamps

Timestamps and decision ids never enter the record body; they live in the
`record_line` envelope beside a sha256 of the body. A reviewer verifies the
body digest and trusts the envelope. This makes replay exact: the
determinism suite reproduces committed bodies byte for byte across
registration orders and Python versions.

## Layout deviations from the spec's module listing

Behavior-neutral renames, recorded so nobody mistakes them for drift:

- `record.py` is `audit.py`; `wrap.py` is a re-export shim over
  `boundary.py`. The spec's import surface (section 1) is unaffected.
- The `normalizers/` package is a single `normalizers.py` module; five
  normalizers do not need four files.
- `evidence/run.py` is `evidence/recompute.py` (the Makefile's `evidence`
  target and `evidence/README.md` both point there).
- The golden record file lives at `tests/core/data/records.golden.jsonl`,
  next to the only test that reads it.
- `loader.py` with a public `load_gate` was not built: it is absent from
  the section 1 API, the hook builds its gate internally, and evidence
  replay imports its policy module directly. It becomes worth extracting
  when a second consumer with the hook's exact loading needs appears.
- The six worked policies appear three times on purpose: in
  `examples/policies.py` (the copy a reader adapts, run by
  `examples/demo.py`), in `evidence/policies.py` (the replayed gate, which
  also carries the rigged POLICY_ERROR set), and in
  `tests/example_policies.py` (the case-matrix fixture). Each site has a
  different job and a different blast radius when edited; sharing one
  module across them would couple the published evidence to example
  refactors.

## Candidate v0.2 items

`wants` and `Facts.get`; `FactKey.check` runtime validation of normalizer
output types; keyed digests; a hook daemon (per-event interpreter start is
accepted for v0.1); a lint tying body fact reads to `needs` declarations
and flagging raw-argument interpolation into deny reasons; the HIPAA/ADHICS
policy pack; an MCP proxy attach point.
