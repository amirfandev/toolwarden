# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-27

First release.

### Added

- `Gate` engine: deny by default, order-independent evaluation, any deny
  defeats all permits, and an allow requires at least one explicit permit.
  Registration order of policies and normalizers cannot influence any byte of
  any output.
- Three-state fact model. A fact is Computed, Unavailable, or Undeclared:
  a normalizer failure is a value rather than an escaping exception, an
  Unavailable fact a policy needs makes the engine deny before the policy body
  runs, and an undeclared fact refuses at `Gate` construction. There is no
  path from unparseable input to an allow.
- `policy` and `normalizer` decorators with typed fact access through
  `FactKey[T]`, so mypy infers fact types in policy bodies without casts.
- Denial taxonomy with fixed headline precedence: `malformed_call`,
  `unparseable`, `policy_forbade`, `policy_error`, `no_permit`, `ungoverned`.
  A buggy policy silences only itself, and its silence is a deny.
- Coverage report naming ungoverned, forbid-only, and phantom tools; enforced
  at construction under strict mode and re-checked at every wrap boundary.
- Canonical audit record: facts are loggable, raw args never are. Arg shape
  summaries with digests stand in for values, the body is byte-stable
  canonical JSON, and timestamps and ids live only in the envelope so a
  stored line can be verified against a replayed decision.
- `Gate.wrap()` with signature binding, sync and async guards, per-call
  principal sources, and a choice of raising `ToolDenied` or returning the
  `Refusal`.
- Shipped normalizers: SQL statement classification, recipient email domains,
  USD amounts, PHI field tags, and fax numbers. Each returns Unavailable on
  input it cannot trust.
- Adapters for the OpenAI Agents SDK, the Anthropic tool-use loop, and
  LangChain middleware, each behind its own extra and lazy-importing its
  framework; the deny payload is byte-identical across all of them.
- Claude Code PreToolUse hook (`toolwarden-hook`): tightens only, never
  loosens, and converts its own crashes into explicit denies.
- Worked example policies with mandatory allow/deny case matrices, including
  `phi_minimum_necessary` as the healthcare taste of the v0.2 pack.
- Offline evidence corpus, adversarial evasion set, and replay script under
  `evidence/`; the only source of any number published in the README.
- `py.typed` marker and `docs/DESIGN.md` recording decisions and rejected
  alternatives.

[Unreleased]: https://github.com/amirfandev/toolwarden/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/amirfandev/toolwarden/releases/tag/v0.1.0
