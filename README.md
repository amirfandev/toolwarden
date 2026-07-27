# toolwarden

[![CI](https://github.com/amirfandev/toolwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/amirfandev/toolwarden/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/toolwarden?cacheSeconds=3600)](https://pypi.org/project/toolwarden/)
[![Python](https://img.shields.io/pypi/pyversions/toolwarden?cacheSeconds=3600)](https://pypi.org/project/toolwarden/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A deterministic gate between an LLM agent and its tools. Every tool call is
checked against policy before it executes and is allowed or denied by code
that returns the same answer every time, not by a model. Every decision is
logged for audit. Zero dependencies, Python 3.11+.

The failure it prevents: an agent told "read-only on prod" or "never email
outside the company" violates that instruction, and the call goes through,
because those sentences are suggestions to a language model and nothing
deterministic stands between the agent and the tool. toolwarden is that
deterministic thing.

## Install

```
pip install toolwarden
```

The core, the shipped normalizers, and the Claude Code hook are stdlib only.
Framework adapters live behind extras: `toolwarden[openai-agents]`,
`toolwarden[langchain]`, `toolwarden[anthropic]`.

## Quickstart

```python
from toolwarden import (
    Gate, policy, Deny, Allow, NOT_APPLICABLE, Facts, Verdict, ToolDenied,
)
from toolwarden.normalizers import (
    SQL_CLASS, SqlClass, classify_sql,
    RECIPIENT_DOMAINS, recipient_domains,
)

COMPANY = "ourcompany.com"

@policy("prod_db_read_only", tools=("db_exec",), needs=(SQL_CLASS,), permits=False)
def prod_db_read_only(f: Facts) -> Verdict:
    if f.principal.get("env") != "production":
        return NOT_APPLICABLE
    if f[SQL_CLASS] is not SqlClass.READ:      # WRITE and UNKNOWN both land here
        return Deny("statement is not a provable read against the production database")
    return NOT_APPLICABLE                      # the permit comes from db_read_scope

@policy("db_read_scope", tools=("db_exec",), needs=(SQL_CLASS,))
def db_read_scope(f: Facts) -> Verdict:
    if f[SQL_CLASS] is SqlClass.READ:
        return Allow()
    return NOT_APPLICABLE

@policy("internal_email_only", tools=("send_email",), needs=(RECIPIENT_DOMAINS,))
def internal_email_only(f: Facts) -> Verdict:
    external = f[RECIPIENT_DOMAINS] - {COMPANY}
    if external:
        return Deny(f"recipient domain(s) outside {COMPANY}: "
                    f"{', '.join(sorted(external))}")
    return Allow()

def db_exec(query: str) -> list[dict]: ...
def send_email(to: list[str], subject: str, body: str) -> str: ...

gate = Gate(
    policies=[prod_db_read_only, db_read_scope, internal_email_only],
    normalizers=[classify_sql, recipient_domains],
    tools=("db_exec", "send_email"),
)

guarded = gate.wrap(
    {"db_exec": db_exec, "send_email": send_email},
    principal={"env": "production", "agent": "support-bot"},
)

rows = guarded["db_exec"](query="SELECT id FROM orders WHERE id = 42")   # allowed

try:
    guarded["db_exec"](query="DELETE FROM orders")                       # denied
except ToolDenied as e:
    print(e.refusal.message())
```

An allow requires zero denials and at least one explicit permit. A tool no
policy names is denied. A policy that raises denies itself. Registration
order cannot influence any byte of any output.

## The safety invariant

A bad input must never become an allow. The mechanism is a three-state fact
model:

- **Computed**: a normalizer turned a raw argument into a typed value.
  "Absent but fine" is a value too (an empty tuple, `SqlClass.UNKNOWN`).
- **Unavailable**: the normalizer could not trust the input, or raised. This
  is a value, not an exception. Any policy that needs that fact is denied by
  the engine (kind `unparseable`) before its body runs.
- **Undeclared**: the policy never declared the fact, or no normalizer
  provides it for that tool. The gate refuses to construct.

Policy bodies therefore run only on facts that computed. There is no code
path from "could not parse" to "allowed", and none of the paths depend on a
policy author remembering to check anything.

The shipped normalizers carry their own adversarial hardening: the SQL
classifier lexes string literals and comments in a single left-to-right
pass, so a write keyword hidden by comment tricks or quote tricks either
surfaces as WRITE or degrades to UNKNOWN, both denied by a read-only
policy; the email normalizer accepts only single-`@` addresses and compares
the whole domain after that `@`, so `evil@sub.ourcompany.com.attacker.com`
resolves to `attacker.com`'s domain, not yours, and a multi-`@` address is
refused outright rather than split; the amount normalizer rejects bools, NaN,
and infinities before any cap comparison can be sweet-talked.

## Audit records

Facts are loggable, raw arguments are not. Each decision renders a
byte-stable canonical JSON body: the computed facts, the fact errors, every
policy's verdict, every denial with its reason, and shape summaries of the
arguments (type, length, truncated digest) instead of their values.
Timestamps and ids live only in the envelope, so a stored line can be
verified against a replayed decision. The `policyset_sha256` fingerprint
moves whenever a policy's or normalizer's own source or declaration changes,
because a normalizer edit changes decisions as surely as a policy edit does.
It digests each body's literal text, not state that text references (a
closure variable or a module-level constant), so keep behavior-affecting
values inside the body if you rely on the fingerprint to track them.

## Attach points

- `gate.wrap(tools, principal=...)` guards plain callables, sync or async,
  binding arguments through the tool's own signature.
- `toolwarden.adapters.openai_agents.toolwarden_guardrail` for the OpenAI
  Agents SDK, with `assert_all_guarded` to turn unguarded tools into a boot
  failure.
- `toolwarden.adapters.anthropic_loop.run_tool_uses` executes the tool_use
  blocks of an Anthropic message under the gate.
- `toolwarden.adapters.langchain.toolwarden_tool_wrapper` for LangChain's
  `wrap_tool_call` middleware hook.
- `toolwarden-hook`, a Claude Code PreToolUse hook that tightens, never
  loosens, and converts its own crashes into explicit denies.

The denied model always receives the same payload: which policies denied,
every reason, and a decision id that joins the transcript to the audit line.

## Evidence

Every number below is produced by one offline command, stdlib only, no
install step:

```
python3 evidence/recompute.py
```

From the current committed run (`evidence/results.json`): 61 cases, of
which 34 are adversarial evasion attempts (comment-split, comment-quote, and
MySQL executable-comment SQL, the backtick and dollar-quote paired-phantom
attacks, the PostgreSQL `#` operator, stacked statements, the domain suffix
attack, string-not-list PHI tags, bool and Infinity amounts, malformed and
ungoverned calls).
Adversarial calls allowed: 0. Planted secret values leaked into any record,
envelope, or refusal: 0. Record-body mismatches across reversed
registration orders: 0. All six denial kinds are exercised.

## What v0.1 does not do

No stateful facts (rate limits, per-day spend), no MCP proxy, no output
governance, no Cedar export. The healthcare angle is one worked policy
(`phi_minimum_necessary`); the full pack is v0.2. Decisions and rejected
alternatives are recorded in `docs/DESIGN.md`.

## License

MIT.
