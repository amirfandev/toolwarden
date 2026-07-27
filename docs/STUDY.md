# toolwarden: the owner's study guide

This document teaches the system to the person who owns it. It is written to
be read start to finish in one sitting, with the code open in a second
window. By the end you should be able to defend every design decision in a
technical interview, extend the library without breaking its invariants, and
say plainly what it does not do.

The library is small on purpose: a stdlib-only core, about a dozen modules,
one intellectual move at its center. That move, the three-state fact model,
is covered in section 3, and everything before it exists to make the problem
it solves concrete. Everything after it is the machinery that carries the
move to a real boundary: an engine, an audit trail, a wrapping layer, three
framework adapters, and one hook.

---

## 1. The problem: a model cannot be its own gate

Give an LLM agent a database tool and the instruction "read-only on
production", and you have not built a control. You have written a sentence.
That sentence sits in the model's context alongside every other piece of
text the model sees, including text an attacker may control: retrieved
documents, tool results, user messages. The model weighs it, usually obeys
it, and sometimes does not. Prompt injection can override it. A long session
can push it out of effective attention. Plain sampling variance can walk
past it. When any of that happens, the model emits `db_exec` with a DELETE
in it, and unless something deterministic stands between the emitted call
and the tool, the call executes.

Prompt-level guardrails do not close this. A guardrail that is itself a
model (a judge screening tool calls, a system-prompt rule, a classifier
scoring intent) has the same two defects as the agent it guards: its inputs
are attacker-influenced text, and its decision function is soft. It can be
argued with, because arguing with it is just more text. And it returns
different answers on different days, which means you cannot audit it: a
decision you cannot reproduce is a decision you cannot review.

The fix has a specific shape. Enforcement must be out of band: it runs in
the host process, between the model's emitted tool call and the tool's
execution, in code the model cannot address. The model controls the
arguments of a call; it must control nothing else. And enforcement must be
deterministic: the same call against the same policy set returns the same
answer and the same audit bytes, every time, so a stored decision can be
replayed and verified.

This position is nearly unoccupied. The great majority of agent deployments
today run with no deterministic enforcement on tool calls at all; the rules
live in prompts, which is the gap this library was built for. (Industry
surveys put a number on it, commonly cited around three quarters, but treat
the shape of the claim as the load-bearing part, not any one figure.) The
nearest existing product is AWS AgentCore Policy, which is Cedar-based,
proprietary, and tied to the AWS cloud. No Python library sits in the open-source
position: a policy gate you `pip install`, wire between any agent framework
and its tools, and test with pytest. toolwarden is that library. Zero
dependencies in the core, Python 3.11+, every decision logged.

---

## 2. The shape of the solution

Four ideas, in dependency order:

**The gate.** A `Gate` holds a set of policies and a set of normalizers.
Its one interesting method is `decide(tool=, args=, principal=)`, which
returns a `Decision`. `decide` never raises for any input; every failure
mode is a denial inside the returned decision. Around `decide` sit the
attach points: `gate.wrap()` for plain callables, three adapters for
frameworks, and a Claude Code hook.

**Policies as pure predicates over facts.** A policy is a named, declared
rule: which tools it governs (`tools`), which facts it needs (`needs`),
whether it may permit (`permits`), and a body that is a pure function from
`Facts` to a closed `Verdict` type: `Allow`, `Deny(reason)`, or the
`NOT_APPLICABLE` singleton. Nothing else. Policies do not parse strings, do
not touch raw arguments in the shipped set (beyond the host-supplied
principal), and do not know about each other.

**The engine as a for-loop.** `decide` validates the call's shape, routes
to the policies that declared the tool, runs the normalizers that declared
the tool, evaluates each governed policy once, and aggregates: any denial
defeats every permit; an allow requires zero denials and at least one
explicit permit; a tool nothing governs is denied. That is the whole
evaluator. It fits on a screen and it is deliberately boring.

**The normalization layer, which is the actual product.** The evaluator is
trivial because all the danger was moved out of it. The hard part of
gating an LLM's tool calls is not boolean aggregation; it is deciding what
a hostile string *is*. Is this SQL a read? Is this address internal? Is
this amount a number? Normalizers are the only code in the package that
reads raw model-controlled arguments, and they convert them into typed
facts or into an explicit failure value. Every adversarial case in the
evidence corpus attacks a normalizer, not the engine, because the engine
has no surface to attack. When you extend this library, you will spend your
time in normalizers, and that is by design: correctness lives in the facts.

One consequence worth internalizing early: because the engine collects all
verdicts before aggregating, and canonically sorts every output list, the
registration order of policies and normalizers cannot influence any byte of
any output. This is tested by shuffling registration across seeded
permutations and byte-comparing record bodies
(`tests/core/test_determinism.py`), and re-proven on the committed corpus
by `evidence/recompute.py`.

---

## 3. The three-state fact model

This is the point of the whole library. Take it slowly.

A fact that a policy asks about is in exactly one of three states, and the
states cannot be merged:

| State | Meaning | What happens |
|---|---|---|
| **Computed** | A normalizer produced a value | The policy body sees the typed value |
| **Unavailable** | The normalizer could not trust the input, or raised | The engine denies (`UNPARSEABLE`) on the policy's behalf; the body never runs |
| **Undeclared** | The policy never declared the fact, or no normalizer provides it for the tool | `Gate(...)` refuses to construct; a runtime read raises `UndeclaredFact`, converted to a `POLICY_ERROR` denial |

Two clarifications that matter more than the table:

**"Absent but fine" is Computed, not Unavailable.** When `phi_fields` is
missing from the arguments entirely, the fact computes to `()`: genuinely
untagged is an answer. When `classify_sql` cannot prove what a string is,
the fact computes to `SqlClass.UNKNOWN`: "unprovable" is an answer too, and
a production write policy judges that answer and denies it. `Unavailable`
is reserved for a different situation: the input could not be trusted
enough to answer at all. A `query` that is a dict instead of a string is
not "unknown SQL"; it is not SQL, and pretending otherwise would launder a
structural problem into an in-band value. The distinction is spelled out in
the docstring of `src/toolwarden/normalizers.py` and it is load-bearing:
both paths end in a deny for a production write policy, but by different
mechanisms, and neither depends on the policy author checking anything.

**Unavailable is a value, never an exception.** It is a frozen dataclass,
`Unavailable(fact, reason)`, and it travels inside the normalizer's result
mapping like any other value. Nothing raises across the decide boundary.
The reason string is written for a compliance reader, because it lands
verbatim in the audit record.

### Typed access: `FactKey[T]`

Fact identity is a name; fact typing is a phantom. From
`src/toolwarden/facts.py`:

```python
@dataclass(frozen=True)
class FactKey(Generic[T]):
    """A typed name for one fact. `T` is phantom: it exists only for mypy."""
    name: str
```

`SQL_CLASS` is declared as `FactKey[SqlClass]`, and `Facts.__getitem__` is
generic over the key:

```python
def __getitem__(self, key: FactKey[T]) -> T:
    if key.name not in self._needs:
        raise UndeclaredFact(key.name)
    value = self._computed[key.name]
    if isinstance(value, Unavailable):
        raise TypeError(
            f"engine invariant violated: fact {key.name!r} is Unavailable "
            "inside a policy body"
        )
    return cast(T, value)
```

So `f[SQL_CLASS]` infers as `SqlClass` under mypy strict with zero casts in
policy code. The alternative, a dataclass of facts with `f.sql_class`, was
rejected in `docs/DESIGN.md` because it is closed: a v0.2 healthcare pack
could not add facts without editing core. Keys minted in any module keep
the fact set open; the price is bracket syntax.

Notice what the method does *not* have: a `.get` with a failure-shaped
return, or a `T | Unavailable` return type. By the time a body holds a
`Facts` view, the engine has already proven every declared fact is
Computed. The `isinstance` check is a tripwire for an engine bug, not a
code path, and if it ever fired, the raise would escape the body and become
a `POLICY_ERROR` denial: even the tripwire fails closed.

### Why a bad input cannot become an allow

This is the argument you must be able to reproduce cold. Enumerate every
path a bad input can take through `decide`:

1. **The call itself is structurally broken** (tool is not a non-empty
   string, args or principal not a mapping). Boundary validation denies
   `MALFORMED_CALL` before anything else runs.
2. **No policy declares the tool.** A single `UNGOVERNED` denial. Default
   deny is the engine's floor, not a policy someone wrote.
3. **A normalizer answers with an in-band fail-safe value** like
   `SqlClass.UNKNOWN`. The body runs, judges the value, and the shipped
   write-restricting policy denies anything that is not provably a read.
4. **A normalizer returns Unavailable**, or **raises** (the batch contract
   converts a raise into Unavailable for every fact the normalizer
   promised). Every policy that declared that fact in `needs` is denied
   `UNPARSEABLE` by the engine, and its body is never called.
5. **The policy body itself misbehaves**: raises, reads an undeclared
   fact, returns something that is not a `Verdict`, or returns `Allow`
   under `permits=False`. Each becomes a `POLICY_ERROR` denial. A buggy
   policy silences only itself, and its silence is a deny.
6. **Everything computed, nothing denied, nothing permitted.** A single
   `NO_PERMIT` denial: abstention never accumulates into an allow.

Every path terminates in a denial. The only route to an allow runs through
a policy body that executed on fully Computed, fully declared facts and
returned `Allow` from a `permits=True` policy, with zero denials anywhere
in the decision.

Now state the inversion, because it is the whole trick. In a conventional
design, the policy author must remember to handle "could not parse": the
body receives a None, a sentinel, an exception, and if the author forgets a
check, the malformed input flows into the happy path and the call is
allowed. Fail-open is one forgotten `if` away, forever. In toolwarden, the
policy that would have mishandled the bad input **never executes**. There
is no code that runs on an untrusted value, so there is no code path to get
wrong. Fail-open requires code to run; the gate removes the run.

The design once had an escape hatch, `wants`, which passed
fact-or-Unavailable into the body for policies that wanted to branch on
failure themselves. It was cut before v0.1 (`docs/DESIGN.md`, "Three
states, no `wants`"): no shipped policy used it, and it reopens exactly the
mishandling path `needs` closes. It comes back only when a real policy
demonstrably needs to branch on "could not compute".

The invariant is not just argued; it is tested as a proof shape.
`tests/core/test_safety_invariant.py` builds, for every hostile input to
every shipped normalizer, a gate containing exactly one maximally hostile
policy: one that returns `Allow()` unconditionally. If the body ever ran,
the call would be allowed. The assertions are that the call is denied
`UNPARSEABLE`, and that a side-effect flag proves the body never executed.
That is the invariant itself, not a proxy for it.

---

## 4. A guided tour of the code

Module by module, in dependency order. For each: what it holds, and the one
thing you would not guess from the name.

**`types.py`** holds `ToolCall`, the three verdicts (`Allow`, `Deny`,
`NotApplicable` with its `NOT_APPLICABLE` singleton), and the closed
`Verdict` alias. The non-obvious part: `Allow` and `Deny` carry no policy
name. The engine attributes every verdict to the policy whose body produced
it, so a policy cannot speak on another policy's behalf and a copy-pasted
body cannot smuggle a stale name into the audit trail. `NotApplicable`
overrides `__new__` to be a true singleton, so identity comparison works
and no second, unequal instance can exist.

**`denial.py`** holds `DenyKind`, `Denial(kind, policy, reason)`, and the
sort helpers. The non-obvious part: `DenyKind` declaration order *is*
headline precedence. `_KIND_PRECEDENCE` is derived from the enum by
enumeration rather than written twice, so adding a kind cannot leave the
table stale. `denial_sort_key` sorts by `(kind precedence, policy, reason)`,
which makes the headline outcome a pure function of the denial set,
whatever order denials were collected in.

**`facts.py`** holds `FactKey`, `Unavailable`, and `Facts` (section 3).
One extra detail: `Facts` uses `__slots__` and its `computed` mapping is
built by the engine restricted to the policy's `needs`, so a body cannot
even see facts that were computed for other policies; an out-of-needs read
raises `UndeclaredFact` before the lookup.

**`errors.py`** holds the four operator-side exceptions: `UndeclaredFact`,
`UncoveredFact`, `CoverageError`, `GateConfigError`. The non-obvious part
is the boundary discipline stated in its docstring: none of these can reach
a caller of `decide()`. Three abort construction, so a gate that would
raise them refuses to exist; `UndeclaredFact` escapes a policy body only to
be caught by the engine and converted to a denial. Bad configuration is
loud at startup, a bad policy is a deny at runtime, and neither is ever an
allow.

**`policy.py`** holds the frozen `Policy` record and the `@policy`
decorator, which returns a `Policy` object, not a function. Validation
lives in `Policy.__post_init__` so hand-built instances face the same
checks as decorated ones. Two details worth remembering: the name
`"engine"` is reserved (a policy carrying it could forge engine authorship
in the audit trail), and `tools`/`needs` are rejected as bare strings
before tuple conversion, because `tuple("db_exec")` silently becomes seven
one-letter tool names and every downstream check would then pass vacuously.

**`normalize.py`** holds `Normalizer`, `@normalizer`, and the batch
contract enforcer, `run_normalizers` / `_run_batch`. The contract, which
the engine applies around every normalizer run:

1. A normalizer runs iff `call.tool` is in its declared tools. The
   declaration is the routing; no sniffing args to guess relevance.
2. Its returned mapping must cover exactly its `provides`. An omitted
   promised key becomes `Unavailable`; a key outside `provides` poisons the
   *whole batch* to `Unavailable`, because a normalizer confused about its
   own output cannot be trusted about any of it.
3. If it raises, every declared key becomes `Unavailable`. A normalizer
   bug is indistinguishable from hostile input, which is the correct
   paranoia.
4. Graceful failure is returned, not raised, with a reason written for a
   compliance reader.

The non-obvious part: key inspection happens *inside* the try block. A
hostile or buggy `Mapping` subclass can raise during iteration, and a
`FactKey` subclass can raise from its `name` attribute; both are operator
code and get no benefit of the doubt. An escape here would abort the
decision instead of denying it, which is exactly the fail-open path the
module exists to close.

**`normalizers.py`** holds the five shipped fact producers and their keys:
`classify_sql` (`SQL_CLASS`), `recipient_domains` (`RECIPIENT_DOMAINS`),
`usd_amount` (`AMOUNT_USD`), `phi_fields` (`PHI_FIELDS`), `fax_number`
(`FAX_NUMBER`). Section 6 walks the two security-critical ones. Of the
other three: `usd_amount` rejects bool before the numeric check because a
Python bool *is* an int (`True` would become 1.00 USD and sail under any
cap), rejects non-finite floats because NaN compares False against every
cap (turning `amount > cap` denial logic into an allow), and catches
`OverflowError` from `float(10**400)`. `phi_fields` computes `()` when the
tag is absent and `Unavailable` when the tag is present but malformed; that
split is the fix, at the type level, for a real bug in the prototype, which
mapped `phi_fields="patient_ssn"` (a string, not a list) to the same empty
tuple as "no PHI" and allowed the send. `fax_number` deliberately does no
format normalization: allow-list policies compare exact strings, and a
lenient rewrite would widen what an allow-list entry matches without the
policy author seeing it happen.

**`engine.py`** holds `Gate` and `Decision`. Construction runs every check
that can be run before the first call: duplicate policy or normalizer
names; two distinct `FactKey` objects sharing a name (checked by identity,
`is`, because equal-by-name keys are precisely the hazard); every
(policy, fact, tool) triple covered by a provider (`UncoveredFact`
otherwise); no two normalizers providing the same fact for the same tool;
and, when `tools=` names the universe, coverage findings (raise under
`strict=True`, print to stderr otherwise). `decide` is section 5. Three
details: a `_MISSING` sentinel distinguishes "no fact table entry at all"
from any real value, defense in depth behind the construction-time coverage
check; every decision from every path exits through `_finish`, so the
canonical sorts and the `on_decision` sink cannot be skipped by a new code
path forgetting them; and `decision_id` is minted per decision but excluded
from the record body, for reasons covered in section 7.

**`coverage.py`** holds `audit_coverage`, `ToolCoverage`, and
`CoverageReport`, with three findings: `ungoverned` (no policy names the
tool), `forbid_only` (only `permits=False` policies name it), and `phantom`
(a policy names a tool outside the universe). The non-obvious part:
forbid-only is *worse* than ungoverned, because it looks like coverage.
Someone wrote forbid rules and believes the tool is handled, yet every call
dies `NO_PERMIT`. Coverage adds nothing to enforcement, only timing: every
finding is a runtime deny surfaced at setup, when the operator is looking.

**`audit.py`** holds the canonical record machinery: `_canonical_dumps`
(the one pinned serialization every record byte passes through),
`_digest12` (truncated sha256, the in-record fingerprint), `record_sha256`
(full-length, for envelope verification), `_render_value`, `_arg_summary`,
`render_record`, `render_record_line`, and `policyset_sha256`. The
non-obvious part: `_render_value` maps any unrecognized object to its type
name in angle brackets, never its repr, because reprs can embed both memory
addresses (nondeterminism) and raw values (leaks); and sets sort by each
element's canonical JSON rather than natural order, because a mixed-type
set need not be mutually comparable and the sort must never raise inside
record rendering.

**`refusal.py`** holds `Refusal` and `ToolDenied`. A refusal carries the
tool, the denials, and the `decision_id`; never facts or args, because the
refusal travels into model context and the redaction rule applies doubly to
a channel the model will quote back. `to_tool_result()` uses the same
pinned serialization flags as the audit record, so one denied call reads
byte-identically in a guardrail rejection, an errored `tool_result` block,
a middleware `ToolMessage`, and a raised `ToolDenied`.

**`boundary.py`** (re-exported by the shim `wrap.py`, which exists so the
spec's layout and `Gate.wrap`'s lazy import resolve to one implementation)
holds `wrap_tools` and the guard builder. The guard binds every call
through `inspect.signature(fn).bind(*args, **kwargs)` with defaults
applied, so the gate judges the named-argument view the tool would actually
execute; a call that will not bind is a `MALFORMED_CALL` denial, not a
TypeError. On allow, the guard calls `fn(*args, **kwargs)` with the very
objects it judged: nothing runs between decide and dispatch in-process. The
genuinely non-obvious part is the `**kwargs` flattening in `judge`:
`bound.arguments` nests extra keywords in a dict under the parameter's
name, and a normalizer looking for `phi_fields` cannot see
`kwargs["phi_fields"]`. Leaving the nest in place would let a tool's
signature shape hide a governed argument from policy while still delivering
it to the tool, so the guard flattens the VAR_KEYWORD dict back into the
top-level view before deciding.

**`adapters/`** exposes three factories lazily through a package-level
`__getattr__`, so `import toolwarden` and the whole core test suite run
with no framework installed. Each adapter states an honest guarantee in its
docstring. `openai_agents.toolwarden_guardrail` returns a
`ToolInputGuardrail` that blocks before execution for every `FunctionTool`
it is attached to; attachment is per-tool opt-in, so `assert_all_guarded`
turns a forgotten attachment into a boot failure, checking guard membership
by object identity. It judges the model's raw pre-coercion argument JSON,
and unparseable JSON becomes `gate.deny_malformed` with a reason that names
the failure, never the payload. `anthropic_loop.run_tool_uses` is the
strongest of the three because it *is* the dispatcher: `block.input` is
exactly what the gate judges and exactly what `fn(**args)` receives. It is
stdlib-only (blocks are read duck-typed), synchronous only (a tool
returning a coroutine gets the coroutine closed and an errored result
naming the mismatch), and it distinguishes three non-allow shapes: a policy
denial, a host configuration bug (policy allowed a tool the host never
provided), and a tool's own exception. `langchain.toolwarden_tool_wrapper`
returns the two-argument handler for LangChain 1.x's `wrap_tool_call`
middleware hook; on deny it short-circuits with a `ToolMessage` whose
content is the refusal payload and whose status is `"error"`. All three
read the principal from host state only; there is no code path from tool
arguments to it.

**`hook.py`** is the Claude Code PreToolUse hook, console script
`toolwarden-hook`, one process per event: Claude Code writes a JSON event
to stdin, the script answers on stdout with either nothing or an explicit
deny. Three fixed decisions. Tighten only, never loosen: on a gate allow
the script emits no permission decision, deferring to Claude Code's own
permission system, because emitting "allow" would silently bypass host
prompts. Governed subset: the config declares which tool names the gate
governs; outside the subset the hook stays silent, and inside it full
engine semantics apply, including default deny. Fail closed by
construction: Claude Code treats a nonzero non-2 exit as "hook errored,
continue", which fails open, so `main` catches everything, prints an
explicit deny naming only the exception type, and exits 0. Two smaller
choices with the same spine: argument parsing is by hand because argparse
answers a bad flag with `SystemExit(2)`, and exit code 2 is the host's
"blocking error" channel; and a failed audit-log append raises, which
`main` converts to a deny, because a host that cannot log is a host that
should stop.

---

## 5. Engine semantics and the denial taxonomy

`Gate.decide` executes a fixed seven-step sequence, stated once in the
module docstring of `engine.py` and worth memorizing:

1. **Boundary validation.** Non-string or empty tool, non-mapping args or
   principal: one `MALFORMED_CALL` denial, nothing else runs. The stored
   call is sanitized by type name, never repr, because a malformed payload
   may still hold secrets.
2. **Routing.** Governed policies are exactly those declaring the tool.
   None: one `UNGOVERNED` denial. A policy body never sees a call for a
   tool it did not declare.
3. **Normalization.** Every normalizer declaring the tool runs under the
   batch contract, yielding the fact table.
4. **Evaluation.** Per governed policy, exactly one trail entry. A needed
   Unavailable fact: `UNPARSEABLE` on the policy's behalf, body skipped
   (the reason lists every broken fact, names sorted, so even the reason
   string is canonical). `Deny(reason)`: `POLICY_FORBADE`. `Allow` from
   `permits=True`: a permit. `Allow` from `permits=False`, any escaping
   exception, or a non-Verdict return: `POLICY_ERROR`.
5. **Aggregation.** Any denial defeats all permits. Allowed iff zero
   denials and at least one permit. Governed, no denial, no permit: one
   `NO_PERMIT` denial.
6. **Canonical ordering.** Denials sorted by (kind precedence, policy,
   reason); permits and trail by policy name. The headline `outcome` is
   the first denial of the sorted set: a pure function of the denial set,
   never "first encountered".
7. **Sink.** `on_decision` fires on every decision, allow and deny. If the
   sink raises, the exception propagates: a host that cannot log is a host
   that should stop. This is the one deliberate exception to "decide never
   raises".

Two semantic choices deserve their own paragraph.

**Every policy sees every call it governs, and every denial is reported.**
The engine does not short-circuit at the first denial. Three reasons.
Order-independence: stopping early would make the reported denial depend on
evaluation order, and nothing in this engine is allowed to depend on order.
Audit completeness: a compliance reviewer asking "which rules did this call
violate" deserves the full set, not whichever fired first. And operations:
when a call trips both `internal_email_only` and `phi_minimum_necessary`,
fixing one and re-running should not reveal the other as a surprise. The
headline is then recovered deterministically by sorting.

**Permits are capabilities, declared up front.** `permits=False` exists
because a forbid rule and a permit rule have different blast radii when
buggy. A forbid rule that accidentally returns `Allow` would silently widen
access; declaring `permits=False` closes that path, and the engine converts
the illegal `Allow` into a `POLICY_ERROR` denial. The flag also feeds the
coverage report, which can then distinguish a tool that merely has forbid
rules from a tool something can actually permit.

### The six kinds, each with a concrete case

All six appear in the committed evidence corpus; the examples below are
real corpus entries.

- **`MALFORMED_CALL`**: the call itself is structurally wrong. Corpus:
  tool name `42`; tool name `""`; `args` null. Also produced at
  boundaries: a `wrap()` invocation that will not bind to the tool's
  signature, or argument JSON in the OpenAI adapter that will not parse.
  Attribution: `"engine"`.
- **`UNPARSEABLE`**: a fact a policy needs could not be computed. Corpus:
  `query={"$gt": ""}` denies both `prod_db_read_only` and `db_read_scope`
  before either body runs; `amount_usd=true`; `to="a@ourcompany.com"` (a
  string, not a list). Attribution: the policy whose declared needs broke,
  even though the engine minted the denial; the reason carries the
  normalizer's own words. This is fail-closed made visible and countable.
- **`POLICY_FORBADE`**: the fact computed fine and the rule said no.
  Corpus: `DELETE FROM orders` in production. The only kind that means the
  policy worked as intended against a real violation.
- **`POLICY_ERROR`**: the policy itself misbehaved. The rigged evidence
  gate commits each violation once: a body that raises, a `permits=False`
  policy returning `Allow`, a body returning the string `"approved"`, and
  a body reading an undeclared fact. A bug report, not a violation report,
  hence a different kind with a different owner.
- **`NO_PERMIT`**: policies govern the tool, none denied, none permitted.
  Corpus: `DELETE FROM scratch_table` in staging: `prod_db_read_only`
  abstains (not production), `db_read_scope` abstains (not a read), and
  silence is not consent.
- **`UNGOVERNED`**: no policy names the tool. Corpus: `exfiltrate_db`.
  The runtime twin of the coverage report's ungoverned list; nonzero
  counts on a strict gate mean someone bypassed strict mode.

Precedence runs in the order listed: from "the call itself was broken" down
to "nothing governs this tool", so the headline always names the earliest
failure in the pipeline, which is the one an operator must fix first.

---

## 6. The two security-critical normalizers

### `classify_sql`: one lexer pass, three answers

The classifier's contract is deliberately modest: return `READ` only for a
string that is provably a read, `WRITE` for anything with a visible write
keyword, `UNKNOWN` otherwise. The write-restricting policy treats `WRITE`
and `UNKNOWN` identically, so the classifier's only dangerous failure mode
is calling something `READ` that is not.

The interesting function is `_strip_sql_noise`, which blanks string
literals and comments before any keyword scan. Why blank them at all?
Because both false positives and false negatives live there:
`SELECT 'please UPDATE your records'` must stay a read (the write keyword
is data), and `DELETE FROM t -- just checking` must stay a write (the
comment does not disarm it).

Why a single left-to-right pass instead of layered regex substitutions?
Because the three lexical layers interact. A SQL engine opens whichever
construct appears first, and everything inside it is inert until it closes.
The prototype in `.spike/python/gate.py` stripped strings across the whole
text, then comments, as independent regex passes, and that ordering is a
demonstrated fail-open: in

```sql
SELECT 1 /*'*/ ; DELETE FROM users /*'*/
```

the quote *inside* the first comment opened a phantom string literal that
ran to the quote inside the second comment, swallowing the `DELETE`
between them. The prototype classified this as a provable read. The
mirror ordering (comments first) has the mirror hole: a `--` or `/*`
inside a real literal, as in `SELECT '--' FROM t; DROP TABLE t`, would
swallow real code. No sequence of whole-text passes over three
interacting layers is sound. The prototype's "0 mismatches over 21 cases"
measurement was honest but its corpus contained no comment-embedded
quote, which is why measurement missed it; `docs/DESIGN.md` records this
as the one place v0.1 knowingly implements against the spec's letter,
because the spec's own invariant outranks its description of the
mechanism.

So `_strip_sql_noise` consumes constructs where they actually open, the
way a SQL lexer does. Walking the loop in
`src/toolwarden/normalizers.py`:

- On `'`, `"`, or `` ` ``: consume to the matching close delimiter, treating
  a doubled delimiter as an escape (`'it''s fine'` is one literal). If no
  close delimiter exists, the span runs to end of input and the
  `unterminated` flag is set. The construct is replaced by a single space.
  Backticks (MySQL quoted identifiers) are modeled here, not passed through,
  because a `'` inside a backtick identifier would otherwise open a phantom
  literal; with two backtick identifiers the phantom pairs up and closes
  cleanly, swallowing a write between them
  (`` SELECT 1 AS `a'b`; DELETE FROM users; SELECT 2 AS `c'd` ``). Modeled,
  the identifier's contents are inert and the `DELETE` stays visible, so the
  input classifies `WRITE`.
- On `--`: consume to end of line.
- On `/*`: consume to `*/`; if it never closes, run to end of input and
  set `unterminated`.
- Anything else, `#` included, copy through. `#` is a line comment in MySQL
  but the integer bitwise-XOR operator in PostgreSQL, so treating it as a
  comment would blank a real write after a `#` operator
  (`SELECT 5 # 3; DELETE FROM users`, where the `DELETE` executes on
  PostgreSQL). Copied through, a write after `#` stays visible (`WRITE`) and a
  stray quote after `#` runs a literal off the end (`unterminated`); both
  deny. Corpus case `a30`, `SELECT 1 # '\nINSERT INTO t VALUES(1)`, is denied
  by the `unterminated` route: the `'` after `#` opens a literal that never
  closes.
- After the pass, any character surviving in the stripped code that is
  outside the modeled read grammar (a `$`, a bracket, any dialect quote or
  comment introducer this lexer does not parse) sets the `unmodeled` flag.

The result type says which field matters:

```python
@dataclass(frozen=True)
class _StripResult:
    text: str
    unterminated: bool
    unmodeled: bool
```

`unterminated` and `unmodeled` are the security-critical fields. Then
`_classify_sql` applies its rules in a fixed order:

```python
if any(t in _WRITE_KEYWORDS for t in tokens):
    return SqlClass.WRITE                        # a visible write outranks all
if stripped.unterminated or stripped.unmodeled:
    return SqlClass.UNKNOWN                       # cannot prove a clean read
if not tokens:
    return SqlClass.UNKNOWN
if tokens[0] in _READ_STARTERS:    # SELECT, WITH, EXPLAIN, SHOW, VALUES
    return SqlClass.READ
return SqlClass.UNKNOWN
```

The three backstops close whole families of holes, not just the named tests.
A visible write keyword is definitive even before an unterminated tail
(`DELETE FROM t WHERE note = 'unterminated` is `WRITE`): a real write is
never downgraded. Any construct that runs off the end unterminated forces
`UNKNOWN`: when a literal never closes, the lexer swallowed everything after
the opening quote, and whatever it hid, a write keyword included, is invisible
to the keyword scan. And any character left in the stripped code outside the
modeled read grammar forces `UNKNOWN` too: such a character is a construct the
lexer does not parse, a dialect quote or comment introducer that could
reinterpret a `'` or `"` the scanner already resolved. Together the last two
close the class of "unrecognized construct reinterprets a quote" attacks,
paired-phantom variants included: an unmodeled introducer either leaves a
literal open (caught by `unterminated`) or its own sigil survives into the
stripped code (caught by `unmodeled`). The paired-phantom that motivated
`unmodeled`, `` SELECT $$a'b$$; DELETE FROM users; SELECT $$c'd$$ ``, closes a
phantom literal cleanly yet leaves the `$` sigils in the stripped text, so it
denies rather than reading as a hidden `DELETE`.

Attacks it defeats, with corpus and test cases behind each: the
comment-quote attack in both block and line form (`a27`, `a28`, `a29`);
the MySQL `#` variant (`a30`); comment-split keywords (`DR/**/OP TABLE x`
tokenizes to `DR`, `OP`: `UNKNOWN`, denied); stacked statements
(`SELECT * FROM t; DROP TABLE t`: write keyword anywhere wins); case
mangling (`DeLeTe`); a real write whose literal contains a read keyword
(`UPDATE accounts SET note = 'read only: SELECT'` is `WRITE`); and the
false-positive guard, a read whose literal contains a write keyword, which
must stay an allow so the classifier is useful and not merely paranoid.

The construct to carry into an interview is the MySQL executable comment,
because it is the case that forced a special rule. `/*! ... */` is run by a
MySQL server while every other engine treats it as an inert comment, so
blanking it (as an ordinary `/* ... */` is blanked) would classify
`SELECT 1 /*! DELETE FROM t */` as `READ` and allow a DELETE. The lexer
therefore does not blank a `/*!` opener: it skips the marker and any version
gate digits (`/*!50000`) and scans the interior as code, exactly as the
server runs it, so the `DELETE` becomes visible and the statement is `WRITE`.
A version-gated read (`/*!40001 SQL_NO_CACHE */ SELECT 1`) stays a read. This
was a fail-open until it was closed; the fix is pinned by unit tests and
corpus case `a31`.

The other dialect directions are already safe by the two general backstops.
PostgreSQL dollar-quoting is caught by the `unmodeled` rule: the `$` sigil is
outside the modeled read grammar, so
`` SELECT $$a'b$$; DELETE FROM users; SELECT $$c'd$$ `` classifies `UNKNOWN`
and denies rather than reading as a hidden `DELETE`. Constructs that merely
confuse the lexer into surfacing extra tokens, say leaked contents of a
dialect it does not parse, at worst deny a benign call: annoying,
fail-closed. What remains genuinely uncovered is the residual family this one
special case represents: a construct that some engine executes while leaving
nothing in the stripped code for `unmodeled` to catch, if such a construct
exists beyond `/*!`. That residue is why `classify_sql` is documented as a
keyword classifier over a recognized grammar, not a parser (section 10): the
honest claim is "sound for the grammar it models, and closed against the
executing-comment case that motivated the model", not "sound against every
SQL dialect."

### `recipient_domains`: whole domains, poisoned wholes

The classic hole this normalizer exists to close is the suffix check.
`evil@sub.ourcompany.com.attacker.com` contains the substring
`ourcompany.com`, so any `endswith` or `in` test on the raw address passes
it, but the registrable domain is attacker-controlled. `_email_domain`
never does substring work:

```python
address = address.strip()
if address.count("@") != 1:
    return None
local, _, domain = address.partition("@")
domain = domain.lower()
if not local or not domain:
    return None
if domain.startswith(".") or domain.endswith(".") or ".." in domain:
    return None
if not re.fullmatch(r"[a-z0-9.-]+", domain):
    return None
return domain
```

The domain is everything after the `@`, extracted whole, lowercased, and
structurally vetted (exactly one `@`, non-empty local part, no leading or
trailing or doubled dots, a conservative character set). The policy then
compares whole domains as set members: `f[RECIPIENT_DOMAINS] -
{"ourcompany.com"}` is empty or it is not. Under that comparison the
attack address computes to `sub.ourcompany.com.attacker.com`, which is
simply not the company domain, and
`tests/core/test_normalizers.py::test_email_suffix_attack_never_resolves_to_the_company_domain`
pins exactly that. An address with two `@` signs is refused outright
rather than split at the final one: stricter than the "final @" framing,
and strictness here costs only a deny.

The batch-level rule matters as much as the parse: one unparseable
recipient poisons the whole fact to `Unavailable`, because partial trust is
no trust. A policy allowing "all domains internal" must never judge a list
from which the hostile entry was quietly dropped. And the Unavailable
reasons never echo the address, because a hostile or mistyped address is
exactly the value that must not land in the audit record or the
transcript.

---

## 7. The audit record and the redaction rule

The redaction rule, stated once and enforced in one module (`audit.py`):
**facts are loggable, args are not.** Facts are computed by
operator-registered normalizers and are, by construction, the minimum the
decision depended on. Raw arguments may hold PHI, credentials, or message
bodies, and they never enter the record. Arguments appear only as
top-level shape summaries: `{"type": "str", "len": 43, "sha256_12": ...}`
for strings, `{"type": "list", "len": 3}` for lists, `{"type": "dict",
"keys": [...]}` for dicts (key names are schema, not data; values are
absent), plus one truncated digest over the canonical JSON of the whole
mapping, enough to verify "same arguments" on replay without storing them.
`principal` is logged as-is by contract: it is host-supplied identity
metadata, never model-supplied content, and adapters own its construction
to keep that true.

A denied email's record body, in shape (real output is one line, keys
sorted, no whitespace):

```json
{
  "v": 1,
  "call": {
    "tool": "send_email",
    "principal": {"agent": "support-bot", "env": "production"},
    "args": {
      "to":         {"type": "list", "len": 1},
      "body":       {"type": "str", "len": 43, "sha256_12": "9f2ab..."},
      "phi_fields": {"type": "list", "len": 3}
    },
    "args_sha256": "1c44d..."
  },
  "facts": {"phi_field_names": ["dob", "lab_result", "name"],
            "recipient_domains": ["gmail.com"]},
  "fact_errors": {},
  "trail": [{"policy": "internal_email_only", "verdict": "deny"},
            {"policy": "phi_minimum_necessary", "verdict": "deny"}],
  "denials": [{"kind": "policy_forbade", "policy": "internal_email_only",
               "reason": "recipient domain(s) outside ourcompany.com: gmail.com"},
              {"kind": "policy_forbade", "policy": "phi_minimum_necessary",
               "reason": "PHI (dob, lab_result, name) addressed to non-covered-entity domain(s): gmail.com"}],
  "permits": [],
  "outcome": {"allowed": false, "kind": "policy_forbade",
              "policy": "internal_email_only", "reason": "..."},
  "policyset_sha256": "d32b022cc04a"
}
```

Byte-stability of `record()` rests on three legs, each enforced in exactly
one place. First, every list on `Decision` (denials, permits, trail) is
canonically sorted by the engine before the audit module sees it, so
registration order cannot influence a byte. Second, serialization is
pinned: `sort_keys=True`, `separators=(",", ":")`, `ensure_ascii=True`,
`allow_nan=False`, with `_render_value` mapping every non-JSON value
(enums by `.value`, frozensets as sorted lists, tuples as lists, non-finite
floats as their repr string, unknown objects as their type name) to a
deterministic form first. Third, everything nondeterministic is exiled to
the envelope: `record_line(ts=...)` wraps the body as
`{"ts", "id", "record_sha256", "record"}`, so the body itself contains no
timestamp and no id.

Why does byte-stability across registration order matter for a compliance
log? Because the log's trust story is replay verification. A reviewer
holding a stored line can re-serialize the embedded body with the same
pinned flags, recompute `record_sha256`, and confirm the envelope; or
rebuild the gate at the recorded `policyset_sha256` and re-decide the call,
expecting the identical bytes. Both checks are only meaningful if
irrelevant differences cannot move bytes. If reordering a Python list at
registration changed record output, every refactor would look like a
behavioral change in the audit trail, replay would need to reproduce
registration order (which nothing records), and byte comparison would be
useless as evidence. The determinism suite pins this with twenty seeded
registration shuffles plus full reversal, byte-compared against a
committed golden file that only `tests/core/gen_golden.py` may regenerate.

The `policyset_sha256` fingerprint, stamped on every decision, digests each
policy's name, tools, permits flag, sorted needs names, and *source text*
(via `inspect.getsource`), and each normalizer's declaration and source
text, both lists sorted by name. Normalizers are included because a
normalizer edit changes decisions just as surely as a policy edit does; a
fingerprint that ignored them would claim two behaviorally different gates
were the same gate. There is a test that doctors `classify_sql` into
"everything is a read" and asserts the fingerprint moves.

One piece of honesty the design carries on purpose (`docs/DESIGN.md`,
"Digest honesty"): the in-record 12-hex digests are truncated and unsalted,
so digests of low-entropy strings are brute-forceable offline, and recorded
lengths narrow guesses. They exist to correlate and verify, not to protect
a value from a determined reader of the log. The recorded future option is
a per-deployment keyed digest.

---

## 8. Running and extending

**Run it.**

```
pip install -e ".[dev]"
make check                     # ruff, mypy strict, pytest
python3 examples/demo.py       # end-to-end walk, prints audit lines
python3 evidence/recompute.py  # replays the corpus, rewrites results.json
```

`evidence/recompute.py` needs no install at all (`evidence/_path.py` puts
the checked-out `src/` on the path), and every number the README publishes
comes out of it: currently 61 cases, 34 adversarial, 0 adversarial allows,
0 sentinel leaks, 0 record-body mismatches across reversed registration
orders, all six DenyKinds exercised.

**Add a policy.** Import or mint the fact keys it needs, write the body
against `Facts`, declare everything in the decorator:

```python
@policy("spend_cap", tools=("issue_refund", "charge"), needs=(AMOUNT_USD,))
def spend_cap(f: Facts) -> Verdict:
    if f[AMOUNT_USD] > 500.0:
        return Deny(f"amount {f[AMOUNT_USD]:.2f} USD exceeds the 500 USD cap")
    return Allow()
```

Set `permits=False` if the rule should only ever veto. Write deny reasons
for two audiences at once, the transcript and the audit record: name the
rule and the observed fact, never raw argument values. Then write the case
matrix, which is mandatory: `tests/core/test_case_matrix.py` fails the
suite if a registered example policy has no matrix, if a permitting
policy's matrix has no allowed case, if no case exercises the deny branch
as `POLICY_FORBADE`, if any fact in `needs` lacks an `UNPARSEABLE` case
attributed to that policy, or if any `return` statement in the body never
executed across the matrix (proven with a `sys.settrace` line collector
over the fixture file, kept stdlib-only on purpose). The matrices live
next to the policies in `tests/example_policies.py`; the same shape feeds
`evidence/make_corpus.py`. If your change alters any record body, rerun
`tests/core/gen_golden.py` deliberately and commit the diff.

**Add a normalizer and a fact key.** Mint the key once, in one module, and
import it everywhere (`_check_fact_key_identity` aborts construction if two
distinct key objects share a name). Declare `tools` and `provides`; return
a mapping covering exactly `provides`; put `Unavailable(fact, reason)` in
the mapping for input you cannot trust, with a reason a compliance reviewer
can read; never echo raw values into reasons. Remember the two shapes of
failure: an in-band fail-safe value for "the input is the right type but
unprovable", `Unavailable` for "there is nothing here to compute". Cover
both in `tests/core/test_normalizers.py` (computed values) and
`tests/core/test_safety_invariant.py` (the Unavailable side, under the
eager-allow proof shape).

**Add an adapter.** Import the framework only inside the factory function,
so the module imports cleanly without it and the failure names the pip
extra (`tests/adapters/test_degradation.py` enforces this). Judge through
`gate.decide` or `gate.deny_malformed`, nothing else; the adapter must
contain no allow/deny logic of its own. Deliver
`decision.refusal().to_tool_result()` in the framework's native
"tool errored" channel so the payload stays byte-identical across
boundaries. Build the principal from host state only. Do not log
independently; the `on_decision` sink is the source of truth. Test against
stub objects reproducing the framework interface, as
`tests/adapters/adapter_stubs.py` does for the existing three.

---

## 9. Interview questions

Phrased as an interviewer would ask them. Answers are the ones the code
supports.

**1. Why write a policy engine in Python instead of adopting Cedar? Cedar
has formal analysis.**

Because the spike measured what Cedar would actually decide here, and the
answer was: almost nothing. Look at `.spike/cedar/normalize.py`: SQL
classification, email domain extraction, PHI tag walking, and float-to-cents
conversion all had to be computed in Python before Cedar saw the request,
because Cedar has no regex, no string parsing, and no floats. Cedar was left
evaluating a handful of equality and set-membership checks over facts
Python had already computed, so the correctness-critical code was Python
either way, and Cedar added a runtime dependency, a schema layer, and a
second language for operators. The formal analysis that justifies Cedar is
unreachable from Python anyway; the binding used in the spike, cedarpy, is
a community project, not an official one. And Cedar's failure mode points
the wrong way: a forbid rule that errors at evaluation (a typo'd attribute,
say `sql_clas`) is skipped, its error is a diagnostic, and a standing
permit still allows the call. A typo'd forbid fails open. In toolwarden the
analogous bug, a raising policy, is a `POLICY_ERROR` denial. The reversal
path is recorded in `docs/DESIGN.md`: a `.cedar` exporter, zero code today,
built only if real policy sets outgrow function-per-rule.

**2. How do you know a bad input can never become an allow?**

By exhausting the paths. A structurally broken call dies `MALFORMED_CALL`
at boundary validation. An ungoverned tool dies `UNGOVERNED`. A normalizer
that cannot trust the input returns `Unavailable`, and a normalizer that
raises is converted to `Unavailable` for every fact it promised; either
way, every policy needing that fact is denied `UNPARSEABLE` and its body
never runs, so no code executes on the untrusted value. A normalizer that
can answer but not prove returns an in-band fail-safe value like
`SqlClass.UNKNOWN`, which the write-restricting policy denies. A policy
that misbehaves denies itself as `POLICY_ERROR`. Pure abstention dies
`NO_PERMIT`. The only path to an allow runs through a body that executed
on fully Computed declared facts and returned `Allow` from a `permits=True`
policy with zero denials present. None of these paths depend on a policy
author remembering to check anything, and
`test_safety_invariant.py` proves the body-never-ran claim directly with an
unconditional-`Allow` policy as the hostile witness.

**3. Why report every denial instead of stopping at the first?**

Short-circuiting would make the reported denial a function of evaluation
order, and no output byte is allowed to depend on order; the headline is
instead the first element of the canonically sorted denial set, a pure
function of the set. Beyond determinism: the audit record should answer
"everything this call violated", and an operator fixing a call should see
all of it at once rather than one denial per retry. The cost is running
every governed policy on every call, which is trivial for pure predicates
over precomputed facts.

**4. What stops a tool from lying about what it did?**

Nothing. toolwarden is a gate, not a sandbox. It decides whether a call may
execute; it has no view of what the tool actually does with its process,
network, or filesystem, and no view of the result. A tool that ignores its
arguments, or a `db_exec` implementation that writes when handed a SELECT,
is outside the trust model: tools are host code, trusted like the rest of
the host. If you need containment of tool behavior, you need OS-level
sandboxing underneath this layer; the two compose, they do not substitute.

**5. Why is the principal never read from model output?**

Because the principal is the authority the policy judges against, and
authority that the governed party can write is not authority. The
enforcement is structural, not validation: `ToolCall.args` is the only
place model-controlled values land, and there is no code path from `args`
into `principal` anywhere in the package. `wrap()` takes the principal at
wrap time (a mapping copied once, or a zero-arg callable evaluated per
call); the OpenAI adapter reads it from the host's run context object,
which the model never sees; the hook reads it from a config file at an
operator-chosen absolute path plus `session_id` and `cwd` from the event
envelope, which Claude Code writes and the model does not. If a host's
principal callable returns garbage, boundary validation denies the call
`MALFORMED_CALL`; even that host bug fails closed.

**6. What does this not protect against?**

Anything you did not write a policy for: the gate's floor is default deny
per tool, but only over the tools it stands in front of, and only the
hook's governed subset in hook form. Tool behavior after an allow (see
question 4). Output flows: it governs calls, not results, so a permitted
read can return data a later permitted call exfiltrates within policy.
Dialect constructs the SQL lexer does not model (question 17). A human
with control of the host: an agent that can rewrite the hook's config or
`settings.json` can un-govern itself, which is why the hook docs ship the
idea of a self-protection policy over those paths and state the bound
plainly: it defends against the model, not against the machine's owner.
And it holds no state, so no rate limits or cumulative spend in v0.1.

**7. How is this different from prompt-level guardrails?**

Three axes. Channel: a prompt rule lives in the same text stream the
attacker writes into; the gate lives in host code the model cannot
address. Function: a model-judged rule is probabilistic and can be argued
with; the gate is a deterministic function that returns the same bytes
every time. Evidence: a prompt rule leaves no verifiable trace of having
been applied; every gate decision emits a canonical, replayable,
hash-verifiable record. Prompt guidance still has a job (it reduces how
often the model attempts bad calls), but it is advice to the principal,
not enforcement at the boundary.

**8. What happens when a normalizer raises?**

`_run_batch` catches every exception and converts it into
`Unavailable(fact, "<name> raised <ExceptionType>")` for every fact the
normalizer declared in `provides`. Only the type name is recorded, since
exception messages can carry raw values. Downstream this is
indistinguishable from an honest "cannot trust the input": every policy
needing any of those facts is denied `UNPARSEABLE` with the body skipped.
A normalizer bug is treated as hostile input, which is the correct
paranoia, and the exception never escapes `decide()`, because an escape
would land in host dispatch code where a blanket `except` could swallow it
and continue: the fail-open path this module exists to close. The same
conversion covers a normalizer returning a non-mapping, omitting a
promised key, or producing an undeclared one (which poisons the whole
batch).

**9. Why does an unterminated SQL literal classify UNKNOWN rather than
READ?**

Because the lexer, like a real SQL lexer, runs an unterminated literal to
end of input, which means everything after the opening quote was swallowed
and blanked. The keyword scan then cannot see what was in there, and what
was in there might have been a write. A valid single statement does not
leave a literal open, so an unterminated construct is either malformed SQL
or an active attempt to hide text inside a construct the lexer opened by
mistake (a stray quote after an unrecognized dialect marker, say).
"Provably a read" is the only ticket to `READ`, and an unprovable tail
forfeits it. The converse rule guards the other direction: a visible write
keyword outranks the unterminated flag, so a real write with a sloppy tail
is still `WRITE`, never downgraded.

**10. A `permits=False` policy returns `Allow`. Why is that a denial and
not an exception?**

The two designs were in conflict in the spec and conversion won, for the
same reason as question 8: an exception escaping `decide()` propagates
into host dispatch code, where it can be swallowed, and a swallowed
contract violation is fail-open. Converting to
`Denial(POLICY_ERROR, name, "permits=False policy returned Allow")` means
the illegal `Allow` never takes effect, the coverage report's
`permitted_by` column remains enforced truth, and the violation is visible
and countable in the log stream. The recorded falsifier: deployments
running for weeks with nonzero `POLICY_ERROR` counts nobody notices would
prove the quiet path hides broken policies. Watch the kind counters.

**11. Why is `Unavailable` a value instead of an exception?**

Exceptions travel control flow, and control flow is exactly what must not
be handed to failure here. An exception either escapes (aborting the
decision, letting the host decide what a crash means) or must be caught by
policy authors (reintroducing the forgotten-handler problem). As a value in
the fact table, "could not compute" is inert data that only the engine
interprets, in exactly one place, with exactly one meaning: deny the
policies that needed it, before their bodies run, and put the reason in
`fact_errors` for the record. Values also compose with the batch contract:
a normalizer can fail one fact and compute another in the same mapping.

**12. Why refuse to construct on an uncovered fact instead of denying at
runtime?**

A policy needing a fact no normalizer provides for one of its tools would
be *permanently* `UNPARSEABLE`: every governed call would deny, forever,
which is fail-closed but useless, and worse, it looks like governance while
actually being an outage. Since the condition is fully detectable from
declarations alone, `_check_needs_covered` raises `UncoveredFact(policy,
fact, tool)` before the first call, making "not computed" unrepresentable
at runtime. The general principle, from `errors.py`: a bad configuration is
loud at startup, a bad policy is a deny at runtime, and neither is ever an
allow. The `_MISSING` sentinel in `decide` keeps a runtime backstop anyway,
because defense in depth is cheap and an engine bug must still land on the
deny side.

**13. The FactKey collision check uses `is`, not equality. Why?**

Because equal-by-name keys are precisely the hazard. `FactKey` is a frozen
dataclass, so two independently minted `FactKey("amount")` objects compare
equal, while their phantom type parameters, invisible at runtime, could
disagree: one package's `FactKey[int]`, another's `FactKey[Decimal]`.
Equality-based checking would bless exactly that silent aliasing. Identity
checking forces the discipline the model needs: a fact key is a single
shared object, minted once, imported everywhere, and a collision is a
`GateConfigError` at construction instead of a type confusion at runtime.

**14. Why does an allow require an explicit permit? Isn't zero denials
enough?**

Zero denials only proves nobody objected, and in a system where policies
abstain by default, "nobody objected" describes every call the policy set
never anticipated. Requiring a permit makes the allow side an enumerated,
named grant: the record's `permits` list says which rule authorized the
call, which an audit needs. It also makes the dangerous misconfiguration
loud: a tool governed only by forbid rules denies `NO_PERMIT` at runtime
and shows up as `forbid_only` in the coverage report at setup, instead of
silently allowing everything its forbid rules did not imagine. Deny by
default is the floor; explicit permits are what make an allow mean
something.

**15. Why does `wrap()` bind arguments through the tool's signature, and
why flatten `**kwargs`?**

The gate must judge the same named-argument view the tool would execute.
Binding through `inspect.signature(...).bind` with defaults applied makes
positional and keyword call styles judge identically, and makes an
unbindable call a `MALFORMED_CALL` denial rather than a TypeError: a call
the tool could not have executed must not slip past policy on a
technicality. The flattening closes a subtler gap: for a tool declared
`def send_email(to, **kwargs)`, `bind` nests extra keywords under
`kwargs`, so a normalizer looking for `phi_fields` at the top level would
not see `kwargs["phi_fields"]` even though the tool receives it. That
would let a signature shape hide a governed argument from policy while
still delivering it. Flattening restores the caller's named view, the same
view an adapter judges from raw argument JSON, and it cannot collide with
a real parameter because `bind` would have assigned such a keyword to that
parameter instead.

**16. Why are timestamps and decision ids kept out of the record body?**

So the body is a pure function of the call and the policy set, and
therefore byte-replayable. The trust story is: re-decide the call against a
gate with the same `policyset_sha256`, or re-serialize the embedded body,
and compare bytes against the stored `record_sha256`. A timestamp or a
random id inside the body would make every replay a mismatch by
construction. Both still exist, in the `record_line` envelope
(`ts`, `id`, `record_sha256`, `record`), and the id also rides in every
model-visible `Refusal`, which is what joins a transcript refusal to its
audit line. The recorded falsifier for this bet: a compliance reviewer
who requires the timestamp inside the signed body.

**17. Why does `policyset_sha256` include normalizer source text?**

Because a normalizer edit changes decisions exactly as a policy edit does:
loosen `classify_sql` and yesterday's denied call is today's allowed one,
with every policy byte unchanged. The fingerprint exists so a stored
record names the governing configuration; a fingerprint that ignored
normalizers would call two behaviorally different gates identical, which
breaks replay verification. Source text (via `inspect.getsource`) is
digested, not just names and declarations, because an edited body changes
behavior while its declaration stays put. The scope is exactly that, and no
wider: the digest covers a body's own text, not what the text references at
runtime. A policy factory closing over a different threshold, or a body that
consults a module-level allow-list someone later edits, changes behavior with
its source text unchanged and fingerprints identically. So the honest reading
is "the fingerprint moves when a body's own source or declaration changes,"
not "it moves whenever behavior can"; a deployment that wants the stronger
property keeps behavior-affecting state inside the body text. Both lists are
sorted by name so registration order cannot move the digest, and the accepted
cost is that objects without retrievable source (builtins, REPL-defined
functions) fall
back to `repr` and lose cross-process stability.

**18. Why does the Claude Code hook always exit 0, even when it crashes,
and why does it never emit "allow"?**

Because of the host's protocol. Claude Code reads exit 2 as a blocking
error and any other nonzero exit as "hook errored, continue", and
"continue" is fail-open. So the only channel that cannot be misread is
exit 0 with either silence or an explicit deny payload, and `main` wraps
everything in a catch-all that converts any crash (unreadable config,
broken policy module, bad stdin, unwritable audit log) into a deny naming
only the exception type. This is also why argument parsing avoids
argparse, whose error path is `SystemExit(2)`. The hook never emits
"allow" because allow-emitting would override Claude Code's own permission
prompts: the hook tightens, never loosens, and on a gate allow it stays
silent so the host's permission system keeps its authority.

**19. Two normalizers provide the same fact for the same tool. What
happens?**

`GateConfigError` at construction, from `_check_unique_providers`. It
cannot be resolved fail-closed at runtime because the ambiguity is about
which code should have run: whichever value won would depend on
registration order, which no output is allowed to depend on, and the audit
record's fact provenance would be ambiguous. Wiring ambiguity refuses to
start; that is the same stance as duplicate policy names, colliding fact
keys, and unnameable wrap targets.

---

## 10. Known weaknesses, plainly

Say these before an interviewer does.

**It gates only what you write policies for.** Deny-by-default holds
within the tool universe the gate stands in front of. A tool dispatched
around the gate, an OpenAI-hosted tool executing on OpenAI infrastructure,
an MCP-served tool the adapter cannot see, or a tool outside the hook's
governed subset is simply not governed. `assert_all_guarded` and the
coverage report shrink this gap; they do not close it.

**Normalizers are a maintained recognition layer.** The whole design pushes
correctness into normalizers, which means the recognition they perform has
to be maintained like any parser-adjacent code. They recognize what they
were built to recognize, and the world grows new argument shapes.

**`classify_sql` is a keyword classifier, not a parser, and it has dialect
gaps.** The one-pass lexer is sound for the grammar it models: `'`, `"`, and
MySQL backtick spans with doubled-delimiter escapes, `--` and `/* */`
comments, and MySQL `/*! ... */` executable comments scanned as code. A
dialect construct it does not model can still misclassify, but only in the
safe direction, because an unmodeled quote or comment introducer either
leaves a literal open (`unterminated`) or survives into the stripped code as
an out-of-grammar character (`unmodeled`), and both deny. That is how
PostgreSQL dollar-quoting is handled: the `$` sigil is out of grammar, so such
a query denies rather than reading as a hidden write. The reverse case, text
this lexer blanks as inert that some engine *executes*, is the harder one:
its type specimen, the MySQL executable comment `/*! ... */`, is handled by
scanning the comment interior as code (section 6), so
`SELECT 1 /*! DELETE FROM t */` classifies `WRITE` and denies. The general
family it represents, a construct executed by some engine yet leaving nothing
out-of-grammar for `unmodeled` to catch, is closed for the one case known to
exist and not proven closed for cases nobody has named. The `unterminated`
and `unmodeled` rules close the phantom-literal family; the `/*!` rule closes
the one known member of the executed-as-inert family. If your target is a
specific engine, extend the lexer for that engine's grammar or put a real
parser behind the same fact key.

**It is not a sandbox.** Nothing constrains what an allowed tool does, and
nothing observes results. Output governance (a permitted read whose data a
later permitted call leaks) is an explicit non-goal for v0.1.

**The trust bound of the hook is the host, not the machine.** A hook
configured through files an agent can edit can be un-governed by that
agent. The defense is operational: config and settings outside the
workspace, plus a self-protection policy over those paths. It defends
against the model, not the human who owns the machine.

**The healthcare policy is one taste, not the pack.**
`phi_minimum_necessary` plus a fax allow-list proves the shape; the
HIPAA/ADHICS pack is v0.2, and the covered-entity registry in the shipped
examples is a frozenset literal.

**No stateful facts.** Normalizers are pure functions of one `ToolCall`,
so rate limits, per-day spend, and session history are inexpressible in
v0.1. A stateful fact source needs a store and a clock, with consequences
for determinism and audit that deserve their own design pass.

**Assorted recorded tradeoffs.** In-record digests are truncated and
unsalted, so low-entropy values are brute-forceable offline (keyed digests
are the recorded fix). The hook starts an interpreter per event (a daemon
is the recorded reversal). The OpenAI adapter judges raw pre-coercion
argument JSON, betting that pydantic coercion never diverges from it in a
policy-relevant way; the falsifier and mitigation are written down in the
spec's riskiest-decisions list. And the adapters track moving frameworks:
pin them in the lockfile.

Every one of these is documented in the repo (`docs/DESIGN.md`, the spec's
section 13 and 14, the adapter and hook docstrings), which is itself a
stance: state the boundary, do not imply coverage you do not have.
