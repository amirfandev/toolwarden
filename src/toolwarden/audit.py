"""Canonical audit records: the byte-stable JSON body and its envelope.

The redaction rule, stated once: facts are loggable, args are not. Facts are
computed by operator-registered normalizers and are by construction the
minimum the decision depended on; raw args may hold PHI, credentials, or
message bodies and never enter the record. Args appear only as top-level
shape summaries (type, length, truncated digest) plus one digest over the
whole mapping, enough to verify a stored line against a replayed decision
without holding the raw values. `principal` is logged as-is by contract: it
is host-supplied identity metadata, never model-supplied content.

Byte-stability of `record()` rests on three legs, each enforced in one place:

  1. Every list on `Decision` (denials, permits, trail) is canonically
     sorted by the engine before it reaches this module, so registration
     order of policies and normalizers cannot influence any byte.
  2. Serialization here is pinned: `sort_keys=True`,
     `separators=(",", ":")`, `ensure_ascii=True`, `allow_nan=False`, and
     `_render_value` maps every non-JSON value to a deterministic form
     before dumping.
  3. Everything nondeterministic (timestamp, decision id) is exiled to the
     `record_line` envelope; the body contains neither, so the same call
     against the same policy set replays to the same bytes and the same
     `record_sha256`.

Digest honesty, per the spec: the 12-hex digests here are truncated and
unsalted, so digests of low-entropy strings are brute-forceable offline and
lengths narrow guesses. v0.1 documents that tradeoff instead of hiding it.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import math
from collections.abc import Callable, Mapping, Sequence
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from toolwarden.engine import Decision
    from toolwarden.normalize import Normalizer
    from toolwarden.policy import Policy


def _canonical_dumps(payload: object) -> str:
    """The one serialization every record byte passes through.

    Pinned flags, never varied: `sort_keys` fixes dict ordering,
    `separators` removes whitespace variance, `ensure_ascii` removes
    unicode-encoder variance across environments, and `allow_nan=False`
    turns a NaN that slipped past rendering into a loud error instead of
    non-standard JSON that some parsers reject and others mangle.
    """
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _digest12(text: str) -> str:
    """Truncated sha256, the record's compact fingerprint form."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def record_sha256(body: str) -> str:
    """Full sha256 over a record body string.

    Full-length, unlike the in-record 12-hex fingerprints, because this is
    the digest a reviewer verifies a stored envelope against; truncating the
    verification digest would weaken the one check the trust story rests on.
    """
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _render_value(value: object) -> object:
    """Deterministic JSON-safe form of a fact, principal entry, or arg value.

    Rules from the spec: enums by `.value`, frozensets as sorted lists,
    tuples as lists, scalars as-is. Extended, in the same fail-closed
    spirit, to everything else that could reach a record: non-finite floats
    become their repr string (so `allow_nan=False` cannot abort a record),
    mapping keys are stringified, and any unrecognized object becomes its
    type name in angle brackets rather than its repr, because reprs can
    embed both memory addresses (nondeterminism) and raw values (leaks).

    Sets sort by each element's canonical JSON, not by natural order: the
    elements of a mixed-type set need not be mutually comparable, and the
    sort must never raise inside record rendering. For the common case,
    sets of strings, this matches natural order.
    """
    if isinstance(value, Enum):
        return _render_value(value.value)
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else repr(value)
    if isinstance(value, (set, frozenset)):
        rendered = [_render_value(v) for v in value]
        return sorted(rendered, key=_canonical_dumps)
    if isinstance(value, Mapping):
        return {str(k): _render_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_render_value(v) for v in value]
    return f"<{type(value).__name__}>"


def _arg_summary(value: object) -> dict[str, object]:
    """Shape summary of one top-level argument, the only form args take in
    a record.

    Strings get a length and a truncated digest so replay can confirm "same
    argument" without storing it. Dict keys are listed because key names are
    schema, not data; dict values are not. Anything unrecognized reduces to
    its type name: when in doubt, log less.
    """
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "bool"}
    if isinstance(value, int):
        return {"type": "int"}
    if isinstance(value, float):
        return {"type": "float"}
    if isinstance(value, str):
        return {"type": "str", "len": len(value), "sha256_12": _digest12(value)}
    if isinstance(value, list):
        return {"type": "list", "len": len(value)}
    if isinstance(value, Mapping):
        return {"type": "dict", "keys": sorted(str(k) for k in value)}
    return {"type": type(value).__name__}


def render_record(decision: Decision) -> str:
    """The canonical JSON body behind `Decision.record()`.

    A pure function of the decision's already-sorted contents; list order is
    preserved from the Decision (the engine's canonical sorts), dict order
    is imposed by `sort_keys`. No timestamp, no id: those live only in the
    envelope so this body is byte-identical on replay.
    """
    call = decision.call
    args_canonical = _canonical_dumps(_render_value(dict(call.args)))

    outcome: dict[str, object]
    if decision.denials:
        head = decision.denials[0]
        outcome = {
            "allowed": False,
            "kind": head.kind.value,
            "policy": head.policy,
            "reason": head.reason,
        }
    elif decision.permits:
        outcome = {"allowed": True, "policy": decision.permits[0]}
    else:
        # Unreachable for engine-built decisions (no denial and no permit
        # becomes a NO_PERMIT denial), kept total so a hand-built Decision
        # still serializes as a deny rather than crashing the audit path.
        outcome = {"allowed": False}

    body: dict[str, object] = {
        "v": 1,
        "call": {
            "tool": call.tool,
            "principal": _render_value(dict(call.principal)),
            "args": {str(k): _arg_summary(v) for k, v in call.args.items()},
            "args_sha256": _digest12(args_canonical),
        },
        "facts": {name: _render_value(v) for name, v in decision.facts.items()},
        "fact_errors": dict(decision.fact_errors),
        "trail": [{"policy": p, "verdict": v} for p, v in decision.trail],
        "denials": [
            {"kind": d.kind.value, "policy": d.policy, "reason": d.reason}
            for d in decision.denials
        ],
        "permits": list(decision.permits),
        "outcome": outcome,
        "policyset_sha256": decision.policyset_sha256,
    }
    return _canonical_dumps(body)


def render_record_line(decision: Decision, *, ts: str) -> str:
    """The envelope behind `Decision.record_line(ts=...)`.

    Timestamp, decision id, and the body's full sha256 wrap the body here
    and only here. The body is embedded as a JSON object, not a string, so
    a log pipeline can query it; re-serializing it with the same pinned
    flags reproduces the exact bytes the digest covers, which is what lets
    a reviewer verify a stored line offline.
    """
    body = render_record(decision)
    envelope = {
        "ts": ts,
        "id": decision.decision_id,
        "record_sha256": record_sha256(body),
        "record": json.loads(body),
    }
    return _canonical_dumps(envelope)


def _source_text(fn: Callable[..., object]) -> str:
    """Source of a policy or normalizer body, or its repr as a last resort.

    Source text is in the policyset digest because an edited body changes
    decisions while name and declaration stay put, so the fingerprint moves
    whenever a body's own source or declaration changes. It captures the body's
    literal text, not what that text references: a closure variable, a
    module-level constant, or a helper function the body calls can change
    behavior with the source text unchanged, and the fingerprint does not move
    for those. See `policyset_sha256` for the exact scope of the guarantee. The
    repr fallback (builtins, C extensions, interactively defined functions)
    sacrifices cross-process stability for those objects only, which the spec
    accepts explicitly.
    """
    try:
        return inspect.getsource(fn)
    except (OSError, TypeError):
        return repr(fn)


def policyset_sha256(policies: Sequence[Policy], normalizers: Sequence[Normalizer]) -> str:
    """Fingerprint of the governing configuration, stamped on every decision.

    Sorted by name on both lists so registration order cannot move the
    digest, mirroring the engine's order-independence. Normalizers are
    included because a normalizer edit changes decisions just as surely as
    a policy edit does. Needs names are sorted (declaration order of needs
    has no semantic effect); tools and provides are digested in declared
    order because they are part of the declaration itself.

    Scope of the guarantee, stated precisely: the digest covers each body's
    name, tools, permits/provides, needs, and literal source text. It does NOT
    reach what a body references at runtime, closure variables, module-level
    constants, or helper functions, so two configurations that differ only in
    those (a policy factory closing over different thresholds, an edited
    module-level allow-list a body consults) fingerprint identically. The
    fingerprint moves when a body's own source or declaration changes; it is
    not a proof that two logs with equal fingerprints ran identical behavior
    when policies close over or delegate to state outside their own text.
    """
    entries: list[object] = []
    for pol in sorted(policies, key=lambda p: p.name):
        entries.append(
            [
                "policy",
                pol.name,
                list(pol.tools),
                pol.permits,
                sorted(key.name for key in pol.needs),
                _source_text(pol.fn),
            ]
        )
    for nrm in sorted(normalizers, key=lambda n: n.name):
        entries.append(
            [
                "normalizer",
                nrm.name,
                list(nrm.tools),
                [key.name for key in nrm.provides],
                _source_text(nrm.fn),
            ]
        )
    return _digest12(_canonical_dumps(entries))
