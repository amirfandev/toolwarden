"""Gate and Decision: construction-time checks and the decide loop.

The decide sequence, fixed and stated once (spec section 4):

  1. Boundary validation. A structurally broken call (non-string or empty
     tool, non-mapping args or principal) is a single MALFORMED_CALL denial;
     nothing else runs.
  2. Routing. The governed policies are exactly those declaring the tool.
     None: a single UNGOVERNED denial. A policy body never sees a call for
     a tool it did not declare.
  3. Normalization. Every normalizer declaring the tool runs under the
     batch contract in `toolwarden.normalize`, yielding the fact table.
  4. Evaluation. Per governed policy, exactly one trail entry. A needed
     Unavailable fact: UNPARSEABLE on the policy's behalf, body never runs.
     Deny(reason): POLICY_FORBADE. Allow from permits=True: a permit. Allow
     from permits=False, any escaping exception, or a non-Verdict return:
     POLICY_ERROR. A buggy policy silences only itself, and its silence is
     a deny, never an abstention.
  5. Aggregation. Any denial defeats all permits. Allowed iff zero denials
     and at least one permit. Governed, no denial, no permit: NO_PERMIT.
  6. Canonical ordering. Denials sorted by (kind precedence, policy,
     reason); permits and trail by policy name. The headline outcome is the
     first denial of the sorted set: a pure function of the denial SET, so
     registration order cannot influence any byte of any output.
  7. Sink. `on_decision` fires on every decision, allow and deny, after the
     trail is complete. If the sink raises, the exception propagates: a
     host that cannot log is a host that should stop.

There is no path from unparseable input to allow, and none of the deny paths
depend on a policy author remembering to check anything.
"""

from __future__ import annotations

import sys
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from toolwarden.audit import policyset_sha256 as _compute_policyset_sha256
from toolwarden.audit import render_record, render_record_line
from toolwarden.coverage import CoverageReport, audit_coverage
from toolwarden.denial import Denial, DenyKind, sort_denials
from toolwarden.errors import CoverageError, GateConfigError, UncoveredFact
from toolwarden.facts import FactKey, Facts, Unavailable
from toolwarden.normalize import Normalizer, run_normalizers
from toolwarden.policy import Policy
from toolwarden.types import Allow, Deny, NotApplicable, ToolCall

if TYPE_CHECKING:
    from toolwarden.refusal import Refusal

PrincipalSource = Mapping[str, Any] | Callable[[], Mapping[str, Any]]

# Sentinel for "no fact table entry at all", distinct from any real value
# and from Unavailable. Construction-time coverage makes this unreachable;
# the runtime check stays because defense in depth is cheap and an engine
# bug here must still land on the deny side.
_MISSING: object = object()


@dataclass(frozen=True)
class Decision:
    """The complete, order-independent result of judging one call.

    `denials`, `permits`, and `trail` are canonically sorted at
    construction by the gate, so two decisions over the same call and the
    same policy set compare equal whatever order anything was registered or
    evaluated in. `decision_id` is minted per decision and deliberately
    excluded from `record()`: it joins a transcript refusal to an audit
    line via the `record_line` envelope without costing the body its
    byte-stability.
    """

    call: ToolCall
    decision_id: str
    denials: tuple[Denial, ...]
    permits: tuple[str, ...]
    trail: tuple[tuple[str, str], ...]
    facts: Mapping[str, object]
    fact_errors: Mapping[str, str]
    policyset_sha256: str

    @property
    def allowed(self) -> bool:
        """True iff nothing denied and at least one policy permitted."""
        return not self.denials and bool(self.permits)

    @property
    def outcome(self) -> Denial | None:
        """The headline denial, None when allowed.

        First element of the canonically sorted denials, hence a pure
        function of the denial set, never "first encountered".
        """
        return self.denials[0] if self.denials else None

    def refusal(self) -> Refusal:
        """The model-facing view of a denied decision.

        Imported lazily to keep this module importable on its own; the
        refusal layer is a separate concern with its own module.
        """
        from toolwarden.refusal import Refusal

        return Refusal(
            tool=self.call.tool,
            denials=self.denials,
            decision_id=self.decision_id,
        )

    def record(self) -> str:
        """Canonical JSON body, byte-stable across replays; see audit.py."""
        return render_record(self)

    def record_line(self, *, ts: str) -> str:
        """One audit log line: ts, id, and body digest wrapping the body."""
        return render_record_line(self, ts=ts)


class Gate:
    """The deterministic gate: policies plus normalizers, checked at
    construction, judging every call by the fixed decide sequence.

    Everything that can be wrong about the wiring is raised here, before the
    first call: duplicate names, colliding fact keys, a needed fact with no
    provider, ambiguous providers, and (when `tools=` names the universe)
    coverage findings. A gate that constructs is a gate whose runtime
    failure modes are all denials.
    """

    def __init__(
        self,
        policies: Sequence[Policy],
        normalizers: Sequence[Normalizer],
        *,
        tools: Sequence[str] | None = None,
        strict: bool = True,
        on_decision: Callable[[ToolCall, Decision], None] | None = None,
    ) -> None:
        self._policies = _validated_policies(policies)
        self._normalizers = _validated_normalizers(normalizers)
        _check_fact_key_identity(self._policies, self._normalizers)
        _check_needs_covered(self._policies, self._normalizers)
        _check_unique_providers(self._normalizers)

        if on_decision is not None and not callable(on_decision):
            raise GateConfigError("on_decision must be callable or None")
        self._on_decision = on_decision
        self._strict = bool(strict)

        if tools is not None:
            report = audit_coverage(self._policies, tools)
            if not report.clean:
                if self._strict:
                    raise CoverageError(
                        "coverage findings against the declared tool universe:\n"
                        + report.render()
                    )
                # Non-strict exists for incremental adoption: surface every
                # finding where an operator will see it, then proceed.
                print(report.render(), file=sys.stderr)

        self._policyset_sha256 = _compute_policyset_sha256(self._policies, self._normalizers)

    @property
    def policyset_sha256(self) -> str:
        """Fingerprint of the registered policies and normalizers."""
        return self._policyset_sha256

    @property
    def policies(self) -> tuple[Policy, ...]:
        """Registered policies, in registration order (order never affects
        any decision output; the canonical sorts guarantee it)."""
        return self._policies

    @property
    def normalizers(self) -> tuple[Normalizer, ...]:
        """Registered normalizers, in registration order."""
        return self._normalizers

    @property
    def strict(self) -> bool:
        """Whether coverage findings abort construction and wrap()."""
        return self._strict

    def decide(
        self,
        *,
        tool: str,
        args: Mapping[str, Any],
        principal: Mapping[str, Any],
    ) -> Decision:
        """Judge one call. Never raises for any input; every failure mode
        is a denial. (The one deliberate exception: a raising `on_decision`
        sink propagates, per the decide sequence's step 7.)
        """
        problems: list[str] = []
        if not isinstance(tool, str):
            problems.append(f"tool is not a string (got {type(tool).__name__})")
        elif not tool:
            problems.append("tool name is empty")
        if not isinstance(args, Mapping):
            problems.append(f"args is not a mapping (got {type(args).__name__})")
        if not isinstance(principal, Mapping):
            problems.append(f"principal is not a mapping (got {type(principal).__name__})")
        if problems:
            # The stored call is sanitized by type name, never by repr:
            # a malformed payload may still hold secrets, and MALFORMED
            # reasons land in records and transcripts.
            safe_tool = tool if isinstance(tool, str) else f"<{type(tool).__name__}>"
            safe_args = args if isinstance(args, Mapping) else {}
            safe_principal = principal if isinstance(principal, Mapping) else {}
            call = ToolCall(tool=safe_tool, args=safe_args, principal=safe_principal)
            denial = Denial(DenyKind.MALFORMED_CALL, "engine", "; ".join(problems))
            return self._finish(call=call, denials=[denial])

        call = ToolCall(tool=tool, args=args, principal=principal)

        governed = [p for p in self._policies if tool in p.tools]
        if not governed:
            denial = Denial(DenyKind.UNGOVERNED, "engine", f"no policy governs tool {tool!r}")
            return self._finish(call=call, denials=[denial])

        table = run_normalizers(self._normalizers, call)
        facts_out = {k: v for k, v in table.items() if not isinstance(v, Unavailable)}
        fact_errors = {k: v.reason for k, v in table.items() if isinstance(v, Unavailable)}

        denials: list[Denial] = []
        permits: list[str] = []
        trail: list[tuple[str, str]] = []

        for pol in governed:
            # Needed names sorted so the multi-fact UNPARSEABLE reason
            # string is itself canonical, independent of needs declaration
            # order.
            needed = sorted({key.name for key in pol.needs})
            broken: list[tuple[str, str]] = []
            for name in needed:
                value = table.get(name, _MISSING)
                if value is _MISSING:
                    broken.append((name, "no registered normalizer produced it"))
                elif isinstance(value, Unavailable):
                    broken.append((name, value.reason))
            if broken:
                reason = "; ".join(f"fact {name} unavailable: {why}" for name, why in broken)
                denials.append(Denial(DenyKind.UNPARSEABLE, pol.name, reason))
                trail.append((pol.name, "deny"))
                continue

            view = Facts(
                tool=call.tool,
                args=call.args,
                principal=call.principal,
                computed={name: table[name] for name in needed},
                needs=needed,
            )
            try:
                verdict = pol.fn(view)
            except Exception as exc:
                denials.append(
                    Denial(DenyKind.POLICY_ERROR, pol.name, f"policy raised {type(exc).__name__}")
                )
                trail.append((pol.name, "deny"))
                continue

            if isinstance(verdict, Deny):
                denials.append(Denial(DenyKind.POLICY_FORBADE, pol.name, verdict.reason))
                trail.append((pol.name, "deny"))
            elif isinstance(verdict, Allow):
                if pol.permits:
                    permits.append(pol.name)
                    trail.append((pol.name, "allow"))
                else:
                    denials.append(
                        Denial(
                            DenyKind.POLICY_ERROR,
                            pol.name,
                            "permits=False policy returned Allow",
                        )
                    )
                    trail.append((pol.name, "deny"))
            elif isinstance(verdict, NotApplicable):
                trail.append((pol.name, "not_applicable"))
            else:
                denials.append(
                    Denial(
                        DenyKind.POLICY_ERROR,
                        pol.name,
                        f"policy returned {type(verdict).__name__}, not a Verdict",
                    )
                )
                trail.append((pol.name, "deny"))

        if not denials and not permits:
            denials.append(
                Denial(
                    DenyKind.NO_PERMIT,
                    "engine",
                    f"policies govern {tool!r} but none permitted this call",
                )
            )

        return self._finish(
            call=call,
            denials=denials,
            permits=permits,
            trail=trail,
            facts=facts_out,
            fact_errors=fact_errors,
        )

    def deny_malformed(self, tool: str, reason: str) -> Decision:
        """A MALFORMED_CALL decision minted at a boundary.

        For adapters facing input `decide()` never gets to see, such as
        argument JSON that would not parse. It goes through the same finish
        path as every other decision, so the audit sink fires and the
        record carries the same policyset fingerprint.
        """
        safe_tool = tool if isinstance(tool, str) else f"<{type(tool).__name__}>"
        call = ToolCall(tool=safe_tool, args={}, principal={})
        denial = Denial(DenyKind.MALFORMED_CALL, "engine", reason)
        return self._finish(call=call, denials=[denial])

    def coverage(self, tools: Sequence[str]) -> CoverageReport:
        """Coverage of the registered policies against a tool universe.

        Pure query; enforcement (raising under strict) belongs to the
        callers that stand at boundaries: the constructor and `wrap()`.
        """
        return audit_coverage(self._policies, tools)

    def wrap(
        self,
        tools: Mapping[str, Callable[..., Any]] | Sequence[Callable[..., Any]],
        *,
        principal: PrincipalSource,
        on_deny: Literal["raise", "result"] = "raise",
    ) -> dict[str, Callable[..., Any]]:
        """Guarded callables for a set of tools; see toolwarden.wrap.

        Lazily imported: the wrap layer builds on the engine, not the other
        way around, and this module must stay importable without it.
        """
        from toolwarden.wrap import wrap_tools

        return wrap_tools(self, tools, principal=principal, on_deny=on_deny)

    def _finish(
        self,
        *,
        call: ToolCall,
        denials: Sequence[Denial],
        permits: Sequence[str] = (),
        trail: Sequence[tuple[str, str]] = (),
        facts: Mapping[str, object] | None = None,
        fact_errors: Mapping[str, str] | None = None,
    ) -> Decision:
        """Apply the canonical sorts, mint the Decision, fire the sink.

        Every decision, from every path including malformed and ungoverned,
        exits through here: the sorts and the sink cannot be skipped by a
        new code path forgetting them.
        """
        decision = Decision(
            call=call,
            decision_id=uuid.uuid4().hex,
            denials=sort_denials(denials),
            permits=tuple(sorted(permits)),
            trail=tuple(sorted(trail)),
            facts=dict(facts) if facts is not None else {},
            fact_errors=dict(fact_errors) if fact_errors is not None else {},
            policyset_sha256=self._policyset_sha256,
        )
        if self._on_decision is not None:
            self._on_decision(call, decision)
        return decision


def _validated_policies(policies: Sequence[Policy]) -> tuple[Policy, ...]:
    """Reject non-Policy objects and duplicate names, naming every duplicate."""
    out = tuple(policies)
    for item in out:
        if not isinstance(item, Policy):
            raise GateConfigError(
                f"policies must be Policy objects, got {type(item).__name__}; "
                "was the @policy decorator applied?"
            )
    _check_unique_names([p.name for p in out], kind="policy")
    return out


def _validated_normalizers(normalizers: Sequence[Normalizer]) -> tuple[Normalizer, ...]:
    """Reject non-Normalizer objects and duplicate names."""
    out = tuple(normalizers)
    for item in out:
        if not isinstance(item, Normalizer):
            raise GateConfigError(
                f"normalizers must be Normalizer objects, got {type(item).__name__}; "
                "was the @normalizer decorator applied?"
            )
    _check_unique_names([n.name for n in out], kind="normalizer")
    return out


def _check_unique_names(names: Sequence[str], *, kind: str) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for name in names:
        if name in seen:
            duplicates.add(name)
        seen.add(name)
    if duplicates:
        raise GateConfigError(f"duplicate {kind} names: {', '.join(sorted(duplicates))}")


def _check_fact_key_identity(
    policies: Sequence[Policy], normalizers: Sequence[Normalizer]
) -> None:
    """Two distinct FactKey objects sharing a name abort construction.

    The name is the runtime identity and the phantom type is invisible at
    runtime, so two packages independently minting `FactKey("amount")` with
    different type parameters would silently alias. Identity (`is`), not
    equality, is the test: equal-by-name keys are precisely the hazard.
    """
    keys_by_name: dict[str, FactKey[Any]] = {}
    declared: list[FactKey[Any]] = []
    for pol in policies:
        declared.extend(pol.needs)
    for nrm in normalizers:
        declared.extend(nrm.provides)
    for key in declared:
        existing = keys_by_name.get(key.name)
        if existing is None:
            keys_by_name[key.name] = key
        elif existing is not key:
            raise GateConfigError(
                f"two distinct FactKey objects share the name {key.name!r}; "
                "a fact key must be a single shared object, imported from one module"
            )


def _check_needs_covered(
    policies: Sequence[Policy], normalizers: Sequence[Normalizer]
) -> None:
    """Every (policy, fact, tool) triple must have a provider.

    Enforced at construction so that "not computed" is unrepresentable at
    runtime: without this, the fact would be permanently Unavailable and
    every governed call would die UNPARSEABLE, fail-closed but useless.
    """
    provided: set[tuple[str, str]] = set()
    for nrm in normalizers:
        for tool in nrm.tools:
            for key in nrm.provides:
                provided.add((tool, key.name))
    for pol in policies:
        for key in pol.needs:
            for tool in pol.tools:
                if (tool, key.name) not in provided:
                    raise UncoveredFact(pol.name, key.name, tool)


def _check_unique_providers(normalizers: Sequence[Normalizer]) -> None:
    """Two normalizers providing the same fact for the same tool abort
    construction: the audit record would have ambiguous provenance, and
    which value wins would depend on registration order, which nothing in
    this engine is allowed to depend on."""
    providers: dict[tuple[str, str], str] = {}
    for nrm in normalizers:
        for tool in nrm.tools:
            for key in nrm.provides:
                prev = providers.get((tool, key.name))
                if prev is not None and prev != nrm.name:
                    raise GateConfigError(
                        f"normalizers {prev!r} and {nrm.name!r} both provide fact "
                        f"{key.name!r} for tool {tool!r}; provenance would be ambiguous"
                    )
                providers[(tool, key.name)] = nrm.name
