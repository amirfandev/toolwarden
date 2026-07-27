"""Refusal and ToolDenied: the model-facing half of the deny-time contract.

One denied decision has two audiences with two different needs. The host
gets the full `Decision` through `on_decision` and the audit record; that
side lives in the engine and audit modules. The model gets a `Refusal`: the
tool name, every denial with its policy and reason, and the `decision_id`
that joins the transcript to the audit line. The model must learn WHY it was
denied, in the tool-result channel it already reads, or it will retry the
same call forever; and an operator reading the transcript later must be able
to find the matching audit line, which is what the id is for.

`to_tool_result()` is canonical JSON with the same pinned serialization
flags as the audit record, so the payload is byte-identical whichever
adapter or wrapper delivers it. One denied call must read the same in a
guardrail rejection, an errored tool_result block, a middleware ToolMessage,
and a raised ToolDenied, because tests, log tooling, and the model itself
all key off those bytes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from toolwarden.denial import Denial


@dataclass(frozen=True)
class Refusal:
    """What the model is told when its call is denied.

    Carries denials only, never facts or args: the refusal travels into
    model context, and the redaction rule (facts are loggable, args are
    not) applies doubly to a channel the model will quote back. Deny
    reasons are already written for the transcript by the policy author.
    """

    tool: str
    denials: tuple[Denial, ...]
    decision_id: str

    def message(self) -> str:
        """Plain-text form, for channels that carry prose rather than JSON.

        Format: denied by policy (<policy> [<kind>]: <reason>; ...), in the
        decision's canonical denial order, so the headline denial leads.
        """
        parts = "; ".join(
            f"{d.policy} [{d.kind.value}]: {d.reason}" for d in self.denials
        )
        if not parts:
            # Unreachable for engine-built refusals (a denied decision has
            # at least one denial); kept total so a hand-built Refusal
            # still renders instead of crashing a deny path.
            return f"call to tool {self.tool!r} was denied"
        return f"denied by policy ({parts})"

    def to_tool_result(self) -> str:
        """Canonical JSON payload, byte-identical across every adapter.

        Serialization flags are pinned to the audit record's: sorted keys,
        no whitespace, ascii only, no NaN. `denied` is an explicit marker so
        a host running its own loop can recognize a refusal-shaped string
        without guessing, and the denials list keeps the decision's
        canonical order.
        """
        payload = {
            "denied": True,
            "tool": self.tool,
            "decision_id": self.decision_id,
            "denials": [
                {"kind": d.kind.value, "policy": d.policy, "reason": d.reason}
                for d in self.denials
            ],
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        )


class ToolDenied(Exception):
    """Raised by a wrapped tool (on_deny="raise") when the gate denies.

    An exception rather than a return value because bare `wrap()` serves
    hosts whose dispatch code is invisible: a returned refusal mistaken for
    a tool result is silent corruption, while an exception is impossible to
    mistake for success. The full `Refusal` rides along so the host can
    still deliver `to_tool_result()` to the model after catching.
    """

    def __init__(self, refusal: Refusal) -> None:
        super().__init__(refusal.message())
        self.refusal = refusal
