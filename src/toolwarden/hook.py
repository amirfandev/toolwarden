"""Claude Code PreToolUse hook: `toolwarden-hook`, stdlib only, fail closed.

The bridge is one process per event: Claude Code writes a JSON event
(`tool_name`, `tool_input`, `session_id`, `cwd`) to stdin; this script
answers on stdout with either nothing or an explicit deny. Three fixed
decisions, from the spec:

  1. Tighten only, never loosen. On a gate allow the script emits no
     permission decision, deferring to Claude Code's own permission system.
     Emitting "allow" would silently bypass host prompts, inverting the
     product.

  2. Governed subset. The config declares which tool_names the gate
     governs; ungoverned tools pass through untouched, because the host's
     permission system is already their authority. Inside the subset, full
     engine semantics apply, including default deny. This is a documented
     narrowing relative to wrap(): here, "ungoverned" means "not
     toolwarden's problem".

  3. Fail closed by construction. Claude Code treats a nonzero non-2 exit
     as "hook errored, continue", which fails open. So `main` catches
     everything, prints an explicit deny naming only the exception type
     (messages can carry values; types cannot), and exits 0. A crash in
     toolwarden reads as a deny, never a shrug.

The principal, honestly: a hook has no JWT and no session token to verify.
What it has is a config file at an absolute path chosen by the operator
(`--config` or `TOOLWARDEN_HOOK_CONFIG`, set in settings.json, outside the
workspace), whose `principal` mapping is host-supplied by definition, plus
`session_id` and `cwd` lifted from the event envelope, which Claude Code
writes and the model does not. `tool_input` is the model-controlled part
and lands only in `ToolCall.args`. The bound, stated plainly: this defends
against the model, not against the human who owns the machine, and an
agent that can rewrite the config or settings.json can un-govern itself,
which is why the examples ship a self-protection policy over those paths.

Config file shape (JSON):

    {
      "policy_module": "/etc/toolwarden/policies.py",   // or a dotted module name
      "governed_tools": ["Bash", "Write", "Edit"],
      "principal": {"agent": "claude-code", "env": "workstation"},
      "audit_log": "/var/log/toolwarden/audit.jsonl"    // optional
    }

The policy module must expose `build_gate() -> Gate` (preferred, built
fresh per invocation) or a module-level `GATE`.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from types import ModuleType
from typing import Any

from toolwarden.engine import Decision, Gate
from toolwarden.errors import GateConfigError

_ENV_CONFIG = "TOOLWARDEN_HOOK_CONFIG"


def main(argv: Sequence[str] | None = None) -> int:
    """Console entry point. Always exits 0; a deny is data, not an error.

    Exit 0 with a deny payload is the only channel that cannot be
    misread: any other exit code is either "blocking error" (2) or
    "errored, continue" (fail open) in the host's protocol.
    """
    try:
        output = _run(sys.argv[1:] if argv is None else list(argv), sys.stdin.read())
    except Exception as exc:  # noqa: BLE001  (breadth is the point: fail closed)
        output = _deny_payload(
            f"toolwarden hook failed closed: {type(exc).__name__}; "
            "the call was denied because it could not be judged"
        )
    if output is not None:
        print(output)
    return 0


def _run(argv: list[str], stdin_text: str) -> str | None:
    """Judge one event. Returns the deny payload, or None for "no opinion".

    None is returned in exactly two cases: the tool is outside the governed
    subset, or the gate allowed the call. Every failure before the governed
    check raises (and `main` converts that to a deny), because a hook that
    cannot read its config or its event cannot know whether the call was
    governed, and not knowing must not become an allow.
    """
    config = _load_config(_config_path(argv))
    event = json.loads(stdin_text)
    if not isinstance(event, Mapping):
        raise GateConfigError("hook event is not a JSON object")

    tool_name = event.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name:
        # Cannot attribute the call to the governed subset: fail closed.
        raise GateConfigError("hook event carries no usable tool_name")

    if tool_name not in config.governed_tools:
        return None

    gate = _load_gate(config.policy_module)

    principal: dict[str, Any] = dict(config.principal)
    for key in ("session_id", "cwd"):
        value = event.get(key)
        if isinstance(value, str):
            principal[key] = value

    args = event.get("tool_input")
    if not isinstance(args, Mapping):
        # decide() would deny this as MALFORMED_CALL anyway; passing {} with
        # a decide on the real mapping type would launder the malformation.
        decision = gate.deny_malformed(
            tool_name, f"tool_input is not an object (got {type(args).__name__})"
        )
    else:
        decision = gate.decide(tool=tool_name, args=args, principal=principal)

    if config.audit_log is not None:
        _append_audit_line(config.audit_log, decision)

    if decision.allowed:
        return None
    refusal = decision.refusal()
    return _deny_payload(f"{refusal.message()} (decision_id: {refusal.decision_id})")


class _HookConfig:
    """Parsed and validated hook configuration.

    Validation is loud and total here because every config defect must
    become a deny (via the raise in `_run`) rather than a partially applied
    config: a half-read governed_tools list is a list of tools someone
    believes are governed and are not.
    """

    __slots__ = ("audit_log", "governed_tools", "policy_module", "principal")

    def __init__(self, raw: object) -> None:
        if not isinstance(raw, Mapping):
            raise GateConfigError("hook config is not a JSON object")
        policy_module = raw.get("policy_module")
        if not isinstance(policy_module, str) or not policy_module:
            raise GateConfigError("hook config: policy_module must be a non-empty string")
        governed = raw.get("governed_tools")
        if (
            not isinstance(governed, list)
            or not governed
            or not all(isinstance(t, str) and t for t in governed)
        ):
            raise GateConfigError(
                "hook config: governed_tools must be a non-empty list of tool names"
            )
        principal = raw.get("principal", {})
        if not isinstance(principal, Mapping):
            raise GateConfigError("hook config: principal must be an object")
        audit_log = raw.get("audit_log")
        if audit_log is not None and (not isinstance(audit_log, str) or not audit_log):
            raise GateConfigError("hook config: audit_log must be a non-empty string path")

        self.policy_module: str = policy_module
        self.governed_tools: frozenset[str] = frozenset(governed)
        self.principal: dict[str, Any] = dict(principal)
        self.audit_log: str | None = audit_log


def _config_path(argv: list[str]) -> str:
    """The config path from --config or the environment; no path, no gate.

    Parsed by hand rather than argparse because argparse answers a bad
    argument with SystemExit(2), and exit code 2 is the host's "blocking
    error" channel; every failure here must flow through the one
    deny-and-exit-0 path in `main`.
    """
    for index, arg in enumerate(argv):
        if arg == "--config" and index + 1 < len(argv):
            return argv[index + 1]
        if arg.startswith("--config="):
            return arg.split("=", 1)[1]
    from_env = os.environ.get(_ENV_CONFIG)
    if from_env:
        return from_env
    raise GateConfigError(
        f"no hook config: pass --config /abs/path.json or set {_ENV_CONFIG}"
    )


def _load_config(path: str) -> _HookConfig:
    with open(path, encoding="utf-8") as fh:
        return _HookConfig(json.load(fh))


def _load_gate(policy_module: str) -> Gate:
    """Build the gate from the configured policy module.

    Accepts a filesystem path (ends in .py or contains a separator) or a
    dotted module name. The module exposes `build_gate()` or `GATE`;
    `build_gate` wins when both exist because a fresh gate per invocation
    cannot carry state between events. All construction-time checks
    (coverage, uncovered facts, duplicate names) run here, per invocation,
    so an edit that breaks the policy module turns every governed call into
    a deny instead of loading a stale gate.
    """
    module = _import_policy_module(policy_module)
    builder = getattr(module, "build_gate", None)
    if callable(builder):
        gate = builder()
    else:
        gate = getattr(module, "GATE", None)
    if not isinstance(gate, Gate):
        raise GateConfigError(
            f"policy module {policy_module!r} must expose build_gate() -> Gate, "
            "or a module-level GATE"
        )
    return gate


def _import_policy_module(policy_module: str) -> ModuleType:
    if policy_module.endswith(".py") or os.sep in policy_module:
        spec = importlib.util.spec_from_file_location("_toolwarden_hook_policies", policy_module)
        if spec is None or spec.loader is None:
            raise GateConfigError(f"cannot load policy module from {policy_module!r}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    return importlib.import_module(policy_module)


def _append_audit_line(path: str, decision: Decision) -> None:
    """One record_line appended per governed decision, allow and deny alike.

    The hook owns the loop here, so it is the sink. A failed append raises,
    which `main` converts to a deny: a host that cannot log is a host that
    should stop, and in hook form "stop" is "deny the call".
    """
    line = decision.record_line(ts=datetime.now(UTC).isoformat())
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _deny_payload(reason: str) -> str:
    """The PreToolUse deny answer, exactly as the host protocol expects."""
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


if __name__ == "__main__":
    sys.exit(main())
