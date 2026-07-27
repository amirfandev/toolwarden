"""The Claude Code PreToolUse hook, tested as it runs in production: a
subprocess, JSON on stdin, config at an absolute path.

The protocol invariants under test: a governed deny prints the deny payload
and exits 0; a governed allow and an ungoverned tool print nothing (tighten
only, never loosen); and EVERY failure (bad stdin, missing config, broken
policy module, unwritable audit log) is an explicit deny with exit 0,
because any other exit code reads as "hook errored, continue", which is the
fail-open path the design exists to close.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from support import SECRET_QUERY, assert_no_sentinels

_SRC = str(Path(__file__).resolve().parents[2] / "src")

POLICY_MODULE = textwrap.dedent(
    """
    from toolwarden import Allow, Deny, Facts, Gate, NOT_APPLICABLE, Verdict, policy
    from toolwarden.normalizers import SQL_CLASS, SqlClass, classify_sql


    @policy("prod_db_read_only", tools=("db_exec",), needs=(SQL_CLASS,), permits=False)
    def prod_db_read_only(f: Facts) -> Verdict:
        if f.principal.get("env") != "production":
            return NOT_APPLICABLE
        if f[SQL_CLASS] is not SqlClass.READ:
            return Deny("statement is not a provable read against the production database")
        return NOT_APPLICABLE


    @policy("db_read_scope", tools=("db_exec",), needs=(SQL_CLASS,))
    def db_read_scope(f: Facts) -> Verdict:
        if f[SQL_CLASS] is SqlClass.READ:
            return Allow()
        return NOT_APPLICABLE


    @policy("session_pin", tools=("db_exec",), permits=False)
    def session_pin(f: Facts) -> Verdict:
        # Proves the event's session_id reaches the principal: the model
        # cannot set it, only the host event envelope can.
        if f.principal.get("session_id") != "sess-ok":
            return Deny("call is not attributable to the pinned session")
        return NOT_APPLICABLE


    def build_gate() -> Gate:
        return Gate(
            [prod_db_read_only, db_read_scope, session_pin],
            [classify_sql],
            tools=("db_exec",),
        )
    """
)


def _write_config(tmp_path: Path, **overrides: Any) -> Path:
    policy_path = tmp_path / "policies.py"
    if not policy_path.exists():
        policy_path.write_text(POLICY_MODULE, encoding="utf-8")
    config: dict[str, Any] = {
        "policy_module": str(policy_path),
        "governed_tools": ["db_exec"],
        "principal": {"agent": "claude-code", "env": "production"},
    }
    config.update(overrides)
    config_path = tmp_path / "hook.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    return config_path


def _run_hook(
    config: str | None, stdin_text: str, *, env_config: str | None = None
) -> subprocess.CompletedProcess[str]:
    argv = [sys.executable, "-m", "toolwarden.hook"]
    if config is not None:
        argv += ["--config", config]
    env = {"PYTHONPATH": _SRC, "PATH": "/usr/bin:/bin"}
    if env_config is not None:
        env["TOOLWARDEN_HOOK_CONFIG"] = env_config
    return subprocess.run(
        argv, input=stdin_text, capture_output=True, text=True, env=env, timeout=60
    )


def _event(tool: str, tool_input: Any, session_id: str = "sess-ok") -> str:
    return json.dumps(
        {
            "tool_name": tool,
            "tool_input": tool_input,
            "session_id": session_id,
            "cwd": "/work",
        }
    )


def _deny_reason(stdout: str) -> str:
    payload = json.loads(stdout)
    hook_out = payload["hookSpecificOutput"]
    assert hook_out["hookEventName"] == "PreToolUse"
    assert hook_out["permissionDecision"] == "deny"
    reason = hook_out["permissionDecisionReason"]
    assert isinstance(reason, str)
    return reason


def test_governed_deny_prints_payload_and_exits_zero(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    proc = _run_hook(
        str(config), _event("db_exec", {"query": f"DELETE FROM t -- {SECRET_QUERY}"})
    )
    assert proc.returncode == 0
    reason = _deny_reason(proc.stdout)
    assert "denied by policy" in reason
    assert "prod_db_read_only" in reason
    assert "(decision_id: " in reason  # joins the transcript to the audit line
    assert_no_sentinels(proc.stdout, where="hook stdout")


def test_governed_allow_emits_nothing(tmp_path: Path) -> None:
    """Tighten only: on allow the hook stays silent and the host's own
    permission system remains the authority."""
    config = _write_config(tmp_path)
    proc = _run_hook(str(config), _event("db_exec", {"query": "SELECT 1"}))
    assert proc.returncode == 0
    assert proc.stdout.strip() == ""


def test_ungoverned_tool_emits_nothing(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    proc = _run_hook(str(config), _event("Read", {"file_path": "/etc/hosts"}))
    assert proc.returncode == 0
    assert proc.stdout.strip() == ""


def test_bad_stdin_fails_closed(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    proc = _run_hook(str(config), "this is not json")
    assert proc.returncode == 0
    assert "failed closed" in _deny_reason(proc.stdout)


def test_missing_config_fails_closed() -> None:
    proc = _run_hook(None, _event("db_exec", {"query": "SELECT 1"}))
    assert proc.returncode == 0
    assert "failed closed" in _deny_reason(proc.stdout)


def test_config_via_environment_variable(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    proc = _run_hook(None, _event("db_exec", {"query": "DROP TABLE t"}), env_config=str(config))
    assert proc.returncode == 0
    assert "prod_db_read_only" in _deny_reason(proc.stdout)


def test_broken_policy_module_denies_governed_calls(tmp_path: Path) -> None:
    (tmp_path / "policies.py").write_text("raise RuntimeError('broken policies')\n")
    config = _write_config(tmp_path)
    proc = _run_hook(str(config), _event("db_exec", {"query": "SELECT 1"}))
    assert proc.returncode == 0
    reason = _deny_reason(proc.stdout)
    assert "failed closed" in reason
    assert "RuntimeError" in reason
    assert "broken policies" not in reason  # type name only, never the message


def test_broken_policy_module_does_not_break_ungoverned_passthrough(tmp_path: Path) -> None:
    """The governed-subset check precedes gate construction, so a broken
    policy module cannot turn the hook into a global deny-everything."""
    (tmp_path / "policies.py").write_text("raise RuntimeError('broken policies')\n")
    config = _write_config(tmp_path)
    proc = _run_hook(str(config), _event("Read", {"file_path": "/etc/hosts"}))
    assert proc.returncode == 0
    assert proc.stdout.strip() == ""


def test_nonstring_tool_input_denies_as_malformed(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    proc = _run_hook(str(config), _event("db_exec", ["not", "an", "object"]))
    assert proc.returncode == 0
    reason = _deny_reason(proc.stdout)
    assert "tool_input is not an object" in reason


def test_session_id_from_event_reaches_the_principal(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    good = _run_hook(str(config), _event("db_exec", {"query": "SELECT 1"}, session_id="sess-ok"))
    assert good.stdout.strip() == ""
    bad = _run_hook(str(config), _event("db_exec", {"query": "SELECT 1"}, session_id="sess-evil"))
    assert "session_pin" in _deny_reason(bad.stdout)


def test_audit_log_appends_verifiable_lines_for_allow_and_deny(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    config = _write_config(tmp_path, audit_log=str(audit))
    _run_hook(str(config), _event("db_exec", {"query": "SELECT 1"}))
    _run_hook(str(config), _event("db_exec", {"query": f"DROP TABLE t -- {SECRET_QUERY}"}))
    _run_hook(str(config), _event("Read", {"file_path": "/x"}))  # ungoverned: no line
    lines = audit.read_text().splitlines()
    assert len(lines) == 2  # allow and deny both logged, passthrough not
    allowed_seen = []
    for line in lines:
        envelope = json.loads(line)
        body = json.dumps(
            envelope["record"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        assert envelope["record_sha256"] == hashlib.sha256(body.encode()).hexdigest()
        allowed_seen.append(envelope["record"]["outcome"]["allowed"])
        assert_no_sentinels(line, where="hook audit line")
    assert allowed_seen == [True, False]


def test_unwritable_audit_log_fails_closed(tmp_path: Path) -> None:
    config = _write_config(tmp_path, audit_log=str(tmp_path / "no_such_dir" / "audit.jsonl"))
    proc = _run_hook(str(config), _event("db_exec", {"query": "SELECT 1"}))
    assert proc.returncode == 0
    assert "failed closed" in _deny_reason(proc.stdout)


def test_bad_config_shape_fails_closed(tmp_path: Path) -> None:
    config_path = tmp_path / "hook.json"
    config_path.write_text(json.dumps({"governed_tools": []}), encoding="utf-8")
    proc = _run_hook(str(config_path), _event("db_exec", {"query": "SELECT 1"}))
    assert proc.returncode == 0
    assert "failed closed" in _deny_reason(proc.stdout)


@pytest.mark.parametrize("flag_style", ["separate", "equals"])
def test_both_config_flag_styles_work(tmp_path: Path, flag_style: str) -> None:
    config = _write_config(tmp_path)
    argv = [sys.executable, "-m", "toolwarden.hook"]
    if flag_style == "separate":
        argv += ["--config", str(config)]
    else:
        argv += [f"--config={config}"]
    proc = subprocess.run(
        argv,
        input=_event("db_exec", {"query": "DROP TABLE t"}),
        capture_output=True,
        text=True,
        env={"PYTHONPATH": _SRC, "PATH": "/usr/bin:/bin"},
        timeout=60,
    )
    assert proc.returncode == 0
    assert "prod_db_read_only" in _deny_reason(proc.stdout)
