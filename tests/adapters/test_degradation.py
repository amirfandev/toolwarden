"""Framework-absent degradation: clear errors naming the exact extra.

The core promise is that `import toolwarden` and every adapter module
import cleanly with no framework installed, and that the moment a factory
genuinely needs its framework, the failure is a ModuleNotFoundError whose
message names the pip extra, not a bare traceback.

The real-absence tests are skipped automatically when the framework IS
installed (per the spec's optional smoke job); in the frameworkless CI
environment they all run.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from example_policies import PRINCIPAL_PROD, build_gate

_HAS_AGENTS = importlib.util.find_spec("agents") is not None
_HAS_LANGCHAIN_CORE = importlib.util.find_spec("langchain_core") is not None


def test_adapter_modules_import_without_any_framework() -> None:
    import toolwarden.adapters
    import toolwarden.adapters.anthropic_loop
    import toolwarden.adapters.langchain
    import toolwarden.adapters.openai_agents  # noqa: F401


def test_lazy_package_surface_resolves_names() -> None:
    import toolwarden.adapters as adapters

    assert callable(adapters.toolwarden_guardrail)
    assert callable(adapters.run_tool_uses)
    assert callable(adapters.toolwarden_tool_wrapper)
    assert callable(adapters.assert_all_guarded)
    with pytest.raises(AttributeError):
        adapters.no_such_factory  # noqa: B018
    assert set(adapters.__all__) <= set(dir(adapters))


@pytest.mark.skipif(_HAS_AGENTS, reason="openai-agents is installed here")
def test_openai_factory_names_its_extra_when_absent() -> None:
    from toolwarden.adapters.openai_agents import toolwarden_guardrail

    with pytest.raises(ModuleNotFoundError, match=r"toolwarden\[openai-agents\]"):
        toolwarden_guardrail(build_gate())


@pytest.mark.skipif(_HAS_AGENTS, reason="openai-agents is installed here")
def test_assert_all_guarded_names_its_extra_when_absent() -> None:
    from toolwarden.adapters.openai_agents import assert_all_guarded

    with pytest.raises(ModuleNotFoundError, match=r"toolwarden\[openai-agents\]"):
        assert_all_guarded(object(), object())


@pytest.mark.skipif(_HAS_LANGCHAIN_CORE, reason="langchain_core is installed here")
def test_langchain_factory_names_its_extra_when_absent() -> None:
    from toolwarden.adapters.langchain import toolwarden_tool_wrapper

    with pytest.raises(ModuleNotFoundError, match=r"toolwarden\[langchain\]"):
        toolwarden_tool_wrapper(build_gate(), principal={})


def test_anthropic_loop_runs_fully_with_zero_frameworks() -> None:
    """The strongest degradation claim: this adapter has no framework to be
    absent. Proven in a fresh interpreter with only src on the path."""
    src = str(Path(__file__).resolve().parents[2] / "src")
    tests = str(Path(__file__).resolve().parents[1])
    code = (
        "from example_policies import PRINCIPAL_PROD, build_gate\n"
        "from toolwarden.adapters.anthropic_loop import run_tool_uses\n"
        "message = {'content': [{'type': 'tool_use', 'id': 'x', 'name': 'db_exec',"
        " 'input': {'query': 'DELETE FROM t'}}]}\n"
        "results = run_tool_uses(build_gate(), {}, message, principal=PRINCIPAL_PROD)\n"
        "assert results[0]['is_error'] is True\n"
        "import json; payload = json.loads(results[0]['content'])\n"
        "assert payload['denied'] is True\n"
        "import sys\n"
        "assert 'anthropic' not in sys.modules\n"
        "print('clean')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": f"{src}:{tests}", "PATH": "/usr/bin:/bin"},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "clean"


def test_payload_parity_across_all_delivery_channels() -> None:
    """One denied call, five channels (wrap raise, wrap result, guardrail
    stub, anthropic loop, langchain stub): byte-identical refusal payloads
    once the per-decision id is removed."""
    from adapter_stubs import (
        StubToolCallRequest,
        make_agents_module,
        make_langchain_core_modules,
    )

    from toolwarden import ToolDenied
    from toolwarden.adapters.anthropic_loop import run_tool_uses

    payloads: dict[str, dict[str, object]] = {}

    def strip(raw: str) -> dict[str, object]:
        parsed: dict[str, object] = json.loads(raw)
        parsed.pop("decision_id")
        return parsed

    args = {"query": "DELETE FROM orders"}

    # wrap, raise mode
    gate = build_gate(strict=False)
    guarded = gate.wrap({"db_exec": lambda query: "ok"}, principal=PRINCIPAL_PROD)
    with pytest.raises(ToolDenied) as excinfo:
        guarded["db_exec"](**args)
    payloads["wrap_raise"] = strip(excinfo.value.refusal.to_tool_result())

    # wrap, result mode
    resulter = gate.wrap(
        {"db_exec": lambda query: "ok"}, principal=PRINCIPAL_PROD, on_deny="result"
    )
    payloads["wrap_result"] = strip(resulter["db_exec"](**args).to_tool_result())

    # anthropic loop
    message = {
        "content": [{"type": "tool_use", "id": "x", "name": "db_exec", "input": args}]
    }
    (result,) = run_tool_uses(
        build_gate(), {"db_exec": lambda query: "ok"}, message, principal=PRINCIPAL_PROD
    )
    payloads["anthropic"] = strip(result["content"])

    # openai guardrail and langchain middleware, against the stubs
    agents_mod = make_agents_module()
    lc_pkg, lc_messages = make_langchain_core_modules()
    saved = {name: sys.modules.get(name) for name in ("agents", "langchain_core", "langchain_core.messages")}
    sys.modules["agents"] = agents_mod
    sys.modules["langchain_core"] = lc_pkg
    sys.modules["langchain_core.messages"] = lc_messages
    try:
        from adapter_stubs import StubGuardrailData, StubToolContext

        from toolwarden.adapters.langchain import toolwarden_tool_wrapper
        from toolwarden.adapters.openai_agents import toolwarden_guardrail

        guard = toolwarden_guardrail(
            build_gate(), principal_from_context=lambda ctx: PRINCIPAL_PROD
        )
        output = guard.guardrail_function(
            StubGuardrailData(
                context=StubToolContext(tool_name="db_exec", tool_arguments=json.dumps(args))
            )
        )
        payloads["openai"] = strip(output.message)

        handler = toolwarden_tool_wrapper(build_gate(), principal=PRINCIPAL_PROD)
        tool_message = handler(
            StubToolCallRequest(tool_call={"name": "db_exec", "args": args, "id": "c1"}),
            lambda request: "ran",
        )
        payloads["langchain"] = strip(tool_message.content)
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module

    reference = payloads["wrap_raise"]
    for channel, payload in payloads.items():
        assert payload == reference, f"payload from {channel} diverged"
