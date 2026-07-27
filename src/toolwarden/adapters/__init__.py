"""Framework adapters, exposed lazily.

The core rule (spec section 2): ``import toolwarden`` and everything under
it must work with no framework installed. The adapter modules obey it by
importing their framework only inside factory functions, and this package
obeys it by importing nothing eagerly: ``__getattr__`` resolves a factory
on first attribute access. A missing framework therefore surfaces at the
moment a factory is called, as a ModuleNotFoundError naming the exact
extra to install, never as a bare traceback for merely importing the
adapter.

- ``toolwarden_guardrail`` / ``assert_all_guarded``: OpenAI Agents SDK,
  extra ``toolwarden[openai-agents]``.
- ``run_tool_uses``: Anthropic tool-use loop, stdlib only (the
  ``toolwarden[anthropic]`` extra installs the client for the surrounding
  loop, not for the adapter).
- ``toolwarden_tool_wrapper``: LangChain 1.x middleware, extra
  ``toolwarden[langchain]``.
"""

from __future__ import annotations

import importlib
from typing import Any

__all__ = (
    "assert_all_guarded",
    "run_tool_uses",
    "toolwarden_guardrail",
    "toolwarden_tool_wrapper",
)

_HOMES: dict[str, str] = {
    "assert_all_guarded": "toolwarden.adapters.openai_agents",
    "run_tool_uses": "toolwarden.adapters.anthropic_loop",
    "toolwarden_guardrail": "toolwarden.adapters.openai_agents",
    "toolwarden_tool_wrapper": "toolwarden.adapters.langchain",
}


def __getattr__(name: str) -> Any:
    home = _HOMES.get(name)
    if home is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(importlib.import_module(home), name)


def __dir__() -> list[str]:
    return sorted(__all__)
