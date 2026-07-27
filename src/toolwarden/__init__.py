"""toolwarden: a deterministic gate between an LLM agent and its tools.

Every tool call is checked against policy before it executes and allowed or
denied by code that returns the same answer every time. Public API only;
all logic lives in the submodules.
"""

from toolwarden.coverage import CoverageReport, ToolCoverage
from toolwarden.denial import Denial, DenyKind
from toolwarden.engine import Decision, Gate
from toolwarden.errors import (
    CoverageError,
    GateConfigError,
    UncoveredFact,
    UndeclaredFact,
)
from toolwarden.facts import FactKey, Facts, Unavailable
from toolwarden.normalize import Normalizer, normalizer
from toolwarden.policy import Policy, policy
from toolwarden.refusal import Refusal, ToolDenied
from toolwarden.types import (
    NOT_APPLICABLE,
    Allow,
    Deny,
    NotApplicable,
    ToolCall,
    Verdict,
)

__all__ = (
    "NOT_APPLICABLE",
    "Allow",
    "CoverageError",
    "CoverageReport",
    "Decision",
    "Denial",
    "Deny",
    "DenyKind",
    "FactKey",
    "Facts",
    "Gate",
    "GateConfigError",
    "Normalizer",
    "NotApplicable",
    "Policy",
    "Refusal",
    "ToolCall",
    "ToolCoverage",
    "ToolDenied",
    "Unavailable",
    "UncoveredFact",
    "UndeclaredFact",
    "Verdict",
    "normalizer",
    "policy",
)
