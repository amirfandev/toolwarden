"""The spec's section 1 import surface, verbatim.

The public API is a contract like any other: every name the spec promises
must be importable from exactly the module the spec names, with no
framework installed. A rename or a moved re-export is a breaking change
this test exists to catch.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_section_1_imports_resolve() -> None:
    """Engine, policy authoring, facts, boundary, and coverage names, all
    from the package root as the spec writes them."""
    from toolwarden import (  # noqa: F401
        NOT_APPLICABLE,
        Allow,
        CoverageError,
        CoverageReport,
        Decision,
        Denial,
        Deny,
        DenyKind,
        FactKey,
        Facts,
        Gate,
        GateConfigError,
        Normalizer,
        NotApplicable,
        Policy,
        Refusal,
        ToolCall,
        ToolCoverage,
        ToolDenied,
        Unavailable,
        UncoveredFact,
        UndeclaredFact,
        Verdict,
        normalizer,
        policy,
    )


def test_shipped_normalizer_surface_resolves() -> None:
    from toolwarden.normalizers import (  # noqa: F401
        AMOUNT_USD,
        FAX_NUMBER,
        PHI_FIELDS,
        RECIPIENT_DOMAINS,
        SQL_CLASS,
        SqlClass,
        classify_sql,
        fax_number,
        phi_fields,
        recipient_domains,
        usd_amount,
    )


def test_import_toolwarden_pulls_in_no_framework() -> None:
    """The core rule: importing the package (and the whole normalizer set)
    must not import any adapter framework. Checked in a fresh interpreter so
    this test cannot be fooled by modules other tests already imported."""
    src = str(Path(__file__).resolve().parents[2] / "src")
    code = (
        "import sys\n"
        "import toolwarden\n"
        "import toolwarden.normalizers\n"
        "import toolwarden.adapters\n"
        "forbidden = [m for m in sys.modules if m.split('.')[0] in "
        "('agents', 'langchain', 'langchain_core', 'anthropic', 'openai')]\n"
        "assert not forbidden, forbidden\n"
        "print('clean')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": src, "PATH": "/usr/bin:/bin"},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "clean"


def test_errors_importable_from_spec_layout_locations() -> None:
    """The spec layout places UndeclaredFact in facts.py and the coverage
    errors in coverage.py; the single definitions live in errors.py and are
    re-exported, so isinstance checks cannot split across two classes."""
    from toolwarden import coverage as coverage_mod
    from toolwarden import errors, facts

    assert getattr(facts, "UndeclaredFact") is errors.UndeclaredFact  # noqa: B009
    assert coverage_mod.CoverageError is errors.CoverageError
    assert coverage_mod.UncoveredFact is errors.UncoveredFact
    assert coverage_mod.GateConfigError is errors.GateConfigError


def test_wrap_module_is_the_boundary_implementation() -> None:
    from toolwarden import boundary, wrap

    assert wrap.wrap_tools is boundary.wrap_tools
