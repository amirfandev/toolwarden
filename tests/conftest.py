"""Test bootstrap: make the in-repo package and the test helpers importable.

The suite must run against the working tree without an editable install,
because the CI job that proves "core needs no framework" starts from a bare
interpreter. Inserting `src/` here, once, keeps every test file free of path
gymnastics; inserting the tests root makes the committed fixtures
(`support`, `example_policies`) importable from any test subdirectory.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
for _entry in (str(_REPO / "src"), str(_REPO / "tests")):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)
