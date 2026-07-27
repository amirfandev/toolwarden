"""Put the repo's src/ tree on sys.path.

The evidence scripts must run from a bare clone with nothing installed,
because every published number has to be reproducible by anyone with the
repo and a Python 3.11+ interpreter. Importing this module first makes
`import toolwarden` resolve to the checked-out source, never to some other
installed copy, so the numbers always describe the code in this tree.
"""

import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parents[1] / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
