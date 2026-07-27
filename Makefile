# Requires an environment with the dev extra installed:
#   pip install -e ".[dev]"

.PHONY: check test evidence

check:
	ruff check .
	mypy
	pytest

test:
	pytest

# Replays the committed corpus through the worked policy gate, asserts every
# expected decision, and rewrites results.json. Every number in the README
# must come from this and nowhere else. Stdlib only, no install step needed.
evidence:
	python3 evidence/recompute.py
