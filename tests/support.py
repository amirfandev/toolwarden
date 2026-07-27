"""Shared constants and helpers for the suite.

The sentinel strings are planted inside call arguments throughout the
fixtures and must never appear in any record body, envelope, refusal
payload, ToolMessage, tool_result, or hook output. They are chosen to be
high-entropy enough that an accidental substring match is impossible, and
they stand in for the real things the redaction rule protects: query text,
message bodies, PHI values, credentials.
"""

from __future__ import annotations

from collections.abc import Iterable

SECRET_QUERY = "SENTINEL-QUERY-4f8a2d71"
SECRET_BODY = "SENTINEL-BODY-9c11e7aa"
SECRET_PHI = "SENTINEL-PHI-DOB-19650412"
SECRET_CRED = "SENTINEL-CRED-sk-live-df90b3"

ALL_SENTINELS = (SECRET_QUERY, SECRET_BODY, SECRET_PHI, SECRET_CRED)


def assert_no_sentinels(text: str, *, where: str) -> None:
    """Fail loudly if any planted secret leaked into an output channel."""
    for sentinel in ALL_SENTINELS:
        assert sentinel not in text, f"sentinel {sentinel!r} leaked into {where}"


def assert_no_sentinels_in_all(texts: Iterable[str], *, where: str) -> None:
    for text in texts:
        assert_no_sentinels(text, where=where)
