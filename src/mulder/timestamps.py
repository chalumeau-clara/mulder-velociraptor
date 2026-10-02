"""Canonical keys for comparing mixed ISO timestamp representations."""

from __future__ import annotations

from datetime import datetime, timezone


def timestamp_key(value: str | None) -> str | None:
    """Compare at microsecond precision; legacy naive extractor times use UTC.

    Original strings remain in the database. This avoids lexical comparison of
    Z, offsets, and fractions excluding a record exactly at a query boundary.
    """
    if not value:
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        return stamp.astimezone(timezone.utc).isoformat(timespec="microseconds")
    except (ValueError, OverflowError):
        return None
