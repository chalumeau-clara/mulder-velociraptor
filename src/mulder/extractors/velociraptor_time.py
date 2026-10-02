"""Explicit artifact timestamp adapters; original JSON remains untouched."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from mulder.extractors.velociraptor import artifact_name

# Bump when mappings change: existing imports are backfilled without duplicating rows.
TIMESTAMP_VERSION = "1"
TIMESTAMP_FIELDS: dict[str, tuple[str, str]] = {
    "Windows.EventLogs.Evtx": ("TimeCreated", "event creation"),
    "Windows.EventLogs.RDPAuth": ("EventTime", "RDP authentication event"),
    "Windows.System.Pslist": ("CreateTime", "process creation"),
    "Windows.Forensics.Usn": ("Timestamp", "USN journal event"),
    "Windows.Forensics.Bam": ("Bam_time", "BAM execution record"),
    "Windows.Forensics.RecycleBin": ("DeletedTimestamp", "file deletion"),
    "Windows.Forensics.RecentApps": ("LastExecution", "last application execution"),
    "Windows.Sys.Programs": ("KeyLastWriteTimestamp", "registry key last write"),
    "Windows.Registry.NTUser": ("Mtime", "registry key last write"),
    "Windows.System.Services": ("Created", "service registry key creation"),
    "Windows.System.CriticalServices": ("Created", "service registry key creation"),
    "Windows.Forensics.Shellbags": ("ModTime", "shellbag key modification"),
    "Windows.Forensics.Amcache/InventoryApplication": ("Timestamp", "Amcache record time"),
    "Windows.Forensics.Amcache/InventoryApplicationFile": ("Timestamp", "Amcache record time"),
    "Windows.Forensics.Amcache/InventoryApplicationShortcut": ("Timestamp", "Amcache record time"),
}
_AWARE_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")


def normalize_timestamp(value: object) -> str | None:
    """Accept precise, timezone-aware ISO dates; do not guess epoch units or zones."""
    if not isinstance(value, str) or not _AWARE_ISO.fullmatch(value):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.year < 1970:  # Windows zero/sentinel dates are not observations.
            return None
        return (
            dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        )
    except (ValueError, OverflowError):
        return None


def timestamp_field(member: str) -> str | None:
    entry = TIMESTAMP_FIELDS.get(artifact_name(member))
    return entry[0] if entry else None


def record_timestamp(raw_text: str, field: str) -> str | None:
    value = json.loads(raw_text)
    return normalize_timestamp(value.get(field)) if isinstance(value, dict) else None
