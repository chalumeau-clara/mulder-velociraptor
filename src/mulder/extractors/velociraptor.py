"""Read offline Velociraptor containers without executing collected content.

ZIP member names are opaque identifiers. In particular, percent-encoded endpoint
paths must never be decoded into local filesystem destinations.
"""

from __future__ import annotations

import json
import stat
import zipfile
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote

MAX_MEMBERS = 100_000
MAX_METADATA_BYTES = 8 * 1024 * 1024
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024**3
_METADATA = ("client_info.json", "collection_context.json", "requests.json")


class CollectionError(ValueError):
    """An unsupported, damaged, or unsafe collection."""


def collection_kind(path: Path) -> str | None:
    """Probe ZIP structure only; ordinary or corrupt ZIPs remain generic archives."""
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            if {"data.zip", "metadata.json"} <= names:
                return "protected"
            if set(_METADATA) <= names:
                return "offline"
    except (OSError, zipfile.BadZipFile):
        pass
    return None


def validate_container(archive: zipfile.ZipFile) -> None:
    """Reject ambiguous names and unsafe entries before reading collection data."""
    entries = archive.infolist()
    if len(entries) > MAX_MEMBERS:
        raise CollectionError("Collection exceeds member limit")
    if sum(entry.file_size for entry in entries) > MAX_TOTAL_BYTES:
        raise CollectionError("Collection exceeds uncompressed size limit")
    seen: set[str] = set()
    for entry in entries:
        name = entry.filename
        parts = PurePosixPath(name).parts
        if (
            not parts
            or name.startswith("/")
            or "\\" in entry.orig_filename
            or ".." in parts
            or ":" in parts[0]
            or name in seen
            or stat.S_ISLNK(entry.external_attr >> 16)
        ):
            raise CollectionError(f"Unsafe or duplicate ZIP member: {name!r}")
        seen.add(name)
    if {"data.zip", "metadata.json"} <= seen or any(e.flag_bits & 1 for e in entries):
        raise CollectionError("Protected collection: decrypt locally before importing")
    if not set(_METADATA) <= seen:
        raise CollectionError("Not a supported offline Velociraptor collection")


def read_document(archive: zipfile.ZipFile, name: str) -> dict[str, Any] | list[Any]:
    """Read bounded JSON metadata, including multiline objects and arrays."""
    if archive.getinfo(name).file_size > MAX_METADATA_BYTES:
        raise CollectionError(f"Metadata exceeds size limit: {name}")
    try:
        value = json.loads(archive.read(name))
    except (ValueError, UnicodeError) as exc:
        raise CollectionError(f"Invalid metadata: {name}") from exc
    if not isinstance(value, (dict, list)):
        raise CollectionError(f"Expected metadata object or array: {name}")
    return value


def read_metadata(archive: zipfile.ZipFile, name: str) -> dict[str, Any]:
    """Read metadata that must be an object (client and collection context)."""
    value = read_document(archive, name)
    if not isinstance(value, dict):
        raise CollectionError(f"Expected metadata object: {name}")
    return value


def result_members(archive: zipfile.ZipFile) -> list[str]:
    """Return JSONL result members, excluding CSV duplicates and binary indexes."""
    return sorted(
        e.filename
        for e in archive.infolist()
        if not e.is_dir()
        and e.filename.startswith("results/")
        and e.filename.endswith((".json", ".jsonl"))
    )


def artifact_name(member: str) -> str:
    """Decode a logical artifact/source label, never a destination path."""
    return unquote(str(PurePosixPath(member.removeprefix("results/")).with_suffix("")))


def iter_records(archive: zipfile.ZipFile, member: str) -> Iterator[tuple[int, str]]:
    """Stream JSONL objects with physical line numbers and original text.

    Blank lines are skipped. Invalid records fail explicitly, rather than quietly
    reducing the evidence available to an investigator.
    """
    with archive.open(member) as stream:
        line_number = 0
        while raw := stream.readline(MAX_RECORD_BYTES + 1):
            line_number += 1
            if len(raw) > MAX_RECORD_BYTES:
                raise CollectionError(f"Record exceeds size limit: {member}:{line_number}")
            try:
                text = raw.decode("utf-8-sig" if line_number == 1 else "utf-8")
                if not text.strip():
                    continue
                value = json.loads(text)
                if not isinstance(value, dict):
                    raise ValueError("Expected JSON object")
            except (ValueError, UnicodeError) as exc:
                raise CollectionError(f"Invalid JSONL record: {member}:{line_number}") from exc
            yield line_number, text.rstrip("\r\n")


def inspect_collection(
    path: Path,
    upload_offset: int = 0,
    upload_limit: int = 100,
) -> dict[str, object]:
    """Inventory a collection without extracting uploads or loading result rows."""
    if upload_offset < 0 or not 1 <= upload_limit <= 200:
        raise CollectionError("upload_offset must be nonnegative; upload_limit must be 1..200")
    with zipfile.ZipFile(path) as archive:
        validate_container(archive)
        client = read_metadata(archive, "client_info.json")
        context = read_metadata(archive, "collection_context.json")
        results = result_members(archive)
        names = set(archive.namelist())
        uploads = sorted(
            e.filename
            for e in archive.infolist()
            if not e.is_dir() and e.filename.startswith("uploads/")
        )
        return {
            "collection_path": str(path.resolve()),
            "hostname": client.get("Hostname"),
            "os": client.get("OS"),
            "collection_id": context.get("session_id"),
            "collection_state": context.get("state"),
            "collection_time": context.get("create_time"),
            "reported_rows": context.get("total_collected_rows"),
            "artifacts": [
                {
                    "member": name,
                    "artifact": artifact_name(name),
                    "size_bytes": archive.getinfo(name).file_size,
                }
                for name in results
            ],
            "artifact_count": len(results),
            "empty_artifact_count": sum(archive.getinfo(n).file_size == 0 for n in results),
            "upload_count": len(uploads),
            "uploads": [
                {
                    "member": name,
                    "size_bytes": archive.getinfo(name).file_size,
                    "sparse_or_index": name.endswith(".idx") or name + ".idx" in names,
                }
                for name in uploads[upload_offset : upload_offset + upload_limit]
            ],
            "next_upload_offset": (
                upload_offset + upload_limit
                if upload_offset + upload_limit < len(uploads)
                else None
            ),
            "uncompressed_bytes": sum(e.file_size for e in archive.infolist()),
        }
