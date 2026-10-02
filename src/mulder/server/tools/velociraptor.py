"""Audited inspection and streaming import of offline Velociraptor collections."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from collections.abc import Iterator
from functools import partial
from pathlib import Path
from urllib.parse import quote

from mulder.extractors.velociraptor import (
    CollectionError,
    inspect_collection,
    iter_records,
    read_document,
    result_members,
    validate_container,
)
from mulder.extractors.velociraptor_sparse import write_upload
from mulder.extractors.velociraptor_time import (
    TIMESTAMP_VERSION,
    record_timestamp,
    timestamp_field,
)
from mulder.path_policy import resolve_allowed_path
from mulder.server.app import get_cfg, get_ctx, mcp
from mulder.server.helpers import audited_tool
from mulder.server.tool_access import Role, tool_access


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


@mcp.tool()
@tool_access(Role.CATALOG | Role.EXTRACT_PLANNER | Role.EXTRACT_EXECUTOR)
@audited_tool("inspect_velociraptor_collection")
def inspect_velociraptor_collection(
    collection_path: str,
    upload_offset: int = 0,
    upload_limit: int = 100,
) -> dict[str, object]:
    """Inventory an offline collector ZIP, including host and artifact names.

    Call when scanning identifies a velociraptor_collection, before importing it.
    Returns metadata and exact upload member names without extracting files.
    Follow next_upload_offset to page through uploads (limit 1..200).
    """
    return {
        "status": "success",
        **inspect_collection(
            Path(collection_path).expanduser().resolve(), upload_offset, upload_limit
        ),
    }


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
@audited_tool("import_velociraptor_collection")
def import_velociraptor_collection(collection_path: str) -> dict[str, object]:
    """Stream offline collector JSONL results and metadata into the case index.

    Call for an unencrypted offline collector ZIP identified during cataloging.
    Returns per-source counts and explicit errors; uploaded files remain in the ZIP.
    """
    path = Path(collection_path).expanduser().resolve()
    ctx = get_ctx()
    progress_key = "velociraptor.import:" + str(path)
    ctx.db.set_kv(progress_key, json.dumps({"status": "incomplete", "path": str(path)}))
    summary = inspect_collection(path)
    digest = _sha256(path)
    ctx.db.register_evidence_file(str(path), digest, path.stat().st_size)
    prefix = f"velociraptor.{quote(str(summary['hostname'] or 'unknown'), safe='')}.{digest}"
    imported: list[dict[str, object]] = []
    errors: list[dict[str, str]] = []
    total_records = 0
    artifact_records = 0
    with zipfile.ZipFile(path) as archive:
        validate_container(archive)
        members = ["client_info.json", "collection_context.json", *result_members(archive)]
        members.extend(
            n for n in ("uploads.json", "log.json", "requests.json") if n in archive.namelist()
        )
        for member in members:
            try:
                if member in ("client_info.json", "collection_context.json", "requests.json"):
                    records = iter([(1, json.dumps(read_document(archive, member)))])
                else:
                    records = iter_records(archive, member)
                name = f"{prefix}.{member}"
                time_field = timestamp_field(member) if member.startswith("results/") else None
                source_id, count, skipped = ctx.db.import_record_source(
                    name,
                    str(path),
                    "sha256:" + digest,
                    "velociraptor",
                    records,
                    timestamp_parser=partial(record_timestamp, field=time_field)
                    if time_field
                    else None,
                    timestamp_version=TIMESTAMP_VERSION if time_field else None,
                )
                imported.append(
                    {
                        "member": member,
                        "source_name": name,
                        "source_id": source_id,
                        "records": count,
                        "already_indexed": skipped,
                        "timestamp_field": time_field,
                    }
                )
                total_records += count
                if member.startswith("results/"):
                    artifact_records += count
            except (CollectionError, zipfile.BadZipFile) as exc:
                errors.append({"member": member, "error": str(exc)})
    result = {
        "status": "partial" if errors else "success",
        "collection_sha256": digest,
        "hostname": summary["hostname"],
        "sources": imported,
        "errors": errors,
        "records": total_records,
        "artifact_records": artifact_records,
        "reported_artifact_records": summary["reported_rows"],
        "row_count_matches_metadata": artifact_records == summary["reported_rows"],
        "note": "Known artifacts use explicit timestamp adapters; other timestamps stay as data. "
        "Use inspect_velociraptor_collection for exact upload member paths; "
        "uploads.json preserves original endpoint paths and collection metadata. "
        "Missing artifacts do not establish absence of activity.",
    }
    ctx.db.set_kv(
        progress_key,
        json.dumps(
            {
                "status": result["status"],
                "path": str(path),
                "errors": errors,
                "artifact_records": artifact_records,
                "reported_artifact_records": summary["reported_rows"],
                "collection_sha256": digest,
            }
        ),
    )
    return result


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
@audited_tool("extract_velociraptor_file")
def extract_velociraptor_file(collection_path: str, member_path: str) -> dict[str, object]:
    """Extract a regular or sparse collected file, preserving provenance.

    Call with an exact uploads/ member returned by inspect_velociraptor_collection.
    Returns the local file and directory for file-based parsers such as Hayabusa.
    """
    return _extract_collected_file(collection_path, member_path)


def _extract_collected_file(collection_path: str, member_path: str) -> dict[str, object]:
    """Shared local extraction; callers expose their own audited MCP boundary."""
    path = Path(collection_path).expanduser().resolve()
    digest = _sha256(path)
    with zipfile.ZipFile(path) as archive:
        validate_container(archive)
        if not member_path.startswith("uploads/"):
            raise CollectionError("Only uploads/ members may be extracted")
        entry = archive.getinfo(member_path)
        if entry.is_dir() or entry.file_size > 2 * 1024**3:
            raise CollectionError("Upload is a directory or exceeds the 2 GiB file limit")
        # Hash the member identity; keep only a conservative suffix for parser discovery.
        suffix = Path(member_path).suffix.lower()
        if not suffix[1:].isalnum() or len(suffix) > 12:
            suffix = ""
        root = Path(get_cfg().db_dir) / "extracted"
        destination = resolve_allowed_path(
            root
            / "velociraptor"
            / digest
            / (hashlib.sha256(member_path.encode()).hexdigest() + suffix),
            [root],
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=destination.parent)
        try:
            with os.fdopen(fd, "wb") as output:
                details = write_upload(archive, member_path, output)
            os.replace(temporary, destination)
        finally:
            Path(temporary).unlink(missing_ok=True)
    return {
        "status": "success",
        "collection_path": str(path),
        "collection_sha256": digest,
        "member": member_path,
        "extracted_path": str(destination),
        "extracted_dir": str(destination.parent),
        **details,
    }


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
@audited_tool("index_velociraptor_evtx")
def index_velociraptor_evtx(
    collection_path: str,
    member_path: str,
    event_ids: list[int] | None = None,
) -> dict[str, object]:
    """Parse a collected EVTX into searchable, timestamped event records.

    Call for an uploads/ EVTX member returned by collection inspection; no disk
    image or prior extraction state is needed. Returns source and provenance.
    """
    if not member_path.lower().endswith(".evtx"):
        raise CollectionError("Expected an EVTX upload")
    if event_ids is not None and (not event_ids or any(i < 0 or i > 65535 for i in event_ids)):
        raise CollectionError("event_ids must be a nonempty list of IDs between 0 and 65535")
    extracted = _extract_collected_file(collection_path, member_path)
    allowed_ids = set(event_ids) if event_ids is not None else None
    selector = ",".join(str(i) for i in sorted(allowed_ids)) if allowed_ids is not None else "all"
    name = f"evtx.velociraptor.{extracted['collection_sha256']}.{member_path}.{selector}"

    def records() -> Iterator[tuple[int, str]]:
        from Evtx.Evtx import Evtx

        with Evtx(str(extracted["extracted_path"])) as log:
            for line_number, record in enumerate(log.records(), 1):
                xml = record.xml()
                element = ET.fromstring(xml)
                event_id = int(element.findtext("./{*}System/{*}EventID", "-1"))
                if allowed_ids is not None and event_id not in allowed_ids:
                    continue
                created = element.find("./{*}System/{*}TimeCreated")
                yield (
                    line_number,
                    json.dumps(
                        {
                            "TimeCreated": created.get("SystemTime")
                            if created is not None
                            else None,
                            "EventID": event_id,
                            "Channel": element.findtext("./{*}System/{*}Channel"),
                            "EventRecordID": element.findtext("./{*}System/{*}EventRecordID"),
                            "CollectionMember": member_path,
                            "Xml": xml,
                        },
                        ensure_ascii=False,
                    ),
                )

    source_id, count, skipped = get_ctx().db.import_record_source(
        name,
        str(extracted["collection_path"]),
        "sha256:" + str(extracted["sha256"]),
        "velociraptor.evtx",
        records(),
        timestamp_parser=partial(record_timestamp, field="TimeCreated"),
        timestamp_version="1",
    )
    return {
        **extracted,
        "source_name": name,
        "source_id": source_id,
        "records": count,
        "already_indexed": skipped,
    }
