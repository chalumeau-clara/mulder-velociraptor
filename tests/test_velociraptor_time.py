"""Timestamp semantics, conservative parsing, and upgrade of prior imports."""

from __future__ import annotations

import json
from functools import partial

import pytest

from mulder.db import CaseDB
from mulder.extractors.velociraptor_time import (
    normalize_timestamp,
    record_timestamp,
    timestamp_field,
)
from mulder.models import WindowRow


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        1700000000,
        "2026-01-01",
        "2026-01-01T12:34:56",
        "1601-01-01T00:00:00Z",
        "2026-02-31T12:00:00Z",
        "invalid",
    ],
)
def test_no_guessed_dates(value: object) -> None:
    assert normalize_timestamp(value) is None


def test_normalize_offset_and_subseconds() -> None:
    assert (
        normalize_timestamp("2026-10-01T12:34:56.1234567+02:00") == "2026-10-01T10:34:56.123456Z"
    )
    assert normalize_timestamp("2026-10-01T00:00:00Z") == "2026-10-01T00:00:00.000000Z"
    # python-evtx serializes SystemTime with a space instead of T.
    assert normalize_timestamp("2023-02-15 02:52:54.374662+00:00") == "2023-02-15T02:52:54.374662Z"


def test_explicit_artifact_mapping() -> None:
    assert timestamp_field("results/Windows.EventLogs.Evtx.json") == "TimeCreated"
    assert (
        timestamp_field("results/Windows.Forensics.Amcache%2FInventoryApplication.json")
        == "Timestamp"
    )
    assert timestamp_field("results/Unknown.Artifact.json") is None
    # Do not confuse PE build time or an arbitrary date with an event timestamp.
    assert record_timestamp('{"LinkDate":"2026-10-01T12:00:00Z"}', "Timestamp") is None


def test_backfill_existing_source_preserves_identity(tmp_case_db: CaseDB) -> None:
    raw = json.dumps({"TimeCreated": "2026-10-01T12:34:56Z", "Name": "timeline-marker"})
    original = tmp_case_db.import_record_source(
        "test", "/file.zip", "sha256:x", "velo", [(1, raw)]
    )
    assert tmp_case_db.search_windows("timeline")[0][0].event_time is None
    previous_hash = tmp_case_db.get_sources()[0].windows_hash
    parser = partial(record_timestamp, field="TimeCreated")
    upgraded = tmp_case_db.import_record_source(
        "test",
        "/file.zip",
        "sha256:x",
        "velo",
        [],
        parser,
        "1",
    )
    assert upgraded == (original[0], 1, True)
    assert tmp_case_db.search_windows("timeline")[0][0].event_time == "2026-10-01T12:34:56.000000Z"
    assert tmp_case_db.get_sources()[0].windows_hash == previous_hash
    assert len(tmp_case_db.get_sources()) == 1

    def should_not_run(_: str) -> str:
        raise AssertionError("Already backfilled")

    tmp_case_db.import_record_source(
        "test", "/file.zip", "sha256:x", "velo", [], should_not_run, "1"
    )


def test_timestamp_callback_failure_rolls_back(tmp_case_db: CaseDB) -> None:
    def broken(_: str) -> str:
        raise ValueError("bad adapter")

    with pytest.raises(ValueError, match="bad adapter"):
        tmp_case_db.import_record_source(
            "test", "/file.zip", "sha256:x", "velo", [(1, "{}")], broken
        )
    assert tmp_case_db.get_sources() == []


def test_partial_collection_blocks_extraction_gate() -> None:
    from mulder.orchestrator.gates import validate_extraction

    result = validate_extraction(
        {
            "sources_indexed": 100,
            "collection_import_gaps": [{"path": "/collection.zip", "status": "partial"}],
        }
    )
    assert not result.passed
    assert any(c.name == "collection_imports_complete" for c in result.checks)


def test_mixed_source_timestamps_and_exact_boundaries(tmp_case_db: CaseDB) -> None:
    source_id = tmp_case_db.register_source("image", "/image.dd", "x", "tsk", 3)
    times = ["2026-10-01T12:34:56", "2026-10-01T14:34:56+02:00", "2026-10-01T12:34:56.000001Z"]
    tmp_case_db.insert_windows(
        source_id,
        [
            WindowRow(
                source_id=source_id, line_start=i, line_end=i, raw_text="marker", event_time=stamp
            )
            for i, stamp in enumerate(times, 1)
        ],
    )
    tmp_case_db.import_record_source(
        "collection",
        "/collection.zip",
        "x",
        "velo",
        [(1, '{"Name":"marker"}')],
        lambda _: "2026-10-01T12:34:56.000000Z",
        "1",
    )
    grouped = tmp_case_db.get_windows_by_time_range(
        "2026-10-01T12:34:56Z",
        "2026-10-01T12:34:56.000000Z",
    )
    assert sum(len(rows) for rows in grouped.values()) == 3
    found = tmp_case_db.search_windows(
        "marker", time_start="2026-10-01T14:34:56+02:00", time_end="2026-10-01T12:34:56.000001Z"
    )
    assert len(found) == 4
    assert found[-1][0].event_time == times[-1]
