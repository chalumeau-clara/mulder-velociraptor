"""Synthetic collection fixtures; real endpoint evidence is never required in CI."""

from __future__ import annotations

import json
import os
import zipfile
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest

from mulder.db import CaseDB
from mulder.extractors.classifier import EvidenceClassifier
from mulder.extractors.velociraptor import (
    CollectionError,
    collection_kind,
    inspect_collection,
    iter_records,
)


@pytest.fixture
def collection(tmp_path: Path) -> Path:
    path = tmp_path / "collection.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("client_info.json", json.dumps({"Hostname": "LAB", "OS": "windows"}))
        archive.writestr("collection_context.json", json.dumps({"session_id": "F.test"}))
        archive.writestr("requests.json", '[\n  {"artifacts": ["Windows.Test"]}\n]')
        archive.writestr("results/Windows.Test%2FSource.json", '\n{"Name":"example.exe"}\n')
        archive.writestr("results/Windows.Empty.json", "")
        archive.writestr("results/Windows.Empty.json.index", b"\x00")
        archive.writestr("uploads/auto/C%3A/test.evtx", b"test")
        archive.writestr("uploads.json", '{"vfs_path":"uploads/auto/C%3A/test.evtx"}\n')
    return path


def test_inspect_and_classify(collection: Path) -> None:
    result = inspect_collection(collection)
    assert result["hostname"] == "LAB"
    assert result["artifact_count"] == 2
    assert result["empty_artifact_count"] == 1
    assert result["upload_count"] == 1
    assert "Windows.Test/Source" in str(result["artifacts"])
    assert EvidenceClassifier().classify(collection)[0].artifact_type == "velociraptor_collection"


def test_jsonl_preserves_line_numbers(collection: Path) -> None:
    with zipfile.ZipFile(collection) as archive:
        assert list(iter_records(archive, "results/Windows.Test%2FSource.json")) == [
            (2, '{"Name":"example.exe"}')
        ]
        assert list(iter_records(archive, "results/Windows.Empty.json")) == []


def test_upload_pagination_and_limits(collection: Path) -> None:
    with zipfile.ZipFile(collection, "a") as archive:
        archive.writestr("uploads/auto/another.evtx", "data")
    first = inspect_collection(collection, upload_limit=1)
    second = inspect_collection(collection, upload_offset=1, upload_limit=1)
    assert first["next_upload_offset"] == 1
    assert second["next_upload_offset"] is None
    assert first["uploads"] != second["uploads"]
    with pytest.raises(CollectionError, match="upload_limit"):
        inspect_collection(collection, upload_limit=0)


def test_record_limit(collection: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mulder.extractors import velociraptor

    monkeypatch.setattr(velociraptor, "MAX_RECORD_BYTES", 8)
    with (
        zipfile.ZipFile(collection) as archive,
        pytest.raises(CollectionError, match="size limit"),
    ):
        list(iter_records(archive, "results/Windows.Test%2FSource.json"))


def test_duplicate_members(collection: Path) -> None:
    with zipfile.ZipFile(collection, "a") as archive, pytest.warns(UserWarning, match="Duplicate"):
        archive.writestr("client_info.json", "{}")
    with pytest.raises(CollectionError, match="duplicate"):
        inspect_collection(collection)


def test_symlink_member(collection: Path) -> None:
    with zipfile.ZipFile(collection, "a") as archive:
        info = zipfile.ZipInfo("uploads/link")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        archive.writestr(info, "/elsewhere")
    with pytest.raises(CollectionError, match="Unsafe"):
        inspect_collection(collection)


@pytest.mark.parametrize("name", ["../escape", "/absolute", "C:/escape", "a\\b"])
def test_unsafe_members(collection: Path, name: str) -> None:
    with zipfile.ZipFile(collection, "a") as archive:
        info = zipfile.ZipInfo("placeholder")
        info.filename = name  # Avoid Windows normalizing backslashes in ZipInfo.__init__.
        archive.writestr(info, "bad")
    with pytest.raises(CollectionError, match="Unsafe"):
        inspect_collection(collection)


def test_protected_container(tmp_path: Path) -> None:
    path = tmp_path / "protected.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("data.zip", "opaque")
        archive.writestr("metadata.json", "{}")
    assert collection_kind(path) == "protected"
    with pytest.raises(CollectionError, match="decrypt locally"):
        inspect_collection(path)


def test_generic_zip_and_corrupt_zip(tmp_path: Path) -> None:
    path = tmp_path / "ordinary.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("results/test.json", "{}")
    assert collection_kind(path) is None
    assert EvidenceClassifier().classify(path)[0].artifact_type == "compressed_archive"
    path.write_bytes(b"broken")
    assert collection_kind(path) is None


def test_invalid_record_is_explicit(collection: Path) -> None:
    with zipfile.ZipFile(collection, "a") as archive:
        archive.writestr("results/broken.json", "{}\ninvalid\n")
    with (
        zipfile.ZipFile(collection) as archive,
        pytest.raises(CollectionError, match="broken.json:2"),
    ):
        list(iter_records(archive, "results/broken.json"))


def test_atomic_streaming_import(tmp_case_db: CaseDB) -> None:
    def broken() -> Iterator[tuple[int, str]]:
        for line in range(600):
            yield line + 1, '{"Name":"rollback.exe"}'
        raise CollectionError("bad record")

    with pytest.raises(CollectionError):
        tmp_case_db.import_record_source(
            "test", "/collection.zip", "sha256:test", "velo", broken()
        )
    assert tmp_case_db.get_sources() == []
    assert tmp_case_db.search_windows("rollback") == []
    result = tmp_case_db.import_record_source(
        "test", "/collection.zip", "sha256:test", "velo", iter([(2, '{"Name":"needle"}')])
    )
    assert result[1:] == (1, False)
    assert tmp_case_db.search_windows("needle")[0][0].line_start == 2
    repeated = tmp_case_db.import_record_source(
        "test", "/collection.zip", "sha256:test", "velo", broken()
    )
    assert repeated == (result[0], 1, True)


def test_collection_import_and_extraction(
    collection: Path,
    tmp_case_db: CaseDB,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mulder.server.app as app
    from mulder.audit import AuditLog

    monkeypatch.setattr(
        app,
        "_ctx",
        SimpleNamespace(
            db=tmp_case_db,
            audit=AuditLog(tmp_path / "audit.jsonl"),
        ),
    )
    monkeypatch.setattr(app, "_cfg", SimpleNamespace(db_dir=tmp_path))
    inspect = app._tool_dispatch_sync["inspect_velociraptor_collection"]
    importer = app._tool_dispatch_sync["import_velociraptor_collection"]
    extract = app._tool_dispatch_sync["extract_velociraptor_file"]
    assert inspect(collection_path=str(collection))["artifact_count"] == 2
    result = importer(collection_path=str(collection))
    assert result["status"] == "success"
    assert result["records"] == 5
    assert "tool_call_id" in result
    hits = tmp_case_db.search_windows("example")
    assert len(hits) == 1
    assert hits[0][0].event_time is None
    assert "%2FSource.json" in hits[0][1]
    assert importer(collection_path=str(collection))["records"] == 5
    assert len(tmp_case_db.search_windows("example")) == 1
    output = extract(collection_path=str(collection), member_path="uploads/auto/C%3A/test.evtx")
    extracted = Path(str(output["extracted_path"]))
    assert extracted.read_bytes() == b"test"
    assert extracted.is_relative_to(tmp_path / "extracted")
    with pytest.raises(CollectionError, match="Only uploads"):
        extract(collection_path=str(collection), member_path="client_info.json")


def test_partial_import_is_reported(
    collection: Path,
    tmp_case_db: CaseDB,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mulder.server.app as app
    from mulder.audit import AuditLog

    monkeypatch.setattr(
        app,
        "_ctx",
        SimpleNamespace(
            db=tmp_case_db,
            audit=AuditLog(tmp_path / "audit.jsonl"),
        ),
    )
    with zipfile.ZipFile(collection, "a") as archive:
        archive.writestr("results/broken.json", "{}\ninvalid\n")
    result = app._tool_dispatch_sync["import_velociraptor_collection"](
        collection_path=str(collection)
    )
    assert result["status"] == "partial"
    assert "broken.json:2" in str(result["errors"])
    assert not any(s.source_name.endswith("broken.json") for s in tmp_case_db.get_sources())
    state = json.loads(
        tmp_case_db.get_kv("velociraptor.import:" + str(collection.resolve())) or "{}"
    )
    assert state["status"] == "partial"
    assert len(state["errors"]) == 1


def test_invalid_sparse_upload_is_not_silently_extracted(
    collection: Path,
    tmp_case_db: CaseDB,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mulder.server.app as app
    from mulder.audit import AuditLog

    monkeypatch.setattr(
        app,
        "_ctx",
        SimpleNamespace(
            db=tmp_case_db,
            audit=AuditLog(tmp_path / "audit.jsonl"),
        ),
    )
    monkeypatch.setattr(app, "_cfg", SimpleNamespace(db_dir=tmp_path))
    with zipfile.ZipFile(collection, "a") as archive:
        archive.writestr("uploads/auto/C%3A/test.evtx.idx", "{}")
    with pytest.raises(CollectionError, match="Invalid sparse index"):
        app._tool_dispatch_sync["extract_velociraptor_file"](
            collection_path=str(collection),
            member_path="uploads/auto/C%3A/test.evtx",
        )


def test_mixed_evidence_context(collection: Path, tmp_path: Path) -> None:
    from mulder.orchestrator.evidence import EvidenceContext
    from mulder.server.tools.case import _manifest_entry

    (tmp_path / "LAB.E01").write_bytes(b"image placeholder")
    classified = EvidenceClassifier().classify(tmp_path)
    assert {item.artifact_type for item in classified} == {"disk_image", "velociraptor_collection"}
    manifest = _manifest_entry(next(i for i in classified if i.path == collection))
    assert "LAB" in str(manifest["collection"])
    context = EvidenceContext(str(tmp_path)).build_evidence_context("LAB")
    assert "Velociraptor offline collections" in context
    assert "Disk images:" in context
    assert "NESTED ARCHIVES" not in context
    assert "collection.zip" not in EvidenceContext(str(tmp_path)).build_evidence_context("OTHER")
    misleading = collection.rename(tmp_path / "OTHER-collection.zip")
    assert misleading.name not in EvidenceContext(str(tmp_path)).build_evidence_context("OTHER")


@pytest.mark.skipif(
    not os.environ.get("MULDER_TEST_VELOCIRAPTOR_ZIP"), reason="local evidence opt-in"
)
def test_local_collection(
    tmp_case_db: CaseDB,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit local integration check; never prints endpoint record content."""
    import mulder.server.app as app
    from mulder.audit import AuditLog

    collection_path = Path(os.environ["MULDER_TEST_VELOCIRAPTOR_ZIP"])
    monkeypatch.setattr(
        app,
        "_ctx",
        SimpleNamespace(
            db=tmp_case_db,
            audit=AuditLog(tmp_path / "audit.jsonl"),
        ),
    )
    monkeypatch.setattr(app, "_cfg", SimpleNamespace(db_dir=tmp_path))
    inventory = inspect_collection(collection_path)
    importer = app._tool_dispatch_sync["import_velociraptor_collection"]
    result = importer(collection_path=str(collection_path))
    assert result["status"] == "success", result["errors"]
    sources = tmp_case_db.get_sources()
    artifacts = [s for s in sources if ".results/" in s.source_name]
    assert len(artifacts) == inventory["artifact_count"]
    with zipfile.ZipFile(collection_path) as archive:
        expected_counts = {
            name: sum(1 for line in archive.open(name) if line.strip())
            for name in archive.namelist()
            if name.startswith("results/") and name.endswith((".json", ".jsonl"))
        }
    for source in artifacts:
        member = "results/" + source.source_name.split(".results/", 1)[1]
        assert source.line_count == expected_counts[member]
    assert result["artifact_records"] == sum(expected_counts.values())
    assert sum(s.line_count == 0 for s in artifacts) == inventory["empty_artifact_count"]
    assert tmp_case_db.search_windows("Windows", max_results=1)
    repeat = importer(collection_path=str(collection_path))
    assert repeat["status"] == "success"
    assert repeat["records"] == result["records"]
    assert len(tmp_case_db.get_sources()) == len(sources)
    with zipfile.ZipFile(collection_path) as archive:
        candidates = [
            e.filename
            for e in archive.infolist()
            if e.filename.startswith("uploads/")
            and e.filename.endswith(".evtx")
            and e.filename + ".idx" not in archive.namelist()
        ]
        member = next((n for n in candidates if n.endswith("/Security.evtx")), candidates[0])
        expected = archive.read(member)
    output = app._tool_dispatch_sync["extract_velociraptor_file"](
        collection_path=str(collection_path),
        member_path=member,
    )
    assert Path(str(output["extracted_path"])).read_bytes() == expected
    if member.endswith("/Security.evtx"):
        from Evtx.Evtx import Evtx

        with Evtx(str(output["extracted_path"])) as log:
            record = next(log.records(), None)
            assert record is not None
            assert "<Event" in record.xml()
    print(
        f"Imported {len(artifacts)} artifacts, {sum(s.line_count for s in artifacts)} rows; "
        "repeat import and uploaded EVTX byte comparison passed"
    )


@pytest.mark.skipif(
    not os.environ.get("MULDER_TEST_VELOCIRAPTOR_ZIP"), reason="local evidence opt-in"
)
def test_local_sparse_and_evtx_tools(
    tmp_case_db: CaseDB,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify every reconstructed range against stored bytes and every hole as zero."""
    import mulder.server.app as app
    from mulder.audit import AuditLog

    path = Path(os.environ["MULDER_TEST_VELOCIRAPTOR_ZIP"])
    monkeypatch.setattr(
        app,
        "_ctx",
        SimpleNamespace(
            db=tmp_case_db,
            audit=AuditLog(tmp_path / "audit.jsonl"),
        ),
    )
    monkeypatch.setattr(app, "_cfg", SimpleNamespace(db_dir=tmp_path))
    count = 0
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if not name.startswith("uploads/") or not name.endswith(".idx"):
                continue
            member = name[:-4]
            ranges = json.loads(archive.read(name))["ranges"]
            result = app._tool_dispatch_sync["extract_velociraptor_file"](
                collection_path=str(path),
                member_path=member,
            )
            output = Path(result["extracted_path"])
            assert result["sparse_reconstructed"]
            with output.open("rb") as expanded, archive.open(member) as stored:
                for segment in ranges:
                    offset = segment.get("original_offset", 0)
                    # Any implicit gaps and explicit sparse runs must contain zeros.
                    gap = offset - expanded.tell()
                    while gap:
                        block = expanded.read(min(gap, 1024 * 1024))
                        assert block and block == bytes(len(block))
                        gap -= len(block)
                    remaining = segment["length"]
                    packed = segment.get("file_length", 0)
                    assert packed in (0, remaining)
                    while remaining:
                        block = expanded.read(min(remaining, 1024 * 1024))
                        assert block
                        expected = stored.read(len(block)) if packed else bytes(len(block))
                        assert block == expected
                        remaining -= len(block)
                assert expanded.read(1) == b""
                assert stored.read(1) == b""
            assert output.stat().st_size == result["size_bytes"]
            output.unlink()  # Only the test-created reconstructed file; keep input ZIP intact.
            count += 1
        member = next(n for n in archive.namelist() if n.endswith("/Security.evtx"))
    indexed = app._tool_dispatch_sync["index_velociraptor_evtx"](
        collection_path=str(path),
        member_path=member,
        event_ids=[4624],
    )
    assert indexed["records"] > 0
    found = tmp_case_db.search_windows("4624", source_name=indexed["source_name"], max_results=1)
    assert found and found[0][0].event_time is not None
    print(
        f"Reconstructed and verified {count} sparse files; "
        f"indexed {indexed['records']} logon events"
    )
