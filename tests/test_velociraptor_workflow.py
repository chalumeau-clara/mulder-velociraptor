"""Real tool/database/report path; scripted evidence reasoning, no LLM or network.

The image variant creates an actual ext4 filesystem and calls installed Sleuth
Kit. These tests validate the integration contract, not a model's judgement.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from mulder.orchestrator.gates import (
    validate_catalog,
    validate_cross_system,
    validate_extraction,
    validate_narrative,
    validate_report,
)


@pytest.mark.parametrize(
    "with_image", [False, True], ids=["collection-only", "image-and-collection"]
)
def test_workflow_to_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_image: bool
) -> None:
    import mulder.server.app as app

    if with_image and not all(shutil.which(t) for t in ("mkfs.ext4", "debugfs", "fls")):
        pytest.skip("Linux filesystem tools and Sleuth Kit required")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    collection = evidence / "LAB.zip"
    observations = [
        (
            "Windows.System.Pslist",
            {
                "Name": "powershell.exe",
                "CommandLine": "powershell marker-alpha",
                "CreateTime": "2026-01-02T12:34:56Z",
            },
            "alpha",
        ),
        (
            "Windows.Forensics.Bam",
            {"Binary": "marker-beta.exe", "Bam_time": "2026-01-02T12:35:56Z"},
            "beta",
        ),
        (
            "Windows.Forensics.RecycleBin",
            {"Name": "marker-gamma.txt", "DeletedTimestamp": "2026-01-02T12:36:56Z"},
            "gamma",
        ),
    ]
    with zipfile.ZipFile(collection, "w") as archive:
        archive.writestr("client_info.json", '{"Hostname":"LAB","OS":"windows"}')
        archive.writestr(
            "collection_context.json", '{"session_id":"F.fixture","total_collected_rows":3}'
        )
        archive.writestr("requests.json", "{}")
        for artifact, record, _ in observations:
            archive.writestr(f"results/{artifact}.json", json.dumps(record) + "\n")
        archive.writestr("uploads/auto/sparse.bin", b"ABCD")
        archive.writestr(
            "uploads/auto/sparse.bin.idx",
            json.dumps(
                {
                    "ranges": [
                        {"file_length": 2, "length": 2},
                        {"file_offset": 2, "original_offset": 2, "length": 3},
                        {"file_offset": 2, "original_offset": 5, "file_length": 2, "length": 2},
                    ]
                }
            ),
        )
    image = evidence / "LAB.dd"
    if with_image:
        root = tmp_path / "filesystem"
        root.mkdir()
        (root / "marker-alpha.txt").write_text("Synthetic image evidence", encoding="utf-8")
        with image.open("wb") as output:
            output.truncate(16 * 1024 * 1024)
        subprocess.run(
            ["mkfs.ext4", "-q", "-F", "-d", str(root), str(image)], check=True, capture_output=True
        )

    monkeypatch.setattr(app, "_ctx", None)
    monkeypatch.setattr(app, "_cfg", app.ServerConfig(db_dir=tmp_path / "cases"))
    monkeypatch.setattr(app, "_job_store", None)
    monkeypatch.delenv("MULDER_CASE_ID", raising=False)
    call = app._tool_dispatch_sync
    try:
        scanned = call["scan_evidence"](evidence_path=str(evidence), case_id="velo-workflow")
        assert scanned["case_id"] == "velo-workflow"
        catalog = {
            "case_id": "velo-workflow",
            "evidence_root": str(evidence),
            "systems": [{"name": "LAB", "evidence": ["velociraptor_collection"]}],
        }
        assert validate_catalog(catalog).passed
        assert call["get_investigation_summary"]()["collection_import_gaps"]
        imported = call["import_velociraptor_collection"](collection_path=str(collection))
        assert imported["artifact_records"] == 3
        assert imported["status"] == "success"
        if with_image:
            listed = call["run_fls"](image_path=str(image), partition_offset=0)
            assert listed.get("status") != "error", listed
            hit = call["search"](query="alpha", source="tsk.filelist", evidence_path=str(image))
            assert hit["result_count"] > 0
            sources = app.get_ctx().db.get_sources()
            assert {s.extractor for s in sources} >= {"velociraptor", "sleuthkit"}
        assert validate_extraction(call["get_investigation_summary"]()).passed
        timeline = call["get_timeline"](
            t_start="2026-01-02T12:00:00Z", t_end="2026-01-02T13:00:00Z"
        )
        assert timeline["total_events"] >= 3

        for artifact, record, marker in observations:
            searched = call["search"](query=marker, evidence_path=str(collection))
            assert searched["result_count"] >= 1
            source = next(
                s.source_name
                for s in app.get_ctx().db.get_sources()
                if s.source_name.endswith(f"results/{artifact}.json")
            )
            finding = call["submit_finding"](
                title=f"Synthetic fixture observation: {marker}",
                description=json.dumps(record),
                severity="info",
                confidence="inference",
                sources=[source],
                evidence_refs=[searched["tool_call_id"]],
                mitre_attack_ids=["T1059.001"] if marker == "alpha" else [],
            )
            assert "finding_id" in finding, finding
        assert validate_cross_system(call["get_investigation_summary"]()).passed
        forged = call["submit_finding"](
            title="Invalid citation fixture",
            description="Must be rejected",
            severity="info",
            confidence="inference",
            evidence_refs=["tc_nonexistent"],
            sources=[],
        )
        assert forged["status"] == "error"
        extracted = call["extract_velociraptor_file"](
            collection_path=str(collection),
            member_path="uploads/auto/sparse.bin",
        )
        assert Path(extracted["extracted_path"]).read_bytes() == b"AB\0\0\0CD"
        call["audit_evidence_coverage"]()
        coverage = call["audit_tool_coverage"]()
        assert "import_velociraptor_collection" in str(coverage)
        call["submit_narrative"](
            narrative=(
                "Synthetic integration fixture, not an incident assessment. Three timestamped "
                "observations were imported from the LAB offline collection. The process command "
                "uses PowerShell (T1059.001); this alone does not establish malicious intent. "
                "The BAM and Recycle Bin entries document execution and deletion observations. "
                "Uncollected evidence is a gap, not a negative finding."
            )
        )
        readiness = call["check_finalize_readiness"]()
        assert readiness["ready_to_finalize"], readiness
        assert validate_narrative(call["get_investigation_summary"](), readiness).passed
        report = call["finalize_report"]()
        assert "report_path" in report, report
        report_path = Path(report["report_path"])
        assert validate_report(["finalize_report"], report_path, readiness).passed
        assert "alpha" in report_path.read_text(encoding="utf-8")
        assert Path(report["html_report_path"]).is_file()
        assert len(app.get_ctx().db.get_findings()) == 3
        # Importing one collection must not mark a second ZIP as processed.
        second = evidence / "second.zip"
        shutil.copyfile(collection, second)
        coverage = call["audit_tool_coverage"]()
        pending = next(item for item in coverage["coverage"] if item["path"] == str(second))
        assert pending["tools_not_run"] == ["import_velociraptor_collection"]
    finally:
        if app._ctx is not None:
            app._ctx.db.close()
