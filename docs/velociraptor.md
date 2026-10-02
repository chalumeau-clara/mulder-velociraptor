# Offline Velociraptor collections

This fork accepts an unencrypted offline collector ZIP as evidence alongside
disk images, memory dumps and other existing inputs. It does not need a running
Velociraptor server or execute VQL or collected binaries.

## Workflow

Place the collection in your evidence directory, optionally alongside an image
and a `MULDER.md` investigator briefing. Use the existing entry point:

```sh
mulder investigate /path/to/evidence case-id
```

The catalog recognizes `client_info.json`, `collection_context.json`, and
`requests.json` inside the ZIP. The new tools are:

| Tool | Purpose |
|---|---|
| `inspect_velociraptor_collection(collection_path, upload_offset=0, upload_limit=100)` | Host metadata, artifact inventory, and paginated exact ZIP upload names |
| `import_velociraptor_collection(collection_path)` | Import artifact JSONL, metadata, upload mappings and collection logs |
| `extract_velociraptor_file(collection_path, member_path)` | Extract an upload, automatically reconstructing sparse content |
| `index_velociraptor_evtx(collection_path, member_path, event_ids=None)` | Index uploaded EVTX records and event timestamps without disk-image extraction state |

The planner imports the ZIP directly, rather than using generic archive
extraction. Search `velociraptor.*` sources with the normal `search` and
`get_raw_output` tools. Source names contain hostname, full container SHA-256,
and exact member name. Source paths point to the original ZIP. Physical JSONL
line numbers are retained. Metadata documents are serialized as single records.

One source is created for each result member, including empty results. Unknown
artifacts remain searchable. Each source is committed atomically and repeated
imports skip completed sources. Invalid members are reported in an explicit
`partial` result without discarding successfully imported sources. Per-source
transactions allow retry after interruption. Imports are streamed in batches of
500 records (also flushed at 4 MiB of record text), without loading the full
collection into memory.

The import reports actual artifact row counts separately from the collector's
`total_collected_rows` counter; they are not assumed to match. The container
hash identifies the input, and `windows_hash` commits to the indexed text.

For collected files, use exact member names from the inspection tool's
`uploads` list; page with `next_upload_offset`. Do not pass `vfs_path` directly:
it may be a Windows endpoint path rather than a ZIP path. Extraction uses hashed
local filenames while returning the original member and container hash. It
preserves a safe extension so file-based tools can discover EVTX files.
Hayabusa accepts `evtx_dir`, and Chainsaw accepts `evidence_path`. The existing
`index_evtx_file` tool requires disk-image extraction state and is not used here.

## Current limits

- ZIP only, with the offline collector layout above. Server/hunt exports and
  extracted directories are not yet supported.
- Protected containers are detected and require local decryption first.
- Sparse uploads with valid `.idx` sidecars are reconstructed automatically.
  Invalid maps fail explicitly; the 2 GiB limit applies to expanded content.
- Fifteen explicit artifact/source timestamp mappings populate the timeline.
  Unknown schemas remain searchable but have no inferred event time.
- Limits: 100,000 ZIP entries, 128 GiB total declared uncompressed size,
  8 MiB per metadata document or JSONL record, and 2 GiB per extracted upload.
- Specialized analysis helpers using existing hard-coded source names do not
  automatically interpret arbitrary Velociraptor schemas.
- A collection is a selection of artifacts. Missing/empty results do not prove
  that an activity did not occur. Collection logs and errors remain evidence.

## Validation

Synthetic tests exercise recognition, generic ZIP compatibility, protected and
unsafe archives, empty/invalid results, per-source rollback, repeat imports,
search, uploaded file extraction, sparse reconstruction, and mixed image/collection
context. They do not require or publish endpoint evidence:

```sh
python -m pytest tests/test_velociraptor.py tests/test_classifier.py tests/test_db.py
```

An opt-in integration test imports a real collection and checks every result's
row count against the ZIP, repeats the import, performs a search, and compares
one extracted EVTX byte-for-byte. When a Security.evtx is available, it also
parses an event using python-evtx. In PowerShell:

```powershell
$env:MULDER_TEST_VELOCIRAPTOR_ZIP = (Get-ChildItem tests/Velociraptor/*.zip).FullName
.venv/Scripts/python.exe -m pytest tests/test_velociraptor.py::test_local_collection -q -s
```

`tests/Velociraptor/` is ignored by Git. Keep real collections local; CI uses
generated fixtures. Full autonomous report validation and execution of native
forensic binaries should be performed in the supported Linux/SIFT or container
environment with the required model configuration.

Local validation of the supplied example found 121 result members (83 empty)
and 692,405 actual result rows, versus 689,474 reported in collection metadata.
The integration check uses the actual per-member lines as its reference, not
the aggregate metadata counter. A second optional test reconstructs all 29 sparse
uploads and independently verifies stored ranges and zero-filled holes, then
indexes Security logon events with timestamps:

```powershell
.venv/Scripts/python.exe -m pytest tests/test_velociraptor.py::test_local_sparse_and_evtx_tools -q -s
```

## Sparse reconstruction and timestamps

A sparse upload omits zero-filled regions. The `.idx` sidecar describes where
stored bytes belong in the original logical file. For example, stored `ABCD`
may represent `AB`, three zero bytes, then `CD`: a seven-byte logical file.
Parsing compact bytes directly would shift offsets. The earlier MVP refused
these files; `velociraptor_sparse.py` now reconstructs them automatically.

All ranges are validated before writing: integer fields, nonnegative offsets,
nonoverlapping logical ranges, contiguous packed offsets, full stored-byte
coverage and expanded-size limits. Output is streamed and published atomically.
Returned provenance includes ZIP, compact-file, expanded-file and sidecar hashes.
The implementation follows [Velociraptor's container writer](https://github.com/Velocidex/velociraptor/blob/master/reporting/container.go)
and its [file collection format](https://docs.velociraptor.app/docs/file_collection/).

`velociraptor_time.py` maps EVTX, RDP, process creation, USN, BAM, recycle-bin,
RecentApps, registry, services, shellbags and three Amcache source timestamps.
Only complete timezone-aware ISO dates are normalized to UTC microseconds;
original JSON/XML retains its precision and offsets. Numeric epochs, date-only
values, naive timestamps, invalid dates and pre-1970 sentinel dates are not
guessed. Versioned backfill adds timestamps to older imports without changing
source/window IDs or raw hashes. Database comparisons normalize offsets and
fractions so existing image sources and collection events can share a timeline.

## Pipeline and end-to-end checks

The catalog, extraction planner, analyst and report prompts now describe the
collection tools, timestamp semantics and collection limits. Host association
uses metadata, with filename fallback only if a hostname is missing. Import
status is tracked separately for each ZIP: importing one collection cannot
hide another missing or partial import. Extraction gates expose that remaining
work. An artifact and the same data parsed from its upload must not be counted
as independent corroboration.

`test_velociraptor_workflow.py` exercises actual tools, database, audited
citations, findings, readiness gates and Markdown/HTML report generation. Its
two variants use a collection alone and a collection plus a real generated
ext4 image parsed with Sleuth Kit. Linux needs `sleuthkit` and `e2fsprogs`; CI
installs them. Findings are scripted synthetic observations. This checks the
integration contract, not an autonomous model's investigative judgement.

```sh
python -m pytest tests/test_velociraptor*.py tests/test_db.py
python -m pytest tests/ -q
```

No model training is needed: these are deterministic format readers and explicit
schema adapters. New artifact support needs documented field semantics and
regression fixtures. A live autonomous investigation remains a separate check
requiring configured model access. Protected-container decryption and additional
export layouts remain outside this offline unencrypted ZIP implementation.

## Validation recorded on 2026-10-01

- Ubuntu/WSL, Python 3.12: complete suite **1,687 passed, 8 skipped**. Skips:
  five optional radare2 tests, one optional Hayabusa binary test and the two
  opt-in private-evidence tests. Both collection-only and mixed-image report
  workflows passed, using real Sleuth Kit for the generated image.
- Private-evidence tests run separately on Windows: import/reimport and EVTX
  byte comparison passed; all **29 sparse files** reconstructed and verified;
  **1,537 Security logon events** indexed with event timestamps.
- Ruff lint and formatting passed; `git diff --check` passed. Focused mypy
  passed for 15 implementation/test files. Full mypy still reports the existing
  `AsyncIterator.aclose` annotation error in `orchestrator/session.py:569`, also
  with the SDK version specified by `uv.lock`; that file was not changed.
- Runtime authentication check returned `loggedIn: false`. No live autonomous
  model investigation was run, and no private collection data was sent to one.
