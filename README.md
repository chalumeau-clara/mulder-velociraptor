# Mulder Velociraptor

**A fork of [calebevans/mulder](https://github.com/calebevans/mulder) that adds support for offline Velociraptor collector ZIPs.** Analyze a collection on its own or alongside disk images, memory dumps, network captures and other evidence supported by Mulder.

The original Mulder project and investigation architecture were created by Caleb Evans and upstream contributors. The SANS Find Evil Hackathon award and published upstream benchmarks belong to that project; they are not results obtained by this fork. See the [upstream README](https://github.com/calebevans/mulder#readme) for that work.

This fork retains the `mulder` command and `mulder-dfir` Python package name. Install from **this repository** to get the Velociraptor additions. Installing `mulder-dfir` from PyPI or using the upstream container does not install this fork.

## What this fork adds

| Capability | What it does |
|---|---|
| Offline collection detection | Recognizes collector ZIP metadata and identifies the collected host and artifact inventory. |
| Result import | Imports JSON/JSONL artifact results, metadata, upload mappings and collection logs into Mulder's SQLite/FTS index. |
| Custom artifacts | Preserves and indexes unknown schemas, including `Windows.Triage.Targets` sources, without requiring a hard-coded artifact list. |
| Provenance and retries | Tracks container SHA-256, member names and source lines; repeated imports avoid duplicate records, and malformed sources produce explicit errors. |
| Artifact timelines | Uses 15 explicit artifact/source timestamp mappings, normalizes supported dates to UTC and retains original fields. |
| Uploaded files | Extracts files on demand for compatible parsers and reconstructs sparse uploads using their `.idx` sidecars. |
| Direct EVTX indexing | Parses uploaded event logs without requiring a disk image or prior disk-extraction state. |
| Mixed evidence | Integrates collections into cataloging, extraction planning, analysis and reporting alongside existing evidence types. |
| Import coverage | Tracks each collection independently so missing or partial imports remain visible. |

The four added MCP tools are:

- `inspect_velociraptor_collection`
- `import_velociraptor_collection`
- `extract_velociraptor_file`
- `index_velociraptor_evtx`

Importing every result does **not** mean every record has been investigated. Unknown artifacts are searchable, but specialized interpretation and timeline support require suitable field mappings. A process list alone cannot establish that a process is hidden or contains injected code; those conclusions require appropriate evidence.

No model training on the collection is required. Format readers and schema adapters prepare evidence for the existing investigation tools and the model using them. See [Offline Velociraptor collections](docs/velociraptor.md) for implementation details and limits.

## How it works

Mulder's autonomous investigation has five phases:

1. **Catalog:** identify evidence types, systems and collection metadata.
2. **Extraction:** import artifact results, run applicable forensic tools and index their output.
3. **Correlation:** connect observations across sources and systems.
4. **Alternative narrative:** challenge conclusions and check evidence coverage.
5. **Report:** produce findings, timelines, Markdown/HTML reports and optional IOC exports.

The orchestrator applies quality gates between phases. MCP tools record audited calls, and submitted findings must cite valid tool-call references. These checks establish traceability; they do not guarantee that a model's interpretation is correct.

You can use the same tools interactively through `mulder serve`. In that mode, your MCP client drives the investigation; it does not automatically run the orchestrator's five-phase workflow.

## Install on SIFT or Linux with uv

Use Linux/SIFT for the native forensic toolchain. The project requires Python 3.10 or newer; the commands below use Python 3.12. Start with Git and [uv](https://docs.astral.sh/uv/) installed.

```bash
git clone https://github.com/chalumeau-clara/mulder-velociraptor.git
cd mulder-velociraptor

uv python install 3.12
uv sync --locked --python 3.12

.venv/bin/mulder serve --help
```

`uv sync` installs the checkout into its own `.venv`. It does not replace an existing global Mulder installation. Use the fork's absolute executable path in MCP configurations to select the right version.

If you already copied this repository onto SIFT, run the commands from `uv python install` onward inside that directory. The directory must contain `pyproject.toml`, `uv.lock` and `src/`.

For additional forensic integrations:

```bash
uv sync --locked --python 3.12 --extra forensics
.venv/bin/mulder setup
```

`setup` downloads managed rules and helper tools. Native system tools such as Sleuth Kit and Plaso must also be installed when an analysis needs them; SIFT already provides many of these. JSON import and direct python-evtx parsing do not require the full optional toolchain. See the [usage guide](docs/usage-guide.md#native-install).

### Keep an existing Mulder installation

Use separate executable, case and workspace paths:

```text
Original executable:  ~/.local/bin/mulder
Fork executable:      ~/mulder-velociraptor/.venv/bin/mulder
Fork case directory:  ~/mulder-cases-velo
Fork workspace:       ~/mulder-workspace-velo
```

The original executable location may differ on your system. If you installed this fork into `.venv-uv` or a folder named `mulder-velociraptor-test`, substitute those paths in the examples below.

## Use as an MCP server

For a desktop MCP client supporting local commands, add a separate server entry. Replace `/home/USER` with your actual Linux home directory:

```json
{
  "mcpServers": {
    "mulder-velociraptor": {
      "command": "/home/USER/mulder-velociraptor/.venv/bin/mulder",
      "args": [
        "serve",
        "--transport", "stdio",
        "--db-dir", "/home/USER/mulder-cases-velo"
      ]
    }
  }
}
```

Merge this entry into your client's existing configuration. Keep the original Mulder entry if you want both versions available. The client starts the server; you do not need to launch another copy in a terminal. Stdio does not use a listening network port.

### Connect a Windows MCP client to SIFT over SSH

Configure SSH key authentication and verify that the connection works without an interactive password prompt. Then use this entry, replacing the username, address and key path:

```json
{
  "mcpServers": {
    "mulder-velociraptor-sift": {
      "command": "C:/Windows/System32/OpenSSH/ssh.exe",
      "args": [
        "-T",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=15",
        "-i", "C:/Users/YOUR_USER/.ssh/sift_ed25519",
        "USER@SIFT_IP",
        "/home/USER/mulder-velociraptor/.venv/bin/mulder",
        "serve",
        "--transport", "stdio",
        "--db-dir", "/home/USER/mulder-cases-velo"
      ]
    }
  }
}
```

In a client with separate argument fields, enter each array element in its own field. This configuration is for clients that can launch local processes, not a web-only MCP connection form.

Evidence paths supplied to tools must exist **on SIFT**. The ZIP and case database stay there, but tool responses are sent to the MCP client and its model provider for analysis. `serve` itself does not require the autonomous orchestrator's Claude credentials.

### First collection investigation

Place your ZIP in a dedicated evidence directory, for example `/home/USER/evidence-velo`. Keep generated cases outside that directory. Enable only the fork's MCP connection for this test and send:

```text
Use only the Mulder Velociraptor MCP connection.

Verify that inspect_velociraptor_collection and
import_velociraptor_collection are available.

Create case velo-test-001 using scan_evidence on /home/USER/evidence-velo.
If that case exists, verify its evidence source and resume without overwriting it.
Inspect every collection and paginate through its complete inventory.
Import all supported results and report import errors and actual row counts.

Build a coverage table for every artifact/source: record count, data type,
analysis status and limitations. Include custom artifacts and empty results.
Examine the available process, network, persistence, authentication, execution,
file and registry evidence. Correlate observations and test legitimate explanations.
Do not treat imported data as fully analyzed, or samples as exhaustive coverage.

Preserve the original evidence. You may write case indexes, audit logs and reports.
Ask before extracting collected files or reconstructing sparse uploads, including
calls to index_velociraptor_evtx that implicitly extract a file. Never execute
collected programs or send evidence to external lookup services without approval.

Cite evidence references, distinguish confirmed observations from hypotheses,
and report all incomplete analysis and missing data before finalizing a report.
```

Replace the example evidence path before sending. Extraction approval in this prompt is a client instruction, not a server-side permission mechanism. Restrict tool access in your client when enforcement is required.

## Run an autonomous investigation

Configure a model provider supported by Mulder first; see [provider setup](docs/usage-guide.md). Activate the fork's environment so subprocesses also resolve the correct `mulder` command:

```bash
cd ~/mulder-velociraptor
source .venv/bin/activate

mulder investigate /home/USER/evidence-velo velo-test-001 \
  --db-dir "$HOME/mulder-cases-velo" \
  --cwd "$HOME/mulder-workspace-velo"
```

This mode runs the orchestrator and requires its configured model credentials. Use a separate case ID if you want to keep an interactive test and an autonomous run distinct. An optional `MULDER.md` in the evidence directory can describe investigation questions, known facts and scope.

For container deployments, build this checkout rather than pulling the upstream release:

```bash
docker build -t mulder-velociraptor:local .
```

Use that image name with the mounts and provider configuration described in the [container guide](docs/usage-guide.md#running-a-container).

## Supported collection format and limits

- Unencrypted offline collector ZIPs with `client_info.json`, `collection_context.json` and `requests.json` metadata.
- Results under `results/` with `.json` or `.jsonl` extensions, containing one JSON object per line. Arbitrary multiline JSON documents or top-level arrays are not generic result input formats.
- Protected containers are detected but need local decryption first. Server/hunt exports and extracted collection directories are not supported yet.
- Sparse `.idx` maps are validated before reconstruction; malformed maps fail explicitly.
- Limits include 100,000 ZIP entries, 128 GiB declared uncompressed total, 8 MiB per metadata document or result line, and 2 GiB per extracted/reconstructed upload.
- Unknown schemas retain their original fields but do not receive guessed event timestamps.
- Missing or empty artifacts do not prove that activity did not occur. A result and a parser output derived from the same collected data are not independent corroboration.

## Validation

The recorded Linux validation passed **1,687 tests**, with eight optional tests skipped. It included generated collection-only and collection-plus-ext4-image workflows through audited findings and Markdown/HTML reports, using real Sleuth Kit for the image.

Separate local-evidence checks imported 692,405 rows from 121 artifact result members, verified repeat imports, reconstructed all 29 sparse uploads and indexed 1,537 Security logon events with timestamps. These figures describe one test collection, not a general accuracy benchmark. Private evidence is excluded from Git and CI.

The end-to-end workflow tests use scripted synthetic observations. A live autonomous model investigation of the collection has not been validated. See the [detailed validation record](docs/velociraptor.md#validation-recorded-on-2026-10-01), including the existing full-mypy limitation.

Run tests locally:

```bash
uv sync --locked --python 3.12 --extra dev
uv run --locked --extra dev pytest tests/ -q
```

The mixed-image test needs `sleuthkit` and `e2fsprogs`; CI installs them. Optional private-evidence tests are documented separately and do not run against uploaded endpoint data in CI.

## Documentation

| Document | Contents |
|---|---|
| [Offline Velociraptor collections](docs/velociraptor.md) | Format, import behavior, timestamps, sparse reconstruction and tests |
| [Usage guide](docs/usage-guide.md) | Existing CLI, provider and forensic runtime configuration |
| [Architecture](docs/architecture.md) | Orchestrator phases, roles and quality gates |
| [Tool manifest](docs/tool-manifest.md) | MCP tools, including the four Velociraptor additions |
| [Adding tools](docs/adding-tools.md) | Contributor guide |
| [Upstream examples](https://github.com/calebevans/mulder/tree/main/examples) | Original Mulder reports and benchmarks |

## License and attribution

Apache-2.0; see [LICENSE](LICENSE). This fork builds on [Mulder by Caleb Evans and its contributors](https://github.com/calebevans/mulder). Upstream attribution and license notices are retained.
