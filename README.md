# LibIdentifier

Development status: pre-production prototype, not ready for production deployment. Review the documented coverage and resource-safety limitations before integration.

Development: [roadmap](docs/development/roadmap.md),
[Stage 2 acceptance](docs/development/stages/stage-2.md),
[initial release checklist](docs/development/release-readiness.md),
[contributor entry point](AGENTS.md). Historical proposals are archived; the
[integration guide](docs/integration.md) is the public contract authority.

LibIdentifier is a small offline Python package and CLI for identifying known compiled Android and native components from local reference profiles. The current engine supports APK/ZIP, standalone DEX, standalone ELF, and directories containing those files.

It uses LIEF for DEX and ELF parsing, SQLite for local reference profiles, and standard-library archive handling. Identification never calls the network or executes submitted binaries. Optional advisory assessment invokes a verified local OSV-Scanner in full offline mode. The CLI can download a missing Maven advisory database during setup; `--offline` prohibits that download.

Stage 2 adds unattributed code clusters, typed code/component relationships,
published reference dependency declarations, and analysis evidence/coverage.
Profile schema 2 requires an explicit rebuild; public JSON remains schema 1.
Complete enrichment has a measurable memory/runtime cost and can be disabled
selectively; see the [integration guide](docs/integration.md).

## Install

Preview `0.2.0rc1` package and profile publication are being prepared. See
[release/install instructions](docs/releases.md) for the current manual steps;
PyPI and default profile-download commands require publication first.


```powershell
python -m pip install -e .
```

The project targets Python 3.11+ and pins `lief==0.17.1`.

For setup, profile database creation and first scans, see [docs/quickstart.md](docs/quickstart.md).

For the public Python/JSON contract, reference provisioning, error handling and Stage 3 compatibility policy, see [docs/integration.md](docs/integration.md).

## CLI

```powershell
libidentifier inspect app.apk --format json --output inspect.json
libidentifier identify app.apk --profiles profiles.sqlite --format json --output libraries.json
libidentifier identify app.apk --profiles profiles.sqlite --format table
libidentifier profiles build library.dex --purl pkg:maven/example/library@1.0.0 --database profiles.sqlite
libidentifier profiles build libfoo.so --purl pkg:generic/foo@1.2.3 --database profiles.sqlite
libidentifier profiles validate profiles.sqlite
libidentifier sbom libraries.json --output components.cdx.json
```

JAR and AAR profile building requires an explicit local D8 executable:

```powershell
libidentifier profiles build library.jar --purl pkg:maven/example/library@1.0.0 --database profiles.sqlite --d8 C:\Android\build-tools\...\d8.bat --android-jar C:\Android\platforms\android-35\android.jar
```

## Python API

```python
from pathlib import Path
from libidentifier import IdentifyOptions, build_profile, identify, inspect, export_cyclonedx

build_profile(
    Path("library.dex"),
    purl="pkg:maven/example/library@1.0.0",
    database=Path("profiles.sqlite"),
)

result = identify(Path("app.apk"), profiles=Path("profiles.sqlite"), options=IdentifyOptions())
result.write_json(Path("libraries.json"))

summary = inspect(Path("app.apk"))
export_cyclonedx(result, Path("components.cdx.json"))
```

## Identification capabilities

- DEX class-shape fingerprints using canonical `dex-shape-v2` (old profiles require an explicit rebuild).
- Exact ELF identity using `elf-identity-v1`, primarily whole-file SHA-256.
- Multiple DEX files in one APK.
- Multiple libraries in the same DEX when their reference shapes are strong and non-overlapping.
- Unknown classes and parser errors as explicit output, not silent success.
- Separate evidence-backed framework presence hints for Flutter, React Native, Jetpack Compose, Cordova, Unity and Xamarin / .NET MAUI, with exact locations and analysis limitations. These do not inventory framework application logic or infer framework versions.

Structural DEX matches normally identify the library family only. Exact versions are reported only when a strong exact-version signal is available, such as an exact trusted artifact hash or exact ELF identity. Otherwise `version` remains `null` and `version_candidates` lists bounded compatible releases.

## Limitations

- Optional Maven advisory assessment requires a trusted, compatible OSV-Scanner v2 executable and a provisioned local snapshot. GitHub and package-manager installations are supported; v2.6.0 and v2.7.0 are tested. It does not establish reachability or exploitability.
- No JavaScript, Hermes, Dart AOT, Flutter package, or npm dependency identification.
- DEX matching is conservative and shape-based; aggressive R8/ProGuard transformations may reduce confidence or prevent matches.
- Detection thresholds are configurable starting points, not calibrated accuracy claims.
- JAR/AAR ingestion is a trusted profile-build operation and depends on user-supplied local D8.

## Test Fixtures

The tests generate small synthetic DEX/APK/ELF binaries during the run. They do not vendor third-party libraries and do not mock LIEF parser objects.

## Complete Output and Offline Advisories

API/JSON results include all parsed unmatched classes by default. Optional `--max-unknown-classes` caps affect output only and retain original counts; file JSON output streams to an atomic replacement.

Scanner discovery accepts `osv-scanner` / `osv-scanner.exe` and the original Windows/Linux amd64/arm64 release filenames, so renaming is optional. Darwin binaries are unsupported; `osv-scanner_SHA256SUMS` is a checksum file. Missing-scanner warnings include the [release download page](https://github.com/google/osv-scanner/releases).

Table output aligns library identity scores, unknown versions/reference candidates and advisory summaries, with a separate vulnerability section when requested. Advisory attribution requires a score of at least 0.75 by default (`--min-identity-score` configures it); categorical medium matches can qualify. Confirmed and potential findings remain distinct, and affected ranges preserve the OSV boundaries.

```sh
libidentifier vulnerabilities update --database advisory-db --ecosystem Maven
libidentifier vulnerabilities validate --database advisory-db
libidentifier identify app.apk --profiles profiles.sqlite --vulnerabilities --format table
libidentifier identify app.apk --profiles profiles.sqlite --vulnerabilities --offline --output assessment.json
libidentifier scan app.apk --profiles profiles.sqlite --vulnerabilities --osv-scanner /opt/tools/osv-scanner --osv-db advisory-db --output assessment.json
libidentifier correlate inventory.json --osv-scanner /opt/tools/osv-scanner --osv-db advisory-db --format table
```

Install a native v2 executable through [official installation channels](https://google.github.io/osv-scanner/installation/) or [GitHub releases](https://github.com/google/osv-scanner/releases) on PATH or in the working directory; `winget install Google.OSVScanner` is supported, and `--osv-scanner` preserves explicit selection. Compatibility is checked by version and required offline flags, rather than a single-release hash list. `--osv-scanner-sha256` optionally pins a publisher-verified executable digest. The CLI selects `./advisory-db`, then the user cache, or an explicit `--osv-db`. A missing database is provisioned automatically unless `--offline` is set; existing stale/corrupt databases require explicit `update`. Missing scanners warn and retain identification with explicit unassessed JSON. Python APIs remain download-free. Assessment never uploads APKs or inventories, and candidate versions are never installed-version claims. See [the integration guide](docs/integration.md) for APIs, cache locations, offline behavior and stable result contracts.
