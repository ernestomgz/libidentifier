# Public integration guide

LibIdentifier is an independent, offline Python package for identifying known third-party libraries in APK, DEX and ELF inputs. Library matches use a local SQLite reference database. Framework detection is a separate static presence assessment and does not need that database. Optional offline advisory assessment correlates reliable package identities using an approved OSV-Scanner executable and a separately provisioned local database. Identification and advisory matches do not establish reachability or exploitability.

This document defines the public scan integration contract. Stage 3 may replace fingerprints, matchers and databases while preserving this contract. The technical specification describes the original design; verified current code and this guide take precedence over its illustrative examples and proposed thresholds.

## Installation and requirements

Supported platforms: Windows and Linux. Python 3.11 or newer is required. Install from a reviewed checkout of this repository (there is no requirement for a public package registry release):

```sh
python -m venv .venv
```

Activate on Linux with `. .venv/bin/activate`, or on Windows PowerShell with `.\.venv\Scripts\Activate.ps1`, then, from the repository root:

```sh
python -m pip install .
libidentifier --version
```

Installation pins `lief==0.17.1`; SQLite and archive processing use the Python standard library. Java and Android SDK D8 are needed only when provisioning JAR/AAR reference profiles. Scanning does not require them or access the network. Use paths appropriate to your machine; scan paths and database paths accept strings or `pathlib.Path` objects.

## Provision and select references

No reference database is silently downloaded, created or selected by the Python scan API. `identify()` requires the keyword argument `profiles`. An empty valid database can produce no matches; that is different from a missing database, which raises `ProfileError`. Framework results are independent of catalog coverage.

From a checkout containing `catalog/references.json`, explicitly fetch its pinned artifacts:

```sh
libidentifier profiles fetch --catalog catalog/references.json --cache reference-artifacts
```

For the bundled catalog's JAR/AAR references, rebuild with your local SDK paths:

```sh
libidentifier profiles rebuild --catalog catalog/references.json --cache reference-artifacts --database profiles.sqlite --d8 /opt/android-sdk/build-tools/36.1.0/d8 --android-jar /opt/android-sdk/platforms/android-35/android.jar --offline
libidentifier profiles validate profiles.sqlite
```

On Windows, substitute e.g. `--d8 C:\Android\Sdk\build-tools\36.1.0\d8.bat --android-jar C:\Android\Sdk\platforms\android-35\android.jar`. Java must be available to D8. `--offline` requires all catalog artifacts already cached; omit it to allow explicit maintenance-time downloads. Catalog entries have explicit versioned PURLs, URLs and SHA-256 hashes; no automatic upstream version discovery occurs.

A self-contained alternative for a trusted DEX/ELF reference needs no SDK:

```sh
libidentifier profiles build library.dex --purl pkg:maven/example/library@1.0.0 --database profiles.sqlite
libidentifier profiles build libfoo.so --purl pkg:generic/foo@1.2.3 --database profiles.sqlite
```

The small bundled catalog is for validation, not comprehensive coverage. Provision databases centrally, validate them before distributing, and retain the reviewed catalog and rebuild manifest for reference provenance. `profiles rebuild` stages a replacement database and publishes it after success; distribute a completed, immutable copy to workers. Do not replace or modify a database during a scan.

The CLI chooses `--profiles` first, otherwise `LIBIDENTIFIER_PROFILES`. The Python API does **not** read that environment variable. `inspect()` needs no database and performs parsing and framework assessment without library matching.

## Complete Python scan and processing example

Save as `scan.py`. After provisioning `profiles.sqlite`, run `python scan.py app.apk profiles.sqlite`. This example handles fatal failures separately from incomplete scans, processes all result categories, and saves the entire result for evidence persistence.

```python
import sys
from pathlib import Path

from libidentifier import IdentifyOptions, export_cyclonedx, identify
from libidentifier.errors import InputError, ProfileError


def scan(input_path: Path, database: Path) -> int:
    try:
        result = identify(input_path, profiles=database, options=IdentifyOptions())
    except (InputError, ProfileError) as exc:
        print(f"Scan unavailable: {exc}", file=sys.stderr)
        return 1

    result.write_json(Path("scan-result.json"))
    export_cyclonedx(result, Path("scan-result.cdx.json"))
    print("Input:", result.input.path, result.input.sha256)
    print("Database:", result.profile_database.sha256)
    for component in result.components:
        print("Library:", component.component_id, component.name,
              "identity confidence:", component.identity_confidence,
              "package identity:", component.family_purl)
        if component.version is None:
            print("Version unknown; reference candidates:", component.version_candidates)
        else:
            print("Version:", component.version, component.version_confidence,
                  "PURL:", component.purl)
        for location in component.matched_code:
            print("Evidence:", location.container, location.member,
                  location.class_descriptor, location.sha256)
        for limitation in component.limitations:
            print("Library limitation:", limitation)

    for framework in result.frameworks_detected:
        print("Framework:", framework.framework_id, framework.name,
              framework.confidence, "logic coverage:", framework.application_logic)
        for evidence in framework.evidence_records:
            location = evidence.location
            print("Indicator:", evidence.indicator, location.container,
                  location.member, location.class_descriptor, location.sha256)
        for limitation in framework.limitations:
            print("Framework limitation:", limitation)

    print("Unmatched definitions:", result.coverage.unknown_classes_emitted,
          "of", result.coverage.unknown_classes_total,
          "truncated:", result.coverage.unknown_classes_truncated)
    print("Coverage:", result.coverage.to_dict())
    for artifact in result.analyzed_files:
        print("Artifact:", artifact.member, artifact.format, artifact.status)
    for error in result.errors:
        print("Analysis issue:", error.code, error.member, error.severity, error.message)
    # Errors or partial coverage should be retained even when useful matches exist.
    incomplete = bool(result.errors) or any(
        status == "partial" for status in (result.coverage.dex, result.coverage.elf)
    )
    return 2 if incomplete else 0


if __name__ == "__main__":
    raise SystemExit(scan(Path(sys.argv[1]), Path(sys.argv[2])))
```

The example's exit codes are its own application policy. Saving output can raise `OSError`, which the host should handle according to its storage policy. `inspect(input_path, options=IdentifyOptions())` returns the same `ScanResult` type, with empty components and database metadata; its unknown classes are all emitted parsed definitions.

## Subprocess alternative

Use an argument list, not a shell command assembled from untrusted paths:

```python
import json
import subprocess
import sys
from libidentifier import ScanResult

completed = subprocess.run(
    [sys.executable, "-m", "libidentifier.cli", "identify", "app.apk",
     "--profiles", "profiles.sqlite", "--format", "json"],
    capture_output=True, text=True, encoding="utf-8", check=False, timeout=180,
)
if completed.returncode not in (0, 4):
    raise RuntimeError(completed.stderr.strip())
result = ScanResult.from_dict(json.loads(completed.stdout))
# Exit 4 still has a scan result; inspect result.errors and coverage.
```

`subprocess.run(..., timeout=180)` kills and waits for the scan child on expiry and raises `subprocess.TimeoutExpired`; treat this as a failed scan, not an empty result. Retain the previous completed result separately, and do not read a timed-out output file as complete JSON. Scans do not launch analysis subprocesses. Process startup may itself delay timeout delivery.

CLI scan exit codes: `0` means no error-severity analysis issue (warnings may exist); `2` means fatal input error or argparse usage error; `3` means a database or other handled operational error; `4` means a returned result contains error-severity analysis issues. Fatal failures write diagnostics to stderr and no scan JSON. `--output scan-result.json` saves JSON instead of stdout. `--format table` preserves library rows and adds a framework section with confidence, locations and limitations; unknown versions are shown as `Unknown [reference candidates]`, never as installed versions. Table text is for humans and is not a machine contract.

## Public functions and options

These functions are exported from `libidentifier`:

```python
identify(path, *, profiles, options: IdentifyOptions | None = None) -> ScanResult
inspect(path, *, options: IdentifyOptions | None = None) -> ScanResult
build_profile(path, *, purl: str, database, d8=None, android_jar=None,
              reference_sha256: str | None = None) -> ProfileBuildResult
export_cyclonedx(result: ScanResult, path) -> None
```

`IdentifyOptions`, `ScanResult` and `ProfileBuildResult` are exported at the package root. Other result dataclasses are available in `libidentifier.models`; exceptions are in `libidentifier.errors`. Scan inputs support APK/ZIP, standalone DEX/ELF, and directories of APK/DEX/ELF files. Top-level JAR/AAR containers can be inspected for embedded DEX/ELF; JVM `.class` files are not scanned. Directory traversal ignores JAR/ZIP/AAR and unrecognized files, skips symlinks and files deeper than the configured depth, and enforces file/byte budgets. APK names are case-sensitive framework locations.

`ProfileBuildResult` has string fields `database`, `release_id`, `family_id`, `purl`, `version`, `source_format`, `source_sha256`, and integer fields `dex_shapes`, `elf_identities`; it provides `to_dict()`. It describes the trusted reference build, not a scan match.

`IdentifyOptions` is a frozen dataclass; pass keyword arguments and omit options you do not need. Current defaults:

| Fields | Defaults |
| --- | --- |
| `max_archive_members`, `max_directory_files` | 20000 each |
| `max_member_uncompressed_bytes` | 134217728 |
| `max_total_selected_uncompressed_bytes` | 536870912 |
| `max_compression_ratio`, `max_directory_depth` | 200, 8 |
| `max_emitted_unknown_classes`, `max_version_candidates` | `None` (all parsed unmatched classes), 12 |
| `max_scan_seconds` | 180; reserved, currently **not enforced** |
| `medium_min_discriminative_classes`, `medium_min_weighted_coverage` | 3, 0.75 |
| `medium_partial_min_exact_classes`, `medium_partial_min_weighted_coverage`, `medium_partial_min_unique_anchors` | 25, 0.65, 10 |
| `high_min_discriminative_classes`, `high_min_weighted_coverage`, `high_min_unique_anchors`, `high_min_runner_up_delta` | 5, 0.90, 2, 0.15 |
| `min_material_runner_overlap` | 0.25 |

Matching thresholds and scores are engine tuning inputs, not accuracy guarantees. Stage 3 must retain these argument names; new engines may deprecate tuning options without requiring consumers to change scan calls. Byte/member/depth limits must be positive integers; the emitted-unknown cap may be `None` (unlimited output), and either output cap may be zero. Invalid values raise `ValueError`. A host needing a hard time or memory limit should run the CLI in a managed worker process.

`max_scan_seconds` is retained only for call compatibility and is explicitly reported as unenforced in `coverage.limitations`. A Python thread timer cannot safely interrupt native LIEF calls; Unix signals would not provide the same behavior on Windows or worker threads. Embedding a process supervisor inside each API call would change process lifecycle and memory behavior. This release therefore keeps the in-process API and uses the portable subprocess timeout shown above for callers needing a deadline. Byte limits do not bound LIEF memory usage or ZIP central-directory allocation; enforce process memory limits externally when needed. Selected-byte limits are shared across child APKs in directory scans. Oversized standalone binaries are rejected; duplicate ZIP names are skipped to avoid ambiguous evidence, and corrupt members retain other readable results.

## ScanResult and JSON schema 1

Results are frozen dataclasses containing ordinary lists and dictionaries; do not mutate them if sharing between consumers. `to_dict()` returns a JSON-compatible dictionary; `to_json()` returns deterministic compact JSON with sorted keys and explicit `null` values; `write_json(path)` streams deterministic UTF-8 JSON plus a newline into an atomic replacement file, without a full dictionary or JSON-string copy. `to_json()` still needs memory for the returned string; use `write_json()` for large inventories. `ScanResult.from_dict(data)` reconstructs a supported result, ignores unknown additive fields at every model level, accepts legacy framework hints without new fields, and raises `ValueError` for unsupported schema versions. It is not a general validator for untrusted JSON: malformed required fields can raise `KeyError` or `TypeError`.

Every schema-1 result contains these fields:

| Field | Type and meaning |
| --- | --- |
| `schema_version` | integer, currently `1`; the public output format version |
| `tool_name`, `tool_version` | strings; tool identity and package version |
| `fingerprint_algorithm` | string; internal engine compatibility identifier, diagnostic only |
| `profile_database` | `ProfileDatabaseRecord`: nullable strings `id`, `version`, `sha256`, `generated_at`; integer `profile_count` |
| `input` | `InputRecord`: strings `path`, `format`, `sha256`; integer byte `size` |
| `analyzed_files` | list of `ArtifactRecord`: nullable `member`, `path`, `container`; strings `format`, `sha256`, `status` (`analyzed` or `failed`) |
| `components` | list of `ComponentMatch`, described below |
| `frameworks_detected` | list of `FrameworkHint`, described below |
| `class_ownership_hints` | list of `CodeOwnerHint`: strings `subject`, `origin`, `component_id`, `confidence`, `method`; current matcher emits `third_party` hints |
| `unknown_classes` | list of unmatched `CodeLocator` definitions; complete by default, optionally capped by `max_emitted_unknown_classes` |
| `coverage` | `CoverageRecord`, described below |
| `errors` | list of `AnalysisError`: strings `code`, `message`, `severity` (warning/error), nullable `member` |

`profile_database.version` is the **database schema version**, not a catalog release or package version. Its SHA-256 identifies the actual database snapshot; `generated_at` is a stored generation timestamp. No-database inspection uses null metadata and zero profiles. Directory input hashes combine relative paths and file hashes; they are not a file SHA-256 and are not guaranteed identical across operating systems.

### Identified library components

| ComponentMatch field | Type and meaning |
| --- | --- |
| `component_id`, `name` | strings; opaque match identity and display name |
| `ecosystem`, `purl` | nullable strings; PURL can be null when release identity is unknown |
| `version` | nullable string; null means no exact version established |
| `family_purl` | nullable string; versionless package identity from trusted references, including namespace; suitable for advisory discovery, not a version claim |
| `version_candidates` | list of strings; bounded reference releases with sufficient matching evidence, not an exhaustive list of possible installed versions |
| `version_candidates_total`, `version_candidates_truncated` | nullable integer and boolean; candidate count before capping and whether the emitted list was capped; null in legacy results |
| `identity_confidence` | string: `low`, `medium`, `high`; confidence in family identity |
| `version_confidence` | string: `unknown`, `medium`, `high`; current engine emits unknown or high |
| `identification_methods` | list of strings; diagnostic method identifiers may evolve |
| `score` | nullable number; matcher-specific score, not a probability |
| `score_details` | dictionary of engine-specific diagnostic values; keys may evolve |
| `matched_code` | list of `CodeLocator` evidence |
| `source_artifacts` | list of strings naming source members or paths |
| `limitations` | list of strings; human-readable qualifications |

Identity and version confidence are independent. Structural DEX evidence normally establishes a family, not a release: even one database candidate leaves `version=null`. The current engine can establish an exact version from a unique trusted reference input hash or exact ELF identity. A high identity confidence does not make version candidates verified versions. Reference releases sharing only weak incidental shapes are excluded from the candidate list. Candidate rankings and diagnostic scores are not exact-version evidence; unprofiled versions remain possible. Identical ELF bytes associated with multiple releases of one family retain the family match with unknown version; conflicting families remain unidentified. Component IDs are opaque and are not guaranteed to remain identical across engine or database upgrades. Do not derive a package/version from them or parse diagnostic score keys for business decisions. CycloneDX export includes only components with PURL, exact version, and high identity and version confidence; framework hints are not exported as versioned libraries.

### Framework presence

Legacy fields remain: `name: str`, `evidence: str` (summary), `member: str | None` (one representative location), `confidence: str`, `limitations: list[str]`. Additive fields are:

| FrameworkHint field | Meaning |
| --- | --- |
| `framework_id` | nullable stable string; new detections use the IDs below; old serialized hints may lack it |
| `evidence_records` | list of `FrameworkEvidence`: `indicator: str` and `location: CodeLocator`; all supporting observations |
| `application_logic` | `not_supported` or `dex_structure_only`; describes analysis scope, not active usage |

Supported IDs: `flutter`, `react_native`, `jetpack_compose`, `cordova`, `unity`, `dotnet_android` (Xamarin / .NET MAUI). Multiple frameworks can coexist. Directory scans may return separate hints for separate APKs; use container locations to distinguish them. Display names and prose summaries are not identifiers.

Exact runtime class **definitions**, parsed ELF runtime names/SONAMEs, select Flutter engine exports, recognizable asset/assembly layouts and Cordova bootstrap markers are indicators. Generic AndroidX/Kotlin classes, WebView references, Hermes alone, `libapp.so` alone, and standalone filenames do not establish presence. A single exact runtime class yields a low hint; two distinct exact runtime definitions or two evidence kinds yield medium; three evidence kinds, or multiple runtime definitions plus parsed native runtime evidence, yield high. Multiple ABI copies do not increase evidence diversity. These conservative heuristic labels are not calibrated probabilities. Assets and names can be imitated; detection does not prove active use or exact framework version. Runtime stripping, renaming or unfamiliar packaging can prevent detection.

Compose results describe DEX structural coverage only. Flutter Dart, React Native JS/Hermes, Cordova JS, Unity managed/IL2CPP, and .NET assemblies are not reverse engineered or inventoried. Android plugin DEX and native ELF files are still scanned normally for profile-backed libraries. Xamarin and MAUI share runtime indicators and are deliberately grouped rather than guessed apart.

### Locations, provenance and coverage

`CodeLocator` fields: `container: str`, `member: str | None`, `class_descriptor: str | None`, `method_descriptor: str | None`, `sha256: str | None`. Container/member identify the evidence file; descriptors name real defined classes where available. Standalone files have null members. APK locators retain exact ZIP member paths; directory APK locators point to the child APK container. `ArtifactRecord.container` makes native artifact locations equally precise; it defaults to null when reading older output. Use `(container, member, class_descriptor, sha256)` to distinguish occurrences, not a member filename alone. SHA-256 normally identifies the member bytes, not a single class. Method descriptors are optional and currently generally unused. A component's `source_artifacts` alone is a summary; persist locators and the whole scan result.

Profile builds store reference source hashes and provenance internally. Scan JSON exposes the database hash, component evidence and source artifact names, not the complete catalog provenance. Keep the catalog, trusted source artifacts and rebuild manifest alongside the distributed database for audit purposes.

`tool_version` identifies the installed package release. For an unreleased editable checkout, additionally record the source revision and local changes externally; multiple development checkouts can carry the same package version.

`CoverageRecord` contains strings `dex`, `elf`, `metadata` (absent/analyzed/partial), `javascript`, `hermes`, `dart_aot` (currently `not_supported`); dictionaries `analyzed_count` (dex, elf, classes, native_binaries) and `skipped_count` (size_limit, encrypted, unsupported, parse_error); and `limitations: list[str]`. Metadata is currently partial when framework indicators are present and absent otherwise; it does not represent complete AndroidManifest parsing. Counts describe parsing, not the percentage of all libraries identified. Skipped counts are diagnostic, not an exhaustive count of omissions. `unknown_classes_total` counts unmatched definitions before the output cap, `unknown_classes_emitted` counts returned locators, and `unknown_classes_truncated` states whether the output was capped. These fields are null when reading older results, meaning unavailable, not zero. Totals cover only successfully parsed definitions, not code in skipped payloads. `analyzed_count.classes` counts all parsed definitions. Unknown definitions are **not** classified as custom versus third-party code.

`coverage.library_identification` is `not_performed` for `inspect`, `no_profiles` for identification against a valid zero-profile database, and `limited` for identification against a nonempty database. The default `unknown` means unavailable in legacy results. No state claims exhaustive catalog coverage. A populated database can still lack nearly all libraries in an APK.

Successful parsing with zero components is valid and does not establish absence of libraries. A parse failure or skipped archive member can leave useful partial results; check both errors and coverage. Framework absence is inconclusive if relevant payloads were skipped or unsupported. Top-level symlinks and unknown formats are rejected; selected ZIP members are bounded and unsafe paths, encrypted entries or unsupported compression can be skipped. Native LIEF parsing does not sandbox hostile binaries.

## Software inventory and downstream SCA decisions

`ComponentMatch` is generic: it can represent a library, SDK, UI toolkit, framework runtime, language runtime or native component when references establish identity. Future AppCompat, Material, Firebase, Google Play Services, Kotlin or runtime profiles use the same model. Their mention here does not claim current catalog coverage. Direct and transitive dependencies are scanned equally when their code is embedded; LibIdentifier neither reads dependency declarations to invent findings nor reconstructs a dependency graph.

Keep these states distinct:

| State | Public evidence and consumer interpretation |
| --- | --- |
| Supported identity and exact version | Identity score meeting the configured threshold, non-null `version`, `version_confidence=high`, and consistent versioned `purl` support version-specific advisory correlation |
| Identified family, unknown version | Use `family_purl` and identity confidence for package-level advisory discovery; `version=null` remains unknown even with one candidate |
| Uncertain identity | Medium/low identity confidence needs consumer review; do not silently promote it to a confirmed dependency |
| Technology indicator | `frameworks_detected` describes runtime/UI technology presence; no dependency identity or framework version is inferred from it |
| Unidentified code | `unknown_classes` and unassigned analyzed ELF artifacts preserve evidence without asserting custom or third-party ownership |

The current matcher emits accepted medium/high component identities; weaker rejected matches remain unidentified rather than inventing low-confidence components. Future engines may use the existing low confidence value. A technology can have both a presence hint and a separately supported component match; these are different observations, not automatically two dependencies. The historical `frameworks_detected` field also accommodates UI or language technology indicators through additional IDs; consumers must not hard-code a closed list.

For unassigned native artifacts, compare each analyzed ELF's `(container, member, sha256)` with whole-file locators in component `matched_code`. Failed ELF artifacts are parsing failures, not successfully inventoried unknown code. For legacy artifacts without `container`, preserve the original result and use input context; do not invent exact nested locations. No JS/Dart/Hermes/IL2CPP/.NET code inventory is inferred from these counts.

Identification alone does not look up advisories. The optional `correlate()` API now supplies local package-level discovery and official OSV exact-version assessment, as described below; external applications need not parse OSV JSON or access either SQLite schema. A candidate reference version falling inside an affected range means only **potential applicability**, not that the installed library is affected. Do not replace a null version with a candidate, choose the highest score as the installed release, or infer an installed version from another library's upstream dependency declaration. Even a supported exact version needs the consumer's advisory matching and context checks; LibIdentifier can report an affected-version advisory match, but never asserts runtime reachability or exploitability. Persist the full scan, including input hash, tool version, database hash, confidence, limitations and exact code locators.

## CycloneDX export scope

```python
from libidentifier import export_cyclonedx, identify

result = identify("app.apk", profiles="profiles.sqlite")
result.write_json("inventory.json")
export_cyclonedx(result, "components.cdx.json")
```

The CycloneDX 1.5 export remains an identification-only filtered exact-version subset, not the complete inventory. Pass `result.identification` to `export_cyclonedx` for combined scans; the `sbom` CLI continues to consume identification JSON, not an assessment envelope. It includes only components with high identity and version confidence and a consistent versioned PURL. Unknown/ambiguous versions, uncertain identities, invalid/inconsistent PURLs and framework indicators are excluded. Version candidates are never promoted. A zero-component SBOM therefore does not mean zero dependencies or zero vulnerabilities.

The export declares `compositions.aggregate=incomplete` and includes `libidentifier:*` metadata properties for scope, excluded component IDs/reasons, input, profile database, fingerprint algorithm, scan schema, coverage and errors. Exported components retain their scan `component_id` as `bom-ref` and exact locators in the `libidentifier:matched_code` property (JSON encoded as a string). These properties use CycloneDX's standard property mechanism; the full `inventory.json` remains authoritative, including unknown-version components and framework observations. Physical copies of the same exact ELF match share one component with multiple evidence locations, avoiding duplicate BOM references. No dependency graph or direct/transitive relationships are fabricated.

## Complete identification output

`IdentifyOptions(max_emitted_unknown_classes=None)` is the default for `identify()`, `inspect()` and `scan()`. Every parsed unmatched definition is returned. A cap is an output policy only: it does not change extraction, fingerprints, matches, or original unmatched totals. Use e.g. `IdentifyOptions(max_emitted_unknown_classes=1000)` or CLI `--max-unknown-classes 1000` when deliberately requesting a bounded view. A zero cap omits locators but preserves totals and a truncation flag. Existing JSON remains readable.

Complete output is not complete dependency knowledge. Skipped members, unsupported payloads and signature coverage still limit analysis. Version-candidate output retains its separate default cap of 12 and its existing total/truncation fields. Input/resource bounds remain enforced as before, and the in-process LIEF timeout remains unenforced. Streaming removes extra serialization copies, not parser allocations or the in-memory result itself.

## Optional offline advisory assessment

Identification works without OSV installed. The assessment adapter accepts **official OSV-Scanner v2.7.0** native Windows/Linux release assets only, verifying their SHA-256 and runtime version before execution. Download the matching architecture from [the official release](https://github.com/google/osv-scanner/releases/tag/v2.7.0), check the published checksum, and install it as `osv-scanner.exe` or `osv-scanner` (on Linux, grant execute permission). The assessment CLI searches PATH first, then the working directory; `--osv-scanner <path>` overrides discovery. The first discovered executable must pass approval checks; an unapproved executable is rejected without running it. LibIdentifier never downloads, installs or upgrades executables. No additional Python dependency or Docker is required.

Current advisory coverage is **Maven only**, matching the Android reference catalog. Generic ELF identities and other ecosystems are explicitly unassessed. Additional ecosystem support must be qualified rather than inferred from a filename, display name or framework indicator.

Renaming downloaded assets is optional: discovery also accepts `osv-scanner_windows_amd64.exe` / `osv-scanner_windows_arm64.exe` on Windows and `osv-scanner_linux_amd64` / `osv-scanner_linux_arm64` on Linux. Within each search directory the conventional names take precedence, followed by the native architecture release name, then the other supported architecture name. Execution still requires a compatible approved binary. Darwin assets are unsupported; `osv-scanner_SHA256SUMS` is a checksum manifest, never an executable. Missing-scanner warnings include [the release download page](https://github.com/google/osv-scanner/releases); install the qualified v2.7.0 release.

Provision the published Maven advisory archive with an explicit network-enabled maintenance command:

```sh
libidentifier vulnerabilities update --database advisory-db --ecosystem Maven
libidentifier vulnerabilities validate --database advisory-db
```

For an air-gapped installation, transfer the published `https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip` and import it locally:

```sh
libidentifier vulnerabilities provision --database advisory-db --ecosystem Maven --archive Maven-all.zip --fetched-at 2026-10-14T12:00:00Z
```

Supply the actual retrieval timestamp, not the time an old archive was copied. Without `--fetched-at`, local import uses the source file modification time. This is provenance supplied by the operator, not proof that the upstream feed is current. Fresh downloads record the actual retrieval time. The default maximum snapshot age is 30 days; stale snapshots are blocked, with their age retained. `--max-database-age-days` or the corresponding API option changes that explicit policy.

Updates download only the fixed published ecosystem archive URL, enforce archive/record size bounds, build a package-discovery index, validate contents and hashes, and atomically publish `CURRENT.json` referring to an immutable generation. Failed downloads, invalid archives and failed publication preserve the preceding usable generation. Old generations are retained for rollback and active readers; no automatic cleanup or refresh of existing snapshots occurs. `provision` and `validate` are offline. Neither requires OSV installed. Consumers should use these functions/commands rather than manipulating snapshot files or database tables.

The Python `identify`, `inspect`, `scan` and `correlate` APIs never download. Their explicit maintenance function `update_advisory_database` is the advisory network operation. Assessment-enabled CLI commands can call it during setup, before offline assessment, if the selected database directory is absent. Use `--offline` to prohibit this setup download. Existing `profiles fetch/rebuild` maintenance behavior remains independent.

CLI database selection is `--osv-db <directory>`, otherwise an existing `./advisory-db`, otherwise the persistent user cache: `%LOCALAPPDATA%/LibIdentifier/advisory-db` on Windows (falling back to `~/AppData/Local`), or `$XDG_CACHE_HOME/libidentifier/advisory-db` on Linux (falling back to `~/.cache`). A missing directory, including an explicit override, is automatically provisioned from the fixed official Maven archive URL unless `--offline` is set. No package names, versions, APK contents or inventories are transmitted. Scanner approval happens before any download. Existing directories, including empty, stale or corrupt databases, are never silently overwritten or refreshed; use `vulnerabilities update --database <selected-directory>` explicitly. Interrupted provisioning retains any previous usable generation. A failed first download may leave an empty directory requiring that explicit update.

## Assessment Python API

```python
from libidentifier import (
    identify, scan, correlate, VulnerabilityOptions,
    AssessmentResult, VulnerabilityReport,
)

inventory = identify("app.apk", profiles="profiles.sqlite")
inventory.write_json("inventory.json")

options = VulnerabilityOptions(
    scanner="C:/tools/osv-scanner.exe",  # Linux: /opt/tools/osv-scanner
    database="advisory-db",
    timeout_seconds=60,
    max_database_age_days=30,
    discover_unknown_versions=True,
    max_potential_advisories_per_component=100,
    min_identity_score=0.75,
)

# Reassess a cached inventory without parsing the APK again.
report = correlate(inventory, options=options)
report.write_json("advisories.json")

# Or perform both stages in one call.
result = scan("app.apk", profiles="profiles.sqlite", vulnerabilities=options)
result.write_json("assessment.json")

for component in report.components:
    print(component.component_id, component.status, component.evaluated_version,
          component.reason, component.advisories_truncated)
for finding in report.findings:
    print(finding.component_id, finding.advisory_id, finding.applicability,
          finding.match_basis, finding.evaluated_version, finding.related_advisory_ids)
for issue in report.errors:
    print(issue.code, issue.message)
```

Public signatures:

```python
correlate(result: ScanResult, *, options: VulnerabilityOptions) -> VulnerabilityReport
scan(path, *, profiles, options: IdentifyOptions | None = None,
     vulnerabilities: VulnerabilityOptions | None = None) -> AssessmentResult
provision_advisory_database(database, *, archives, fetched_at=None, sources=None)
update_advisory_database(database, *, ecosystems=("Maven",), timeout_seconds=60)
validate_advisory_database(database, *, max_age_days=30)
```

The maintenance functions return `AdvisoryDatabaseRecord`; `archives` maps the supported ecosystem to a local ZIP path. They raise `AdvisoryError` (from `libidentifier.errors`, a `LibIdentifierError` subclass) for handled snapshot/update failures; filesystem errors can also occur when creating the target directory. `correlate()` returns structured assessment failures instead of manufacturing empty success. Identification failures in `scan()` retain the existing `InputError`/`ProfileError` behavior. Invalid Python option values remain programmer errors.

`VulnerabilityOptions` also has `max_output_bytes=67108864`, bounding combined OSV stdout/stderr. Timeout and database-age options must be finite and positive; potential-advisory caps may be zero. Package-only discovery is enabled by default and bounded to 100 source records per component. Use `discover_unknown_versions=False` (`--no-potential`) to disable it. Zero discovery output still reports the original record count and truncation. Candidate reference versions are never queried as installed versions.

Advisory attribution uses `min_identity_score=0.75` by default (inclusive, on the 0–1 score, not a percentage). Configure it with the API option or `--min-identity-score 0.85`; values must be finite and between 0 and 1. The full stored score is compared, while tables round scores to two decimals. Missing/invalid scores are unassessed. The categorical `identity_confidence` remains independent and is retained in findings; a medium-confidence match scoring 0.837 qualifies. This is an attribution policy, not a calibrated probability or an exact-version signal. Successful reports record the chosen threshold in `limitations`. Exact-version assessment still requires high version confidence and a consistent versioned PURL. SBOM's existing high-identity/high-version filter is unchanged.

## Assessment CLI

```sh
libidentifier identify app.apk --profiles profiles.sqlite --vulnerabilities --format table
libidentifier identify app.apk --profiles profiles.sqlite --vulnerabilities --offline --output assessment.json
libidentifier scan app.apk --profiles profiles.sqlite --vulnerabilities --osv-scanner /opt/tools/osv-scanner --osv-db advisory-db --format json --output assessment.json
libidentifier correlate inventory.json --osv-scanner /opt/tools/osv-scanner --osv-db advisory-db --format table
libidentifier scan app.apk --profiles profiles.sqlite --format table
```

Substitute a Windows executable path as needed. Plain `identify` retains its identification-only `ScanResult` JSON. `identify --vulnerabilities` returns the existing `AssessmentResult` envelope, just like `scan --vulnerabilities`. The last command performs identification and returns an assessment envelope with vulnerability status `not_requested`; it needs no OSV dependencies. `correlate` always requests assessment. All three assessment-enabled commands support discovery, optional `--osv-db`, and `--offline`; OSV itself always uses full offline mode regardless of this flag. Other assessment flags: `--osv-timeout`, `--max-database-age-days`, `--no-potential`, `--max-potential`. `identify` and `scan` additionally accept `--max-unknown-classes`. Tables show candidate versions in the library section and attributed advisory IDs/aliases below each component, distinguishing confirmed version matches from potential advisories. Tables remain summaries, not full code inventories.

Assessment CLI exit codes describe operational success, not a vulnerability policy: `0` means a usable result was returned (affected/potential/unassessed components may exist), `2` is an identification/usage error, `3` is a blocked/failed assessment or maintenance error, and `4` is an error-bearing partial assessment or identification result. Missing scanners gracefully return 0 when identification succeeded, with a short stderr warning, report `status=blocked`, error `code=scanner_missing` and component `status=not_assessed`, `reason=scanner_missing`. An empty findings array in that report does not mean zero vulnerabilities. Other preparation failures retain the inventory and structured errors (for example `database_provision_failed`) and return 3. A policy-limited `partial` report without operational errors returns 0; consumers must inspect status and coverage. Findings do not change the exit code automatically. JSON results are retained for blocked/failed/partial assessment stages when identification succeeded. Standalone correlation preserves original identification coverage and issues as well. Maintenance fatal errors write stderr. OSV's raw exit codes are normalized internally.

## Assessment result schema 1

`--format table` prints an input title and aligned `LIBRARIES` columns for library, categorical identity with numeric score, version/reference candidates, and (when requested) advisory summary. A `VULNERABILITIES` section appears only for requested assessment (`--vulnerabilities`, or the assessment-only `correlate` command). It distinguishes `CONFIRMED` exact-version matches, `POTENTIAL` package advisories, unassessed components and scanner failures. Plain `identify`, `inspect` and `scan` without the flag have no vulnerability section. Narrow terminals use stacked fields; longer cells and evidence wrap by display width. Output is plain text, with ANSI/control escapes stripped from data, so it also works when redirected.

Affected-version text comes only from OSV records for the attributed package. Simple single-boundary ranges preserve inclusive `introduced`/`last_affected` and exclusive `fixed` endpoints. Separate ranges remain joined with OR. Complex event timelines or `limit` boundaries are shown as OSV events without sorting or comparing Maven version strings; qualifiers remain intact. Short explicit version lists are shown literally, while longer lists show their exact count and refer to full JSON. Unsupported/missing ranges never cause an invented range; partial summaries explicitly refer to additional JSON ranges. No `Affected:` label appears if usable version data is unavailable. These summaries describe advisory scope, not applicability to an unknown installed version. Version evaluation remains OSV-Scanner's responsibility. See the [OSV event semantics](https://ossf.github.io/osv-schema/#affectedrangesevents-fields).

Vulnerability models live separately in `libidentifier.vulnerabilities.models`; `AssessmentResult`, `VulnerabilityReport` and `VulnerabilityOptions` are exported at the package root. The assessment schemas are independent of identification schema 1, fingerprint algorithms and both database formats. `to_dict`, `to_json`, streaming `write_json` and tolerant `from_dict` are provided. Unsupported schema/result kinds raise `ValueError`; unknown additive fields are ignored, including in nested records. No consumer parses OSV JSON.

| Model | Fields and semantics |
| --- | --- |
| `AssessmentResult` | `schema_version=1`, `result_kind="assessment"`, `identification: ScanResult`, `vulnerabilities: VulnerabilityReport` |
| `VulnerabilityReport` | `schema_version=1`, `result_kind="vulnerability_report"`, `status`, original `input`, `tool_version`, `profile_database`, `scanner`, `database`, `components`, `findings`, `advisories`, `errors`, `limitations`, original `identification_coverage` and `identification_errors` |
| `ScannerRecord` | `path`, `version`, executable `sha256`; nullable report field when verification fails |
| `AdvisoryDatabaseRecord` | `schema_version`, `generation`, `fetched_at`, `age_days`, `ecosystems`, `hashes`, `sources`; nullable when unavailable; retained for stale snapshots |
| `ComponentAssessment` | `component_id`, `family_purl`, `status`, `reason`, nullable `evaluated_version`, independent `identity_confidence`/`version_confidence`, exact `evidence: list[CodeLocator]`, canonical `advisory_ids`, `advisories_total`, `advisories_truncated` |
| `AdvisoryFinding` | `component_id`, canonical `advisory_id`, `related_advisory_ids`, `applicability`, `match_basis`, nullable `evaluated_version`, independent confidences, `reachability="not_analyzed"` |
| `AdvisoryRecord` | OSV `id`, `aliases`, `summary`, `severity`, `affected`, `references`, nullable `modified`/`withdrawn`, full source `raw` record |

Report statuses: `not_requested`, `not_applicable` (no identified components to assess), `blocked` (preflight dependency/database unavailable), `failed`, `partial` (unassessed components, capped discovery, original incomplete identification or operational errors), and `complete` (all requested component assessments completed). Complete can contain potential findings whose version applicability remains unknown. It never means exhaustive software inventory or proven safety.

Component statuses:

- `affected`: identity score met the configured threshold and a high-confidence exact version was passed to official OSV; it matched an advisory for that reliable version. `match_basis=exact_version`, `applicability=affected`.
- `potential`: package identity meets the configured score threshold and has active advisory records in the local index, but its installed version is not reliable. `match_basis=package_identity`, `applicability=potential`, `evaluated_version=null`.
- `not_affected`: OSV evaluated the reliable version against a fresh, validated supported ecosystem snapshot and returned no matches. This means not affected by the evaluated advisories, not universally free of vulnerabilities.
- `not_assessed`: identity score below threshold/unavailable, unsupported/missing package coordinate, unavailable data, unknown version with discovery disabled/no package records, or scanner failure. Its reason explains the limitation.

Source advisory records are deduplicated by OSV ID. Alias-connected records share one canonical finding per component and basis, while retaining all original IDs/records and severity provenance. Discovery totals count source records before capping/alias grouping, not distinct CVEs. Withdrawn advisories are excluded from active discovery/matches. Advisory severity is not identification confidence. A match never proves vulnerable code is present on a reachable execution path or exploitable; consuming applications retain exposure/triage policy.

## Offline execution boundary

The qualified adapter uses only generated dependency coordinates, never APK/DEX/ELF files, with a private temporary directory and empty explicit OSV config. It invokes the approved binary with `shell=False`, `--offline`, `--no-resolve`, disabled Go/Rust call analysis, and no download flag. It sets the snapshot cache directory explicitly to the verified v2.7.0 `osv-scalibr` layout. Returned package coordinates must exactly equal the generated inventory; malformed/contradictory outputs and non-result exit codes fail assessment. No untrusted scanner configuration or arbitrary extra command arguments are accepted.

The subprocess is killed and reaped on timeout or excessive output. Source parsing still runs in-process under the existing identification contract; `timeout_seconds` limits OSV invocations, not LIEF or total scan wall time. Successful updates are the only advisory network path in Python. Full offline flags and a pinned verified executable enforce the approved tool's offline behavior; a Python wrapper is not an OS network sandbox. For an independently enforced no-egress boundary, run the worker under outbound-denying host policy (e.g. Linux network isolation or Windows outbound firewall policy). The library does not silently modify host firewall settings. Immutable snapshots/executables must not be modified concurrently by another process or administrator.

## Errors and compatibility policy

Fatal unreadable/missing/unsupported top-level inputs raise `InputError`. Missing, invalid or incompatible reference databases raise `ProfileError`, including underlying SQLite opening/query failures. Both inherit `LibIdentifierError`. A fatal exception means no `ScanResult`; there is no silent fallback to an empty database. Selected ZIP-member read failures and DEX/ELF parser failures are captured as `AnalysisError` entries with member locations and error severity, and a `ScanResult` is still returned. Exact diagnostic messages and new error-code strings are not stable enums; handle unknown codes and preserve their text. Profile provisioning can raise `ProfileBuildError`, catalog/operational errors or `OSError`; that maintenance workflow is separate from scanning. Invalid argument types are programmer errors, not guaranteed scan exceptions.

The supported compatibility boundary is:

- Retain the new `scan`/`correlate` signatures and the meanings of assessment statuses, confidence, applicability and provenance across Stage 3. OSV adapters and snapshot migrations remain internal; unsupported versions fail clearly instead of silently changing findings.
- Retain `identify(path, *, profiles, options=None)` and `inspect(path, *, options=None)`, return `ScanResult`, and preserve existing option argument names. Preserve the exported profile/SBOM function signatures above.
- Preserve schema-1 core field names, types, null semantics, locator meaning, confidence meaning and fatal-versus-partial error behavior. Existing result-model positional fields retain their order; additions have defaults. New optional `family_purl`, candidate-count, artifact-container and coverage fields also deserialize safely from older results. Prefer named access over positional construction for result models.
- Add optional fields, framework IDs, evidence methods or diagnostic keys without changing `schema_version`; consumers must ignore unfamiliar fields and tolerate unfamiliar diagnostic strings. Keep unknown versions null and candidates explicitly uncertain. Built-in deserialization ignores additive fields.
- Breaking output changes require a new public schema version and an explicit migration policy; `from_dict()` currently supports only schema 1 and rejects others. Do not silently reinterpret schema 1. Package upgrades must advertise any public breaking change; pin a reviewed package release until its upgrade is validated. This is a project contract enforced by tests, not an unlimited guarantee for arbitrary future major releases.
- Fingerprint algorithms and SQLite schema versions are **internal**, versioned separately from JSON. Consumers never query database tables or compute fingerprints to integrate. LibIdentifier validates database schema, algorithm metadata and release algorithms and rejects incompatibility with a clear `ProfileError`. An engine upgrade may require rebuilding/reprovisioning references, but must not require rewriting scan-result handling.
- Detection outcomes, numeric scores, ordering across releases, candidate sets, matched evidence volume, internal database IDs and component IDs can change as the engine improves. Persist tool/database provenance; do not assert identical findings across engine versions.

Upgrade from a reviewed new checkout with `python -m pip install --upgrade .`, validate or rebuild a new database with that version, run representative integration scans, then deploy the package and compatible database together. Retain the previous pair for rollback. The catalog is updated only through reviewed, pinned entries followed by explicit fetch/rebuild. Stage 3 must preserve the scan API and schema semantics even if an old fingerprint database must be replaced.

Automated tests protect public signatures, result fields, null versions, additive/legacy deserialization, incompatible schemas/databases, fatal and partial errors, deterministic serialization, and Python/JSON/table consistency. The original design's proposed thresholds and contamination-prone old DEX algorithm were superseded by actual class-definition filtering, evidence-backed descriptor matching and conservative version handling; consumers must not depend on those earlier internals.
