# LibIdentifier — Technical Implementation Specification

**Status:** implementation-ready v1 design  
**Target:** independent Python package and command-line application for identifying compiled Android/Java and native components  
**Supported host OS:** Windows and Linux  
**Primary consumer:** Moraine (imports `libidentifier`; never the reverse)  
**Runtime network access:** none  
**Initial scope:** APK/DEX/ELF analysis, offline fingerprint matching, local profile construction from DEX/JAR/AAR/SO references, JSON inventory, CycloneDX export  
**Out of scope:** JS/minified JS/Hermes/Dart package identification; general reverse engineering; arbitrary Java data-flow analysis; CVE/advisory matching inside the package.

## 1. Non-negotiable decisions

1. **The package identifies components; it does not decide whether an application is vulnerable.** It returns observed code and component identities with evidence, version ambiguity, and coverage. Moraine turns results into EV/OBS/FC/AP records and runs OSV-Scanner separately.
2. **Python API first, CLI on the same API.** The distribution is installed with pip and imported as `libidentifier`. It has an `libidentifier` console script. Never shell out to its own CLI from its Python API.
3. **Core dependency: LIEF.** Use standard-library `zipfile`, `hashlib`, `json`, `sqlite3`, `pathlib`, `tempfile`, `argparse`, and `dataclasses`. Do not import Androguard or LibScout. D8 and Java are optional **profile-build** prerequisites for JAR/AAR, not scan dependencies.
4. **Scanning is fully offline.** No HTTP requests, Maven resolution, OSV API calls, subprocess execution of submitted binaries, automatic downloads, or remote updates.
5. **Compiled code only in v1.** Recognize informative Flutter/React Native artifacts if encountered; do not parse Dart AOT, JS, Hermes or web assets for package identities. Coverage must reflect this.
6. **A DEX is a container, not a library.** One DEX may contain app and third-party classes; one logical library may span multiple DEX files. An ELF may contain embedded static code. Do not force one component per file.
7. **Unknown is an acceptable and expected output.** Neither unknown code nor a familiar package prefix establishes app ownership, library identity or version.
8. **Identity and version confidence are independent.** Structural similarity can support a component family but seldom proves an exact version. No arbitrary guessed versions.
9. **Fingerprints are generated from pinned, trusted reference artifacts.** Maintain versioned local profiles with traceable provenance. The matcher is generic, not one handwritten detector per library.
10. **Keep the code modular but small.** No plugin framework, database server, web UI, parallel task engine or external service. Standard-library SQLite is sufficient for a queryable local profile database.

## 2. What must work in v1

**Identification inputs:** `.apk`, `.dex`, `.so` / ELF, and directories containing these. File magic determines format; extensions are hints. Nested ZIPs are not recursively searched by default. Support multidex and multiple native ABIs.

**Reference-profile inputs:** prebuilt DEX or ELF; JAR or AAR via an explicitly configured local Android D8 executable. AAR `classes.jar` is primary; embedded extra JARs must not silently be treated as the same library.

**Outputs:** deterministic, schema-versioned JSON with input/container file hashes, matched component families, version candidates, matched class/ELF locators, confidence, methods of identification, unknown classes, coverage, errors, and the fingerprint database identity. Optionally emit CycloneDX 1.5 with **only** eligible, well-identified versions.

**Standalone interfaces:** Python `identify()`, `build_profile()`, `export_cyclonedx()` and CLI `identify`, `inspect`, `profiles build`, `profiles validate` and `sbom`.

**Acceptance:** known library identification from a reference APK; multiple libraries sharing one DEX; unknown controls; at least two release versions with correct version-ambiguity behavior; ELF; APK with multiple DEX and native ABI binaries; all core scans operate without Java, Android SDK or internet.

## 3. Repository tree

```text
libidentifier/
├── pyproject.toml
├── README.md
├── LICENSE
├── THIRD_PARTY_NOTICES.md
├── CHANGELOG.md
├── .gitignore
├── docs/
│   ├── architecture.md
│   ├── formats.md
│   ├── fingerprints.md
│   ├── profile-database.md
│   ├── limitations.md
│   └── integration-moraine.md
├── src/libidentifier/
│   ├── __init__.py              # public exports only
│   ├── api.py                   # identify(), inspect(), build_profile(), export_cyclonedx()
│   ├── cli.py                   # argparse commands; exit codes, stdout/stderr
│   ├── models.py                # dataclasses/enums/serialization
│   ├── errors.py                # structured error taxonomy
│   ├── config.py                # explicit limits and options
│   ├── detect.py                # format detection using magic + context
│   ├── archive.py               # bounded ZIP traversal, member hashes and safe extraction
│   ├── inventory.py             # multi-file aggregation and output construction
│   ├── matcher.py               # generic candidate retrieval and scoring
│   ├── sbom.py                  # CycloneDX 1.5 serialization
│   ├── extractors/
│   │   ├── __init__.py
│   │   ├── dex.py               # LIEF DEX → normalized ClassFeature
│   │   ├── elf.py               # LIEF ELF → normalized ElfFeature
│   │   └── metadata.py          # package metadata and trusted identity hints
│   ├── fingerprint/
│   │   ├── __init__.py
│   │   ├── dex_v1.py            # name-independent class-shape fingerprint v1
│   │   └── elf_v1.py            # binary identity features v1
│   └── profiles/
│       ├── __init__.py
│       ├── schema.py            # SQLite DDL + version checks
│       ├── store.py             # read-only matching index, transactional import
│       └── builder.py           # reference artifacts, D8 conversion, profile generation
├── catalog/
│   └── references.example.json  # metadata examples, no third-party binaries
├── tests/
│   ├── conftest.py
│   ├── test_api.py
│   ├── test_cli.py
│   ├── test_archive_security.py
│   ├── test_dex_features.py
│   ├── test_elf_features.py
│   ├── test_fingerprint_stability.py
│   ├── test_profile_builder.py
│   ├── test_matcher.py
│   ├── test_multidex.py
│   ├── test_versions.py
│   ├── test_sbom.py
│   ├── test_offline.py
│   └── fixtures/              # small synthetic / legally distributable fixtures
└── .github/workflows/
    └── tests.yml              # Windows/Linux, pinned Python/LIEF
```

Do **not** ship scraped JARs/AARs/SOs in the Python wheel. The profile database is a separate release artifact. Ship a tiny test/demo database only if reference-feature redistribution is cleared.

## 4. Packaging and runtime

- Python: support 3.11–3.13 initially, as long as the selected LIEF release publishes compatible wheels for each OS/Python combination. Lock a verified LIEF version in CI and Moraine's runtime; do not guess a broad compatibility range.
- `pyproject.toml`: standard setuptools or hatchling build; `libidentifier = "libidentifier.cli:main"` console entry point. **Runtime dependencies: LIEF only.** `pytest`/formatters belong in dev extras.
- Distribution metadata: Apache-2.0 proposed for original project code, subject to author approval. Keep upstream project citations and third-party notices.
- Install locally: `pip install -e .` or build a wheel; Moraine pins a packaged release. Runtime does not need Git, Go, Android SDK, D8 or OSV-Scanner.
- All archive members are treated as untrusted data; never load Java class code, ELF code, JS or native library code.

## 5. Public Python API

```python
from pathlib import Path
from libidentifier import identify, inspect, build_profile, export_cyclonedx
from libidentifier import IdentifyOptions, ScanResult

result: ScanResult = identify(
    Path("app.apk"),
    profiles=Path("/local/profiles.sqlite"),
    options=IdentifyOptions(),
)
result.write_json(Path("libraries.json"))

summary = inspect(Path("app.apk"))  # parse/type/coverage only; no matching

# Build-time only; caller explicitly supplies trusted reference and tools:
profile = build_profile(
    Path("okhttp-4.12.0.jar"),
    purl="pkg:maven/com.squareup.okhttp3/okhttp@4.12.0",
    database=Path("profiles.sqlite"),
    d8=Path("/path/to/d8"),
    android_jar=Path("/path/to/android.jar"),
)

export_cyclonedx(result, Path("components.cdx.json"))
```

Contract:

```python
identify(path: PathLike, *, profiles: PathLike, options: IdentifyOptions | None = None) -> ScanResult
inspect(path: PathLike, *, options: IdentifyOptions | None = None) -> ScanResult
build_profile(path: PathLike, *, purl: str, database: PathLike,
              d8: PathLike | None = None, android_jar: PathLike | None = None,
              reference_sha256: str | None = None) -> ProfileBuildResult
export_cyclonedx(result: ScanResult, path: PathLike) -> None
```

- API does not create workspace directories or write outputs except explicit `write_json`, `export_cyclonedx` and `build_profile` calls.
- `identify` raises `InputError` for invalid top-level input; malformed members should produce member-level errors and allow partial inventory when safe.
- `ScanResult` is an immutable or read-only final record; returned component arrays are ordered deterministically.
- No Moraine imports, IDs, data models, paths or configuration in LibIdentifier.

## 6. CLI contract

```text
libidentifier --version
libidentifier inspect app.apk --format json --output inspect.json
libidentifier identify app.apk --profiles profiles.sqlite --format json --output components.json
libidentifier identify app.apk --profiles profiles.sqlite --format table
libidentifier identify ./samples/ --profiles profiles.sqlite --format json --output directory-results.json
libidentifier profiles build okhttp.jar --purl pkg:maven/com.squareup.okhttp3/okhttp@4.12.0 \
    --database profiles.sqlite --d8 /path/to/d8 --android-jar /path/to/android.jar
libidentifier profiles build libfoo.so --purl pkg:generic/foo@1.2.3 --database profiles.sqlite
libidentifier profiles validate profiles.sqlite
libidentifier sbom components.json --output components.cdx.json
```

CLI rules:
- `--format table` default to stdout; `--format json` writes JSON to stdout unless `--output` is given. Progress/errors go to stderr.
- No network flags in v1; no `update` or automatic downloads during identification.
- Exit codes: `0` completed (including unknown components); `2` usage or invalid input; `3` fatal parser/profile failure; `4` partial results with significant coverage loss. The JSON records per-member failures regardless of exit code.
- `profiles build` is an explicit trusted **development** operation; D8 may be used there. Library scanning never invokes D8.
- Windows: commands are arguments passed to `subprocess.run`, never `shell=True`; D8 may be a `.bat` wrapper, which requires carefully constructed `subprocess` execution on Windows (or invoke D8's JAR directly via Java). Test this explicitly.

## 7. Data model and JSON schema

Use Python `@dataclass` models with explicit `to_dict()` / `from_dict()` and a versioned JSON schema. Keep string enums, not a separate Python class per library type.

### 7.1 ScanResult

```text
ScanResult
- schema_version: int = 1
- tool_name: str = "libidentifier"
- tool_version: str
- fingerprint_algorithm: str = "dex-shape-v1+elf-identity-v1"
- profile_database: {id, version, sha256, generated_at, profile_count}
- input: InputRecord {path, format, sha256, size}
- analyzed_files: list[ArtifactRecord]
- frameworks_detected: list[FrameworkHint]
- components: list[ComponentMatch]
- class_ownership_hints: list[CodeOwnerHint]
- unknown_classes: list[CodeLocator]
- coverage: CoverageRecord
- errors: list[AnalysisError]
```

### 7.2 ComponentMatch

```text
ComponentMatch
- component_id: deterministic scan-local string
- name: str                       # identified family, never manufactured
- ecosystem: str | null           # e.g., Maven, generic
- purl: str | null                 # versioned only when version is defensible
- version: str | null
- version_candidates: list[str]   # bounded list; total count also reported
- identity_confidence: "high" | "medium" | "low"
- version_confidence: "high" | "medium" | "unknown"
- identification_methods: list[str]
- score: float | null
- score_details: {matched_classes, profile_classes, weighted_coverage,
                  unique_anchors, runner_up_delta}
- matched_code: list[CodeLocator]
- source_artifacts: list[str]
- limitations: list[str]
```

No `ComponentMatch` for mere unsupported/unmatched code: track it under `unknown_classes`. File-name-only indicators may be emitted as `FrameworkHint` or low-confidence hints, **not** proven library identities.

### 7.3 CodeLocator and CodeOwnerHint

```text
CodeLocator: { container: "app.apk", member: "classes2.dex",
               class_descriptor: "Lokhttp3/OkHttpClient;",
               method_descriptor: null, sha256: "..." }
CodeOwnerHint: { subject: "Lokhttp3/OkHttpClient;", origin: "third_party",
                 component_id: "...", confidence: "high",
                 method: "structural_fingerprint" }
```

- Valid `origin`: `third_party`, `unknown` in the standalone tool by default. Optional strong framework hints can be emitted from known platform metadata; the **app** ownership decision belongs to Moraine because it knows the APK Manifest and project context. Do not label unmatched code `app`.
- The user-facing app/third-party/framework/unknown classification is computed by Moraine using LibIdentifier hints plus its own manifest/framework context.
- Keep class descriptors for cross-tool correlation. Preserve member names and hashes to locate complete original files.

### 7.4 Coverage and errors

```text
CoverageRecord:
  dex: analyzed | partial | absent | unsupported | failed
  elf: analyzed | partial | absent | unsupported | failed
  javascript: not_supported
  hermes: not_supported
  dart_aot: not_supported
  metadata: analyzed | partial | absent
  analyzed_count: {dex, elf, classes, native_binaries}
  skipped_count: {size_limit, encrypted, unsupported, parse_error}
  limitations: list[str]

AnalysisError:
  code: str
  member: str | null
  message: str
  severity: warning | error
```

### 7.5 Serialized illustrative result

```json
{
  "schema_version": 1,
  "tool_name": "libidentifier",
  "tool_version": "0.1.0",
  "fingerprint_algorithm": "dex-shape-v1+elf-identity-v1",
  "profile_database": {"id": "demo", "version": "1", "sha256": "<dbhash>", "generated_at": "<UTC>", "profile_count": 12},
  "input": {"path": "app.apk", "format": "apk", "sha256": "<hash>", "size": 100000},
  "analyzed_files": [{"member": "classes.dex", "format": "dex", "sha256": "<hash>", "status": "analyzed"}],
  "frameworks_detected": [],
  "components": [{
    "component_id": "cmp-<stable-hash>",
    "name": "okhttp", "ecosystem": "Maven",
    "purl": null, "version": null, "version_candidates": ["4.11.0", "4.12.0"],
    "identity_confidence": "high", "version_confidence": "unknown",
    "identification_methods": ["dex_shape_v1"], "score": 0.94,
    "score_details": {"matched_classes": 12, "profile_classes": 13,
                      "weighted_coverage": 0.94, "unique_anchors": 4,
                      "runner_up_delta": 0.24},
    "matched_code": [{"container": "app.apk", "member": "classes.dex", "class_descriptor": "Lokhttp3/OkHttpClient;", "method_descriptor": null, "sha256": "<dexhash>"}],
    "source_artifacts": ["classes.dex"], "limitations": ["release version cannot be distinguished"]
  }],
  "class_ownership_hints": [], "unknown_classes": [],
  "coverage": {"dex": "analyzed", "elf": "absent", "javascript": "not_supported",
               "hermes": "not_supported", "dart_aot": "not_supported",
               "metadata": "partial", "analyzed_count": {"dex": 1, "elf": 0, "classes": 100, "native_binaries": 0},
               "skipped_count": {"size_limit": 0, "encrypted": 0, "unsupported": 0, "parse_error": 0},
               "limitations": []},
  "errors": []
}
```

The sample hashes, numbers, scores and confidence are illustrative, not measured results. Do not hardcode sample scores into production tests.

## 8. End-to-end identification process

### Stage A — Intake and format dispatch

1. Validate `path` exists, is file/allowed directory, and lies within input handling limits.
2. Hash original input with streamed SHA-256; record file size and path.
3. Detect with file magic: ZIP (`PK...`), DEX (`dex\n` and supported header), ELF (`\x7fELF`). Do not trust filename extension alone.
4. ZIP: use `ZipFile.infolist()`, prevalidate every member's normalized path, metadata, compression ratio, uncompressed size and encryption flag. Discover `classes*.dex` and native ELF files by path **and** magic. Read only selected members; avoid extract-all.
5. APK: process all discovered DEXs and supported ELF files; preserve each member's original ZIP path and content SHA-256. Inspect only limited relevant metadata/paths (Manifest existence, Maven metadata if present, Flutter/React Native engine markers). No JS parsing.
6. Directory: walk only regular files, no symlink follow; enforce aggregate file count, depth and total bytes. Do not recursively explode nested ZIPs.
7. Order inputs and members lexicographically (stable ordering), deduplicate repeated SHA-256 payload processing while retaining all distinct locations.

### Stage B — Feature extraction

DEX with LIEF:
- `lief.DEX.parse(raw_bytes, name=member_name)`; handle `None` and parsing exceptions.
- Iterate `dex.classes`, record descriptor (`fullname`), package, parent, flags, implemented methods, field types, method prototypes (as available from the pinned LIEF build), original `source_filename` if available.
- Do not depend on JADX output. Do not interpret raw Dalvik bytecode without a real instruction decoder.
- For each class, compute both a name-sensitive hint and a name-independent structural fingerprint; keep raw locators separate from fingerprints.
- Multiple DEX files produce **one shared class feature collection**; preserve per-DEX locators. Repeated/conflicting definitions are reported, not silently overwritten.

ELF with LIEF:
- `lief.ELF.parse(raw_bytes)`; collect ELF machine/architecture, SONAME where present, build-id notes, imported/exported dynamic symbol names, and original SHA-256.
- Missing/stripped symbols and build IDs are normal. A filename or architecture is never enough to claim exact library/version.
- Do not use binary name `libcrypto.so` as definitive evidence of a particular implementation (OpenSSL, BoringSSL, embedded fork, etc.).

Metadata:
- Gather `META-INF/maven/**/pom.properties` or analogous trusted library packaging metadata **when actually present**; keep exact member path and declared source. An APK may contain arbitrary metadata; treat it as a claim to corroborate, not cryptographic proof.
- Recognize `libflutter.so`, `libapp.so`, common React Native engine/classes as **framework hints** with clear limitations; do not infer underlying Dart/npm packages.

### Stage C — Fingerprinting

**DEX class shape fingerprint `dex-shape-v1`:**
1. For every class definition, build a canonical feature map consisting of: class access-category flags; counts of fields/methods/interfaces; normalized field type categories; sorted method signatures of normalized parameter/return type categories; method attribute flags (static, abstract, native, constructor, visibility); superclass/interface type categories (optionally preserved stable Android/JDK API descriptors when known).
2. Type normalization: primitives stay primitive; objects not recognized as stable platform API become `OBJECT`; arrays preserve depth and normalized element type. Strip all library-specific class names and ordinary method identifiers; distinguish constructors/initializers.
3. Serialize as canonical JSON (`sort_keys=True`, fixed separators, UTF-8, stable sorted lists); hash `b"dex-shape-v1\0" + canonical_bytes` using SHA-256.
4. Store **multiplicity** of every class-shape digest per library release. Save raw class names only as locators or name-sensitive hints; they must not affect the rename-invariant digest.
5. Mark structurally generic shapes (empty/trivial classes; signatures appearing in many unrelated library families) as low-discriminative. Never promote matches based solely on them.

`dex-shape-v1` is designed for an initial conservative matcher. It is not guaranteed resistant to aggressive R8 transformations, inlining, class merging, code removal or arbitrary obfuscation. Do not advertise equivalence with LibScout. Future `dex-opcodes-v2` may add normalized Dalvik instruction patterns after a justified decoder has been implemented and tested.

**ELF fingerprint `elf-identity-v1`:**
- Primary strong signal: exact SHA-256 match to a reference ELF of known identity/version.
- Secondary identity evidence: SONAME + stable set of distinctive exported symbols + build ID or distinctive known metadata, with ambiguity checked against all profiles.
- Filename and architecture only create **hints**. A stripped ELF without fingerprints remains unknown or low-confidence; never infer exact version from SONAME alone.

### Stage D — Candidate retrieval and matching

1. Look up exact whole-artifact hashes and strong metadata identifiers first.
2. For DEX features, use SQLite inverted index `class_digest → reference release IDs`, rather than comparing the app against every release in Python.
3. For each reference release, compute matched class-shape multiplicity as the sum of `min(observed_count[d], reference_count[d])` over digests. A class shape cannot match more reference instances than exist in the observed app.
4. Weight distinctive class shapes more heavily: for each digest, `weight(d)=1+log((1+N_families)/(1+families_containing(d)))`. Compute `weighted_coverage = sum(weight × matched_count) / sum(weight × reference_count)`.
5. Classify high-frequency trivial shapes as weak, and require **multiple discriminative class matches**. A match to three trivial classes does not count as three meaningful anchors.
6. Rank candidate **families** by weighted coverage and evidence specificity. Then examine compatible **versions** within that family separately. Prevent overcounting equivalent profiles across release versions.
7. Where competing families claim the same ambiguous observed classes, do not assign ownership twice: keep conflict/alternative candidates and mark impacted classes `unknown` pending disambiguation. If strong, nonoverlapping subsets support two libraries, both can be reported.
8. Record the matched class descriptors and DEX members; avoid storing all observed class features in the human-facing summary by default.
9. Do not create matches for unrelated callers that merely invoke a known library API: an invocation proves use, not that the library's implementation is embedded.

**Initial configurable policy (calibrate before v1 release; thresholds are starting values, not established accuracy claims):**
- Structural identity may be `medium` only with **at least 3 discriminative class matches**, weighted coverage **≥ 0.75**, and a distinguishable family candidate. Otherwise label weak hint/unknown.
- Structural identity may be `high` with **at least 5 discriminative class matches**, weighted coverage **≥ 0.90**, at least 2 uncommon anchor signatures, and runner-up **family score gap ≥ 0.15**. Otherwise keep `medium` or ambiguous.
- Libraries with fewer than 3 distinctive classes require an independent strong metadata/exact-binary signal to establish identity; don't lower thresholds globally.
- Version `high` only from a sufficiently unique trusted reference artifact hash or corroborated release-specific metadata **plus** compatible fingerprints. For structural-only matches, return bounded version candidates with `version=null` and `version_confidence=unknown` in v1, even if one reference profile scores best.
- A `low` identity is informational and **cannot** produce an OSV-eligible versioned SBOM component.
- Ensure all score logic is deterministic; keep raw feature counts and runner-up scores internally for explanations and reproducibility.

### Stage E — Aggregate, serialize, report coverage

1. Merge per-file results by canonical library family, but keep separate physical occurrences/ABIs and version ambiguities. Never collapse two confirmed different versions of the same library.
2. Convert high/medium-confidence matches into inventory components; weak hints go into limitations/hints, not definitive component list.
3. Populate code ownership hints **only** for classes reliably matched to a specific embedded component. All other classes remain unknown; Moraine will add application context.
4. Sort components by stable family ID/variant and code locators; deterministic IDs generated from canonical identities and scanned artifact hash.
5. Write `ScanResult` with database/version/algorithm provenance, even when no libraries are identified. Empty components is not equivalent to full coverage.
6. If parsing of selected members fails, report `partial` and errors; never quietly claim complete inspection.

## 9. Local reference-profile construction

### 9.1 Catalog format

```json
{
  "schema_version": 1,
  "references": [
    {
      "purl": "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0",
      "path": "reference-artifacts/okhttp-4.12.0.jar",
      "sha256": "<verified-reference-hash>",
      "license": "Apache-2.0",
      "provenance_url": "https://repo.maven.apache.org/maven2/..."
    }
  ]
}
```

Catalog entries are reviewed/curated. The local builder verifies SHA-256 before generating signatures. The repository need not contain any copyrighted artifact. Reference downloads, if added later, must be a separate explicit `profiles fetch` maintenance command, never part of `identify`.

### 9.2 Builder pipeline

1. Validate reference file and declared PURL/version; verify SHA-256 if supplied; record source and license metadata.
2. `.dex`: directly extract via LIEF. `.so`: directly extract via LIEF.
3. `.jar`: execute a **local, user-provided D8** on Java bytecode in an isolated temporary directory to obtain DEX. `.aar`: extract `classes.jar` safely, then the same D8 step. Supply local `android.jar`, additional classpath only if required; never fetch dependencies on demand.
4. Extract `dex-shape-v1` or `elf-identity-v1` features using **the same exact code** as scanning unknown binaries. Never duplicate fingerprint logic in profile builder.
5. Validate profile quality (nonempty, expected class count, minimum discriminative features, no accidental contamination from bundled extra JARs).
6. Store a new versioned release with provenance in SQLite in one transaction; duplicate artifact/profile hash is idempotent; conflicting same PURL+version references are explicitly recorded or rejected.
7. Regenerate database metadata/manifest with `fingerprint_algorithm`, schema version, build timestamp and counts; generate stable database hash after finalization. Open matching database read-only during `identify`.

**D8 note:** D8 is part of Android SDK Build Tools and accepts JAR/class inputs; it is used only for offline **profile generation**, not required to scan APKs. Different compiler/optimizer pipelines can change fingerprints. Test JAR→DEX profile matching against app-produced DEX before claiming high confidence.

### 9.3 SQLite profile store (v1 schema)

```sql
CREATE TABLE db_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE library_family (
  family_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  ecosystem TEXT,
  package_name TEXT
);
CREATE TABLE library_release (
  release_id TEXT PRIMARY KEY,
  family_id TEXT NOT NULL REFERENCES library_family(family_id),
  version TEXT NOT NULL,
  purl TEXT NOT NULL,
  source_sha256 TEXT NOT NULL,
  source_format TEXT NOT NULL,
  provenance_json TEXT NOT NULL,
  fingerprint_algorithm TEXT NOT NULL
);
CREATE TABLE dex_shape (
  release_id TEXT NOT NULL REFERENCES library_release(release_id),
  digest TEXT NOT NULL,
  multiplicity INTEGER NOT NULL CHECK(multiplicity > 0),
  PRIMARY KEY (release_id, digest)
);
CREATE INDEX idx_dex_shape_digest ON dex_shape(digest);
CREATE TABLE elf_identity (
  release_id TEXT NOT NULL REFERENCES library_release(release_id),
  abi TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  build_id TEXT,
  soname TEXT,
  symbol_digest TEXT,
  PRIMARY KEY (release_id, abi, sha256)
);
CREATE INDEX idx_elf_sha256 ON elf_identity(sha256);
```

The SQLite file is a distributable local *generated database*, not a server. Use WAL only during profile construction if needed; distribute a checkpointed read-only final file. The database schema and fingerprint algorithm must be version checked before matching.

## 10. CycloneDX and local OSV boundary

- `export_cyclonedx()` emits a CycloneDX 1.5 JSON SBOM with library components having a well-supported PURL **and version**. Include `bom-ref` mapped back to component ID. The detailed inventory remains the source of truth for unknown-version components.
- If a component is only identified to family with `version=null` or several candidates, **exclude it from the vulnerability-eligible SBOM** and record why. Optionally include unversioned entries in a separate *inventory* SBOM, never confuse them with positively matched CVEs.
- Do **not** import, vendor or execute OSV from LibIdentifier. OSV is a separate executable and local advisory database managed by Moraine or another host application.
- A suitable **OSV-Scanner V2** host-side operation is:

```text
osv-scanner scan source -L components.cdx.json --offline --format json --output-file osv-results.json
```

- Host sets `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` to a pre-provisioned local database. During `scan`, never set database-download or remote API flags. Preserve scanner version, database state, stdout/stderr and command records. Treat missing database as `BLOCKED`, not as zero vulnerabilities.
- Even when OSV finds an advisory for an identified version, Moraine must assess component matching confidence and application exposure before expressing risk. A package with unknown version cannot be declared affected merely because advisories exist for some releases.

## 11. Framework handling and scope

- Java/Kotlin and Android Jetpack Compose / Compose Multiplatform Android: examine compiled DEX classes. No Compose-specific decompiler required.
- Flutter: may recognize engine artifacts (`libflutter.so`, `libapp.so`) as framework hints. The Dart AOT application/package dependency inventory is **not supported**; native and Android plugin DEX/ELF are still scanned.
- React Native: identify native DEX/ELF components and framework markers. Hermes bytecode and npm/JS bundle dependency identification are **not supported**.
- WebView/Cordova/Capacitor: analyze embedded Android DEX/ELF, not JavaScript libraries. A WebView API reference alone is not proof of a hybrid framework. Remote content is outside APK scope.
- There is no separate per-framework scanner in v1. A tiny `frameworks_detected` heuristic list can be derived from recognized files/classes; mark framework package coverage accurately.

## 12. Input safety, resource budgets and reproducibility

Initial limits are configuration defaults and should have automated stress tests:

```text
max_archive_members = 20000
max_member_uncompressed_bytes = 128 MiB
max_total_selected_uncompressed_bytes = 512 MiB
max_compression_ratio = 200
max_directory_files = 20000
max_directory_depth = 8
max_scan_seconds = 180
max_emitted_unknown_classes = 5000   # cap JSON listing only, not analysis
```

- Verify normalized ZIP member paths (reject absolute paths, `..`, drive prefixes, NULs); no path traversal. Check encrypted files; reject/safely skip unsupported compression. Do not `extractall()`.
- Check actual decompressed bytes while streaming, not only declared ZIP sizes, and enforce cumulative quotas. Reject nested archive recursion in v1.
- Never execute APK/DEX/ELF/JAR code, run arbitrary build scripts or call network APIs. D8 only processes **trusted local reference inputs** in the builder.
- Hash streams rather than loading the entire APK into memory. Individual selected DEX/ELF buffers may be loaded when LIEF requires them, subject to per-member limits.
- LIEF is native code: parsing malformed inputs can trigger native failures. Moraine should call the LibIdentifier CLI in a managed worker process for hostile APKs if in-process stability becomes an issue, even though a direct imported API remains available. An optional isolated worker may be introduced later; don't invent one without demonstrated need.
- Make sorting deterministic: same APK, profiles, algorithm and config produces byte-equivalent JSON except explicitly identified nondeterministic timestamps (prefer scanning timestamp outside the deterministic result or separate metadata).
- A profile DB must not be mutated during matching; require compatible algorithm/schema versions. A missing or incompatible DB is an explicit error, not a silent empty result.

## 13. Moraine integration contract

Moraine depends on LibIdentifier, never vice versa.

```python
from libidentifier import identify

scan_result = identify(apk_path, profiles=managed_profile_db)
# Moraine owns CMD, EV, OBS, FC, AP persistence and reporting.
```

**Moraine CMD:** records logical LibIdentifier invocation and runtime tool/library version; **EV:** complete original APK/DEX/ELF artifacts when preserved plus complete `libraries.json` and optional SBOM / OSV JSON; **OBS:** `sca.library.detected`, `sca.library.version_candidates`, `sca.advisory.matched`, with accurate evidence refs and class/member locators; **FC:** potential vulnerable dependency only with credible version-advisory association; **AP:** only if connected to evidence-backed application use/attack routes.

- `class_ownership_hints` feed Moraine's ownership index. Unknown remains unknown; manifest/app-package heuristics run on Moraine side.
- The matching engine does **not** produce Moraine Observation or Finding rules. Mapping lives in a thin Moraine SCA adapter.
- If no profile matches, result is a successful identification pass with `components=[]`, preserved coverage and unknowns; not a claim of no dependencies.
- OSV output must be treated as independent tool Evidence and CMD, not mixed into LibIdentifier's identification confidence.

## 14. Tests and verification (mandatory)

### Unit tests

- Supported magic detection vs misleading extension; ZIP member ordering; encrypted member/oversize/zip bomb/path traversal/symlink cases; invalid DEX/ELF.
- Canonical fingerprint stable under method/class traversal order; rename-only changes to non-platform identifiers don't change `dex-shape-v1` if structure is unchanged; a material shape change can alter hash.
- SQLite schema migration refusal/incompatible algorithm; repeated profile build idempotency; duplicate reference mismatch.
- Class-shape weighting, multiplicity, family competition, tiny-library rejection, overlapping assignments; deterministic tie-breaking.
- Version ambiguity: two candidate releases with shared signatures produce `version=null`, not fabricated exact version.
- CycloneDX: only high-confidence exact-version packages become vulnerability-eligible entries, with valid PURLs.
- Windows paths and UTF-8 console output.

### End-to-end fixtures

1. Synthetic APK with app-owned classes + recognizable third-party classes in same DEX.
2. Multidex APK with a library split over `classes.dex` and `classes2.dex`.
3. Two versions of one known library and one unknown/modified version.
4. R8/ProGuard renamed-package fixture; only assert recognition if v1 fingerprints actually support it; otherwise assert explicit uncertainty.
5. Native `.so` reference exact-match + unrelated ELF of same SONAME, to prevent false exact versions.
6. Flutter-/React Native-style archive markers: report limited scope and native components without trying to identify JS/Dart packages.
7. Known-negative app containing many trivial classes, to test false-positive suppression.
8. Fully disconnected execution (no network, no Java, no D8, no OSV), proving identification is self-contained.
9. Optional host-level OSV test with a pinned binary and preloaded offline database; deliberately missing cache must produce `BLOCKED`.

Tests in CI must be offline and deterministic. Any reference binaries checked into test fixtures must have documented redistribution rights; otherwise generate synthetic DEX/ELF fixture binaries during a controlled build or store tests with separately downloadable fixtures outside normal CI.

### Release gates

- Entire positive/negative fixture suite passes Windows and Linux.
- No guessed exact versions, no unknown class misreported as app-owned, no unbacked third-party ownership assignments.
- All identified classes map to an input DEX member/descriptor; all identified native binaries map to ELF member and checksum.
- Unknown and partial coverage are visible in JSON and CLI.
- Reproducible profiles/database hash from the same input corpus and builder version.
- Profiling does not need internet; scanning does not need Android SDK or Java.
- Integration fixture confirms Moraine can import the package and generate EV/OBS records without LibIdentifier importing Moraine.

## 15. Implementation stages — practical deliverables

**Stage 1 — End-to-end minimal but useful v1**
- Build packaging, API, CLI, models/config/errors, safe APK ZIP traversal, LIEF DEX+ELF extractors, deterministic JSON, and basic coverage.
- Build local profile creation (`.dex`, `.so`, JAR/AAR through explicit D8), SQLite schema/inverted index, `dex-shape-v1`/`elf-identity-v1`, generic matcher, version ambiguity policy, several tested reference releases.
- Acceptance: given a sample APK containing known libraries, a single `libidentifier identify` outputs real matches with evidence locators and unknown coverage. No handwritten library-specific detectors, no OSV or Moraine dependency.

**Stage 2 — Integration and confidence hardening**
- Add CycloneDX 1.5 export, benchmark known false positives/negatives, calibrate thresholds, tune overlapping component/ownership logic; document limitations.
- Integrate as a pinned Python package in Moraine; Moraine handles CMD/EV/OBS, ownership, offline OSV-Scanner and final report.
- Acceptance: a pinned APK test yields complete identification output, valid offline OSV invocation where version eligible, and no false confirmation on unknown versions.

**Stage 3 — Optional detection improvements, independently releasable**
- Introduce normalized Dalvik opcode fingerprints (`dex-opcodes-v2`) with a narrow proven decoder (either original code or correctly attributed adapted code); ensure v1 profiles remain supported or rebuild explicitly.
- Add better obfuscation/R8 resilience, version discrimination, expanded reference libraries, native code signatures; only add inputs/framework ecosystems after explicit scoped research.
- No JS/Hermes/Dart identification as a prerequisite for any stage.

Each stage must leave working software with tests and documentation; don't establish dozens of empty future adapter abstractions.

## 16. Licensing, attribution, and research boundaries

- Study LibScout's [repository](https://github.com/reddr/LibScout), particularly its per-version profile generation and matching philosophy, and Androguard's [repository](https://github.com/androguard/androguard). **Do not copy upstream files into v1 by default.**
- If code is actually copied/adapted from Apache-2.0 projects: retain relevant copyright notices, include the license, mark modifications, and preserve applicable NOTICE material. Record upstream revision and modified paths in `THIRD_PARTY_NOTICES.md`. Their projects' licenses do not automatically cover independent third-party profiles, SDK artifacts, or bundled dependencies.
- Attribute research approaches in `docs/fingerprints.md` even when implementing independently. Validate any reference release/profile database redistribution rights prior to distributing it.
- A profile is an artifact generated from external libraries. Store fingerprints rather than shipping the original libraries unless permitted; record their provenance, hashes and licenses.
- The Apache-2.0 choice for LibIdentifier's original code is proposed, not mandatory; select deliberately before public release.

## 17. Things that must not happen

- No separate `detect_okhttp()`, `detect_gson()` etc. per library; use generic profiles and matching.
- No unconditional `import androguard` or `import libscout` in v1.
- No identity inference from package prefix or filename alone as a high-confidence detection.
- No collapsing a multidex APK into a single library; no inferring app ownership from code that did not match a profile.
- No exact version from best-only structural similarity or from a single shared class.
- No declaring CVEs for unknown versions.
- No OSV/API network calls within identification; no embedded OSV implementation.
- No unused JS/Hermes/Dart scanners or generic plugin framework.
- No discarded parser errors or false `complete` status after a partial scan.
- No report or Moraine security entity imported into LibIdentifier.

## 18. External contracts verified for this specification

- LIEF DEX Python API: `lief.DEX.parse`, classes, methods, bytecode; Dalvik disassembly not included: https://lief.re/doc/stable/formats/android/dex/python.html and https://lief.re/doc/latest/tutorials/10_android_formats.html
- LIEF ELF Python API: `lief.ELF.parse`: https://lief.re/doc/stable/formats/elf/python.html
- Android D8 Java→DEX conversion: https://developer.android.com/tools/d8
- LibScout profiling/matching and reference JAR/AAR: https://github.com/reddr/LibScout
- OSV-Scanner V2 SBOM scan CLI: https://google.github.io/osv-scanner/usage/scan-source
- OSV-Scanner offline DB: https://github.com/google/osv-scanner/blob/main/docs/offline-mode.md
- Apache License 2.0 redistribution terms: https://www.apache.org/licenses/LICENSE-2.0.html

**Implementation note:** All file formats, schema and API names above are *target contracts* for a new project; the code does not yet exist. The numeric matching thresholds are initial test hypotheses and must be calibrated on known positive/negative fixtures before a release declares measured accuracy.
