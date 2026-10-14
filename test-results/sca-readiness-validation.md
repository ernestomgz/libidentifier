# Final SCA readiness and integration validation

Historical identification/SCA contract review. See [the subsequent offline-assessment validation](offline-assessment-validation.md) for unlimited default output, the optional OSV APIs and current Windows/Linux results.

Date: 2026-10-14. Platform exercised: Windows, Python 3.12, LIEF 0.17.1. Linux was not available for execution. Existing sample files were hashed before and after validation and remained unchanged.

## Decision

**The public API, schema-1 output and evidence model are sufficient for an external application to integrate once and consume future Stage 3 improvements without redesigning scan integration**, subject to the documented compatibility contract. Keep named model access, tolerate optional/additive fields and new technology IDs, and leave matching algorithms and database internals to LibIdentifier. Engine upgrades may require reference databases to be rebuilt and deployed with the package. They may change findings, scores, candidate sets and evidence; they must preserve public call signatures and the meanings of confidence, null versions, evidence and partial results.

This is readiness for evidence-based identification and downstream SCA decisions, not exhaustive APK dependency discovery or vulnerability applicability. The API exposes package identity for advisory discovery, exact-version eligibility, technology indicators and unidentified code separately. Direct/transitive status is neither a filter nor an inferred dependency graph.

## Rechecked baseline and tests

The original reported result was independently reproduced: **41 passed** before changes. After corrections and new regressions:

```powershell
& 'C:\Users\Windows 11\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -q --basetemp .pytest-tmp-sca
```

**65 passed in 46.69 seconds**, including all six APK regressions (none skipped). The suite is now explicitly scoped to `tests/`, so temporary verification-tool packages under `test-results/tmp` are not accidentally collected.

Added checks cover unknown/empty-database scope, original unmatched counts and caps, versionless package identity, candidate truncation and weak-overlap exclusion, ambiguous native releases, native copies and unique BOM references, exact evidence containers, changed native bytes, invalid/inconsistent PURLs, withheld SBOM entries, duplicate/corrupt ZIP entries, standalone/archive limits, directory depth reporting, API signatures, and the six real APKs. Prior framework and API serialization contract tests remain active.

Three executable Python examples in `docs/integration.md` were exercised with real sample/database paths: complete processing, subprocess scanning, and SBOM export. The host subprocess timeout example was also exercised and raised `TimeoutExpired` as documented.

## Corrections made

- Empty package-private class definitions are no longer silently dropped. Independent raw DEX counts exposed one missing class in Allsafe and 27 in InjuredAndroid; these are now retained as unidentified code. Existing reference fingerprints remain compatible, and the expanded database was rebuilt with the corrected extractor.
- CLI versions now say `unknown (candidates: ...)` instead of displaying candidate numbers as installed versions. The small table now labels the identity-confidence column explicitly.
- Added optional `ComponentMatch.family_purl` for a namespace-qualified versionless identity. The existing `purl` stays versioned and null when exact release identity is unknown. Added nullable candidate-total/truncation fields; legacy payloads remain readable.
- Candidate releases must have sufficient evidence; incidental shape overlap is no longer enough. Diagnostic candidate scores preserve the basis for the targeted comparison without turning scores into exact-version claims.
- Identical ELF bytes assigned to multiple releases of one family retain the supported identity and report unknown version. Conflicting families remain unidentified. Multiple physical copies aggregate evidence under one component ID, avoiding duplicate CycloneDX BOM references.
- Artifact records now include an optional container. DEX ownership keys include the container as well as member/class, preventing one child APK from masking unmatched definitions in another. Native and DEX evidence retain exact child APK locations.
- Coverage explicitly distinguishes `not_performed`, `no_profiles` and `limited` library identification. It reports `unknown_classes_total`, `unknown_classes_emitted` and `unknown_classes_truncated`. Totals count successfully parsed definitions only.
- CycloneDX exports retain exact-version/high-confidence filtering, reject inconsistent PURL/version identity, declare incomplete inventory, list excluded components/reasons, and retain scan/database provenance and exported evidence in namespaced properties.
- Profile ingestion checks PURL coordinates, and database validation rejects reference identities inconsistent with their PURLs, in addition to existing schema/algorithm compatibility checks.
- Oversized standalone binaries are rejected; archive budget checks occur before full selected-member reads; directory selected-byte limits are shared across child files and traversal prunes excess depth. Duplicate ZIP paths are skipped, and individual corrupt members preserve readable members as partial results.

The public schema stays **1**. Public function signatures remain unchanged. These are additive model fields and corrected matching/diagnostic behavior, not a new classification system or analysis engine.

## Real APK regression results

Each APK was scanned against both the existing seven-profile database and a catalog-rebuilt eight-profile database adding only OkHttp 3.14.9. Both retained the same identified families and framework results, with no analysis errors. The counts below use the expanded database.

| Sample | Identified libraries (identity confidence) | Frameworks | Parsed classes | Unknown emitted / total |
| --- | --- | --- | ---: | ---: |
| Allsafe 1.6 | OkHttp (high), RootBeer (high) | none detected | 12,077 | 5,000 / 11,750 |
| AndroGoat 2.0.1 | OkHttp (high) | none detected | 7,448 | 5,000 / 7,127 |
| DIVA | none with these profiles | none detected | 6,493 | 5,000 / 6,493 |
| InjuredAndroid 1.0.12 | none with these profiles | Flutter (high) | 3,798 | 3,798 / 3,798 |
| InsecureBankv2 2.3.1 | none with these profiles | none detected | 6,529 | 5,000 / 6,529 |
| OVAA 1.0.0 | Gson (medium), OkHttp (high), Retrofit (medium) | none detected | 7,907 | 5,000 / 7,410 |

Every reported component in these APKs has `version=null`, `purl=null` and `version_confidence=unknown`. Every component has a versionless `family_purl`. Reference candidates are Gson 2.11.0, OkHttp 4.9.0/4.9.3, Retrofit 2.9.0 and RootBeer 0.0.8; these are **not confirmed installed versions**.

Every reported class locator from both identification runs and no-database inspection was checked against an independent raw traversal of DEX `class_defs`, without using LIEF or LibIdentifier's definition extractor for that check. Container/member hashes were checked against original ZIP bytes. No reference-only DEX type appeared as embedded class evidence. Full untruncated-definition totals were reconciled with emitted counts and truncation flags.

InjuredAndroid's Flutter detection remains supported by its defined `FlutterActivity`, Flutter asset manifest, and parsed `libflutter.so` files in three ABI directories. The native copies count as one evidence kind. Dart code remains unsupported and no Flutter version is claimed.

All six no-database `inspect` scans explicitly report `library_identification=not_performed`. OVAA against a valid empty database reports `no_profiles`, no identified libraries, and its unmatched code. Neither case claims an absence of third-party software.

## OkHttp 3.14.9 investigation

The [published Retrofit 2.9.0 POM](https://repo.maven.apache.org/maven2/com/squareup/retrofit2/retrofit/2.9.0/retrofit-2.9.0.pom) declares a compile dependency on OkHttp 3.14.9. The downloaded POM is retained at `test-results/retrofit-2.9.0.pom`; SHA-256 is `f7e96a31ded699ee36c4e77695c7c1868aa6b4c64bf998f9dfe0c66f25d0e493`.

A single legitimate [Maven Central OkHttp 3.14.9 JAR](https://repo.maven.apache.org/maven2/com/squareup/okhttp3/okhttp/3.14.9/okhttp-3.14.9.jar) was added to the reviewed catalog. Its SHA-256 is `2570fab55515cbf881d7a4ceef49fc515490bc027057e666776a2832465aeca0`; D8 produced 216 reference class shapes. The reference source was explicitly fetched and the eight-profile database was rebuilt offline through the catalog workflow. No upstream version-discovery feature was added.

| OVAA reference | Exact descriptor-and-shape matches | Weighted reference coverage |
| --- | ---: | ---: |
| OkHttp 3.14.9 | 17 | 0.152630 |
| OkHttp 4.9.0 | 272 | 0.915416 |
| OkHttp 4.9.3 | 273 | 0.917068 |

The 3.14.9 reference is much less consistent with this APK's observed structures and is not a supported candidate under current thresholds. 4.9.x references support family identification, but **do not prove either installed version**. Optimizations, unprofiled releases, overrides, repackaging and structural limitations remain possible; no version is inferred from Retrofit's upstream declaration. The original table's numbers were candidates, not confirmed versions, and the corrected table makes that explicit.

## CycloneDX validation

Validated all **12 real-sample exports** (six APKs, two databases) and one positive exact-native export against the official [CycloneDX 1.5 JSON schema](https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/bom-1.5.schema.json), using jsonschema 4.26.0 as a temporary verification tool. No LibIdentifier runtime or development dependency was added for it. Schema SHA-256: `067f7824b08653839ea050ae9e09ca48375eadc2652b0e2a299476e7db90335b`.

All 13 exports passed. Real-sample exports correctly contain zero eligible versioned components because all library versions are unknown, while carrying `compositions.aggregate=incomplete`, excluded component IDs/reasons and provenance. The positive fixture contains one versioned native component supported by an exact trusted byte hash, with two physical locations and a unique `bom-ref`. Candidate releases and framework indicators are never converted into confirmed versioned dependencies.

## Reproduction and artifacts

- Runner: `test-results/validate-sca.py` (run from the repository root).
- Machine-readable measured results: `test-results/sca-readiness-validation.json`.
- Baseline database: `test-results/samples/reference-profiles.sqlite`.
- Expanded database: `test-results/sca-reference-profiles.sqlite`, SHA-256 `ec35a7061e8a8f02425073d4cd4de274b8725c4dfe2a0819266ee46d3f45c960`, eight releases.
- Rebuild records: `test-results/sca-profile-build.json` and `test-results/sca-reference-profiles.sqlite.manifest.json`.
- Full local JSON/SBOM outputs: `test-results/tmp/sca/` (ignored generated files).
- Executed documentation output: `test-results/tmp/doc-check/` (ignored generated files).

Rebuild command (the D8 wrapper is local to this validation host):

```powershell
libidentifier profiles rebuild --catalog catalog/references.json --cache test-results/reference-artifacts --database test-results/sca-reference-profiles.sqlite --d8 test-results/d8-wrapper.cmd --android-jar C:\Users\Windows 11\AppData\Local\Android\Sdk\platforms\android-35\android.jar --offline
```

For schema reproduction, download `bom-1.5.schema.json`, `spdx.schema.json` and `jsf-0.82.schema.json` from the official CycloneDX specification `1.5/schema` directory into `test-results/tmp/`, and install the verification-only validator with `python -m pip install --target test-results/tmp/schema-validation jsonschema==4.26.0`. Then run `python test-results/validate-sca.py`. This is validation tooling, not a scanning dependency or network requirement.

## Limits and deferred Stage 3 improvements

- A small curated catalog cannot provide exhaustive SCA. Very small or shared profiles can remain below current confidence thresholds. AppCompat, Material, Firebase, Play Services and Kotlin runtime coverage are not claimed merely because the model can represent them. Improving fingerprints and expanding reviewed profiles remain Stage 3 work.
- Structural matching and presence heuristics are not calibrated probabilities. Modified/obfuscated libraries can be missed or remain ambiguous. Package-level advisory discovery is possible through `family_purl`, but unknown versions must remain potential matches until the consumer establishes applicability.
- No dependency graph, direct/transitive classification, unknown-code ownership classifier, CVE lookup, OSV integration or exploitability decision is implemented.
- Flutter/Dart, JavaScript/Hermes, Unity IL2CPP and .NET application payloads remain unsupported. Xamarin/MAUI presence remains grouped. Framework presence does not establish runtime use or dependency versions.
- `max_scan_seconds` remains explicitly unenforced in-process. A thread cannot safely stop a native parser, and Unix signals do not offer a portable Windows/worker-thread contract. Use the documented host subprocess timeout; it was exercised. Hard memory isolation also belongs to the host; byte/member limits do not bound all native allocations or ZIP directory allocation.
- Unknown totals cover successfully parsed definitions, not skipped/unsupported payloads. Unassigned native binaries remain traceable through artifact records; no ownership is guessed.
- Linux execution remains unverified in this session. The implementation uses standard-library mechanisms supported on Windows/Linux, but this report is not a Linux test claim.
- `tool_version` is the package release version; unreleased editable checkouts should also have source revision/local changes recorded externally. The working tree is unreleased and was not committed by this task.
