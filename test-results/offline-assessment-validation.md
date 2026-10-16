# Complete output and optional offline assessment validation

Validation period: 2026-10-14–15 (Europe/Madrid).

The later [scanner compatibility validation](scanner-compatibility.md) replaces this report's single-release executable allowlist with trusted local v2 capability checks and optional checksum pinning, and tests GitHub/WinGet v2.6.0 alongside v2.7.0. Original offline execution and result semantics remain.

Later CLI discovery, automatic missing-database preparation and `identify --vulnerabilities` behavior are validated in [Stage 2 OSV convenience validation](osv-convenience-validation.md). Its 88-test Windows/Linux runs supersede the 79-test counts below; the original Python offline contracts remain unchanged.

## Outcome

LibIdentifier now returns all parsed unmatched definitions by default and supports optional, local advisory assessment through `correlate()` and `scan()`. The identification engine, `identify()` signature and identification JSON schema 1 remain unchanged. Assessment models have an independent schema 1 and link findings to component IDs and exact evidence. Moraine can consume these public APIs without parsing OSV output or querying either database schema.

## Executed checks

- **Windows:** Python 3.12, LIEF 0.17.1, official OSV-Scanner 2.7.0 x86-64; **79 passed in 77.31 seconds**.
- **Linux:** WSL Ubuntu, Python 3.14.4, LIEF 0.17.1, official OSV-Scanner 2.7.0 x86-64; **79 passed in 134.37 seconds**.
- **Network-isolated Linux:** all **14 assessment/output tests passed in 84.86 seconds** under `unshare -n`, without an internet route. This includes local success, missing-cache, stale/corrupt data, and scanner error/timeout cases. It proves operation does not require internet connectivity; the production wrapper itself is not an OS network sandbox.
- Four executable Python examples from `docs/integration.md` were exercised against real sample/profile/advisory paths: identification processing, subprocess scanning, CycloneDX export and combined/cached advisory assessment.
- Explicit CLI update, local archive provision, snapshot validation, combined table output and cached correlation were exercised. Only the explicit advisory update downloaded data.
- `git diff --check` passed.

Windows suite:

```powershell
& 'C:\Users\Windows 11\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -q --basetemp .pytest_tmp/final
```

Linux used a workspace-local virtual environment in `test-results/tmp/linux-venv`, with the executable selected through `LIBIDENTIFIER_TEST_OSV`; the final suite used `.pytest_tmp/linux-final`. Temporary executable/venv/fixtures live in ignored `test-results/tmp`, not package runtime dependencies. An overlapping preliminary Linux run shared a pytest temporary directory and failed on removed fixture paths; distinct temporary directories resolved the harness conflict. Final results above have no failures or skips.

## OSV qualification

The official v2.7.0 release metadata and publisher asset checksums were fetched for qualification. Executed `--version`, `scan source --help`, and `update --help`, then verified actual custom dependency input, cache layout, output and exit statuses.

| Qualified executable | Publisher SHA-256 |
| --- | --- |
| Windows x86-64 | `9964ed64ec9a387391eb4cc006ad5c531154821aef29b793e02c448de4686438` |
| Linux x86-64 | `160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b` |

Runtime version is 2.7.0; the Windows build reported OSV-Scalibr 0.5.3 and commit `bfe2f84abd2f09fe0b83ba7f6dad40d296762f40`. Source checksums for official ARM64 Windows/Linux assets are also allowlisted, but ARM64 execution was not available for validation.

Verified protocol:

- Input is generated `osv-scanner.json` dependency coordinates only. APKs, DEX/ELF bytes and code locators are never sent to OSV.
- Arguments include `scan source`, `--offline`, `--no-resolve`, disabled Go/Rust call analysis, `--all-packages`, `--all-vulns`, JSON format, private empty config and an explicit custom lockfile.
- The actual local archive location is `<cache>/osv-scalibr/Maven/all.zip`, not the legacy `osv-scanner` directory shown in some upstream documentation.
- Exit 1 with matching JSON advisories is an affected-version result; exit 0 with the full expected package inventory and no matches is an evaluated no-match result.
- Missing local cache returns exit 127; an empty custom input returns exit 128. Neither is normalized as clean assessment. Returned coordinates and exit/advisory consistency are checked before accepting results.
- The generated custom-input extractor's derived PURL is not used for attribution. The adapter validates the returned ecosystem/name/version tuple against its own generated inventory and retains LibIdentifier's original package identity.

**Justified deviation:** the real v2.7.0 `update` command updates project manifest dependencies; it is not an advisory archive updater. LibIdentifier instead downloads the official fixed ecosystem archive URL only in its explicit `vulnerabilities update` operation, validates it, builds a package-only index, and atomically publishes a snapshot. OSV still performs all exact-version range evaluation.

## Advisory snapshot and range evidence

The explicit update downloaded the published Maven archive from `https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip` at `2026-10-14T21:42:20.231409+00:00`.

- Archive SHA-256: `6df61848ce40744419122f1c56c13221e92d461890dd38998f6bd0cf90937e44`.
- Package index SHA-256: `61291b50328df325eba3d2f5c4fe12d3addd69ee065e6eaffa3781cbb954f8b1`.
- Snapshot generation: `432ae076abc4452abac64b0c88b7dd46`.
- Local validation snapshot: `test-results/tmp/osv/live-db`.

Actual official-scanner checks against that published snapshot establish that a dependency query for `com.squareup.okhttp3:okhttp` version **4.9.0** matches `GHSA-3cqm-mf7h-prrj` / `CVE-2021-0341`, while **4.9.3** returns no matching advisories in this snapshot. These are controlled backend qualification queries, **not claims about versions installed in any APK**.

Independent synthetic archive fixtures tested affected 1.0 versus unaffected 3.0 under a Maven range fixed at 2.0, alias grouping, withdrawn records, candidate-only and unknown versions. Synthetic `OSV-TEST-*` and `CVE-2099-*` fixture IDs are not real vulnerability findings.

## Six APK regressions

All six APKs were rescanned on both Windows and Linux, using `test-results/sca-reference-profiles.sqlite`. Library identities, confidence, unknown versions and framework evidence match the prior validated baseline. Sample SHA-256 hashes were checked before/after; no samples changed. Linux rescans also ran in the network-isolated namespace.

| APK | Libraries | Framework | Unmatched emitted / total | Advisory outcome |
| --- | --- | --- | ---: | --- |
| Allsafe 1.6 | OkHttp, RootBeer | none detected | 11,750 / 11,750 | 2 potential OkHttp advisories; RootBeer version unassessed |
| AndroGoat 2.0.1 | OkHttp | none detected | 7,127 / 7,127 | 2 potential OkHttp advisories |
| DIVA | none with these profiles | none detected | 6,493 / 6,493 | not applicable: no identified components |
| InjuredAndroid 1.0.12 | none with these profiles | Flutter, high | 3,798 / 3,798 | not applicable: no identified components; Flutter is a presence indicator |
| InsecureBankv2 2.3.1 | none with these profiles | none detected | 6,529 / 6,529 | not applicable: no identified components |
| OVAA 1.0.0 | Gson, OkHttp, Retrofit | none detected | 7,410 / 7,410 | 2 potential OkHttp advisories; medium-confidence Gson/Retrofit unassessed |

**There are zero confirmed affected-version findings in these APKs.** Their identified library versions remain null/unknown. Candidate releases are not queried as installed versions.

Potential OkHttp records:

- `GHSA-3cqm-mf7h-prrj`, with alias `CVE-2021-0341`.
- `GHSA-4hc2-jh7r-wrc3`, with alias `CVE-2016-2402`.

These are package-associated records, not applicability assertions. Historical advisories can be returned even when reference candidates appear newer than affected releases. The actual installed version is unknown and candidate lists are not exhaustive. No reachability or exploitability is claimed.

Machine-readable summaries: `test-results/offline-assessment-validation.json` and `test-results/offline-assessment-validation-linux.json`. Complete JSON outputs are in ignored `test-results/tmp/offline/` and `test-results/tmp/offline-linux/`. Reproduction runner: `test-results/validate-offline.py`; Linux selects the native executable and platform suffix via environment variables.

## Complete output and memory

The default unknown-class cap is now `None`. Explicit caps retain original totals and truncation and leave extraction and component matching unchanged. A 6,001-unmatched-definition fixture, plus matched reference classes, verifies defaults and caps of 0, 7 and 7,000.

Deterministic streaming traverses dataclasses/collections directly without constructing a full dictionary or output string. JSON file replacement is atomic, and interrupted writing preserves prior content. String-returning `to_json()` remains convenient but necessarily allocates the returned JSON. The existing `to_dict()` remains a copy-producing convenience.

A measured Allsafe assessment serialization run used **62,549 bytes** of additional peak Python allocations for streaming versus **8,138,037 bytes** for the dictionary/string path. This is serialization allocation evidence, not an RSS/native-parser memory bound. Tests additionally require streamed JSON equivalence and substantially lower allocation peaks for a 10,000-locator result.

## Stable API and files changed in this increment

Public additions: `correlate`, `scan`, `VulnerabilityOptions`, `VulnerabilityReport`, `AssessmentResult`, and advisory snapshot provision/update/validate functions. Existing identification/profile/SBOM call signatures and identification schema remain intact. Assessment/report kinds use their own schema 1 and tolerant deserialization. Snapshot and approved-scanner compatibility are internal; clients do not query SQLite or parse raw OSV output. Stage 3 identity/version improvements automatically feed the same correlation interface.

Core additions:

- `src/libidentifier/serialization.py`.
- `src/libidentifier/vulnerabilities/models.py`, `database.py`, `runner.py`, `correlate.py`, `__init__.py`.

Updated interfaces/output:

- `src/libidentifier/api.py`, `config.py`, `models.py`, `cli.py`, `errors.py`, `__init__.py`.
- `tests/test_offline_assessment.py`; prior contract test updated for the intentional unlimited default.
- `docs/integration.md`, `docs/quickstart.md`, `docs/limitations.md`, README and validation report links.
- This report, platform-specific summaries and the sample reproduction runner.

Prior working-tree changes were preserved. No identification matcher/fingerprint/framework engine or reference catalog expansion was introduced by this increment.

## Limits and responsibilities

- Maven is the initial qualified advisory ecosystem. Generic native components and other ecosystem identities are explicitly unassessed; future support needs qualification.
- Only high identity confidence is automatically attributed. Unknown versions can yield bounded package-level potential records, not affected-version claims. Medium/low identities remain review cases.
- Local archive import relies on the supplied retrieval timestamp or original file modification time. Hashes provide integrity, not proof of feed authenticity/completeness; trusted provisioning and freshness policy remain necessary.
- The default maximum age is 30 days. Missing/corrupt/stale data blocks assessment; no download fallback exists. Failed/interrupted downloads and publication preserve the previous usable generation.
- Source records are deduplicated by ID, and alias-connected records produce one finding per component/basis while retaining original IDs, affected evidence and severity provenance. Discovery caps count source records, not distinct CVEs.
- Full offline mode, fixed arguments and approved executable hashes implement the qualified tool's offline behavior. Linux no-route testing passed. Independently enforced egress denial belongs to host policy; the Python library is not a cross-platform OS sandbox and does not modify firewalls.
- OSV invocations have timeout/output limits; native memory isolation and total worker deadlines remain host responsibilities. Existing LIEF `max_scan_seconds` is still unenforced in-process and documented.
- No JavaScript/Dart/Hermes/IL2CPP/.NET reverse engineering, dependency graph inference, custom-code classifier or exploitability engine was added. Signature coverage remains limited.
- ARM64 assets are approved by published checksum but were not executed. Validation covers native x86-64 Windows and Ubuntu/WSL; it is not an exhaustive Linux distribution/architecture certification.
- The checkout is unreleased and uncommitted. Record source revision/local changes alongside package version when deploying development builds.
