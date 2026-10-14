# Stage 2 OSV convenience validation

Validated 2026-10-15 (Europe/Madrid). This supplements the earlier offline assessment report; previous test counts describe the earlier implementation.

Pre-production commit verification: the complete current Windows suite passed **99 tests in 78.59 seconds** using `.pytest_tmp/preproduction-commit`; staged whitespace checks passed. This remains a development prototype, not a production release. Downloaded executables, local databases/manifests and caches are excluded from the commit; previously tracked regression fixtures remain available.

Release-filename follow-up: discovery now accepts original Windows/Linux amd64/arm64 executable names as well as conventional names, preferring the native architecture among release assets. Missing-scanner stderr includes `https://github.com/google/osv-scanner/releases` and the qualified version. Darwin assets and `osv-scanner_SHA256SUMS` are excluded. Focused suite: **20 passed on Windows in 13.90 seconds**, **20 passed on Linux in 28.82 seconds**. Both platforms executed the approved amd64 binary under its original release filename; arm64 selection was tested synthetically, without ARM hardware. Explicit overrides and JSON contracts are unchanged.

## Implementation

- `identify --vulnerabilities` uses the existing schema-1 assessment envelope and correlation engine. Plain `identify`, Python signatures, result models and existing commands retain their contracts.
- CLI scanner selection: explicit path, otherwise PATH, then working directory. Approval hashes and runtime version remain mandatory before execution or database download.
- CLI database selection: explicit path, existing `./advisory-db`, otherwise persistent Windows/Linux user cache. Only an absent directory is automatically provisioned; `--offline` prohibits that download. Existing invalid/stale snapshots require explicit maintenance.
- Missing scanners return identification successfully with a stderr warning and explicit `blocked` report, `scanner_missing` error and `not_assessed` component statuses. Other setup failures preserve identification and return an operational error.
- Tables retain library/version-candidate presentation and print attributed advisory IDs/aliases with confirmed-version or potential labels. Candidate reference versions are never submitted as installed versions.
- OSV execution remains full offline with controlled arguments, isolated generated dependency input and `shell=False`. Only archive provisioning contacts the official fixed Maven feed; no APK or inventory is uploaded. Python `scan`/`correlate` remain download-free.

## Executed checks

- Windows: Python 3.12, LIEF 0.17.1, official OSV-Scanner **2.7.0** amd64: **88 passed in 46.35 seconds**.
- Linux: WSL Ubuntu, Python 3.14.4, LIEF 0.17.1, official OSV-Scanner **2.7.0** amd64: **88 passed in 142.54 seconds**.
- Linux with no internet route (`unshare -n`): **23 assessment/convenience tests passed in 102.67 seconds**. Bootstrap fixtures simulate the allowed download; all actual scanner invocations operate without networking. Tests cover discovery priorities, explicit overrides, default databases, offline setup prohibition, missing/unapproved scanners, download interruption, inventory preservation, advisory IDs, and existing affected/unaffected/version/timeout/database contracts.
- Actual automatic provisioning downloaded the official Maven archive on Windows, validated it, and published a usable snapshot. Maven archive SHA-256: `6df61848ce40744419122f1c56c13221e92d461890dd38998f6bd0cf90937e44`; retrieval timestamp and generation are recorded in the Windows JSON below.
- All six preserved APKs were rescanned using CLI discovery on Windows and Linux. Linux sample assessment ran under `unshare -n`. Input hashes, library/framework identities, unknown-class counts and unknown version semantics remained unchanged. No confirmed version-applicable findings were manufactured.
- `git diff --check` passed.

Initial runs exhausted available disk space because test fixtures copied the large OSV executable repeatedly. Generated pytest directories were removed within the workspace. Test installation now makes one executable copy per session; the successful Windows/Linux results above supersede those environment failures. A preliminary hard-link optimization was incompatible with the restricted Windows test environment and was replaced by the portable session copy. Windows native and Linux WSL amd64 were exercised; ARM64 and bare-metal Linux were not available.

## Real APK results

| APK | Identified libraries | Framework | Full unmatched definitions | Potential advisory groups | Confirmed affected |
| --- | --- | --- | ---: | ---: | ---: |
| Allsafe | OkHttp, RootBeer | — | 11,750 | 2 | 0 |
| AndroGoat | OkHttp | — | 7,127 | 2 | 0 |
| DIVA | None identified | — | 6,493 | 0 | 0 |
| InjuredAndroid | None identified | Flutter | 3,798 | 0 | 0 |
| InsecureBankv2 | None identified | — | 6,529 | 0 | 0 |
| OVAA | Gson, OkHttp, Retrofit | — | 7,410 | 2 | 0 |

OkHttp's package advisories remain potential: `GHSA-3cqm-mf7h-prrj` / `CVE-2021-0341` and `GHSA-4hc2-jh7r-wrc3` / `CVE-2016-2402`. Installed versions are unknown. Medium-confidence Gson/Retrofit identities are unassessed. No identified components means `not_applicable`, not a clean or exhaustive scan. Flutter indicators are not dependency identities.

Reproduction: `test-results/validate-osv-convenience.py` (Windows actual bootstrap uses `--bootstrap`; Linux uses a locally imported snapshot). Detailed provenance and sample hashes: [Windows](osv-convenience-validation-windows.json), [Linux](osv-convenience-validation-linux.json).

## Modified files and remaining limits

Changes are confined to `src/libidentifier/cli.py`, new `vulnerabilities/setup.py`, the shared unavailable-report helper in `vulnerabilities/correlate.py`, `tests/test_osv_convenience.py`, README, integration/quickstart/limitations documentation and this validation script/report/output. No identification algorithms, profiles, sample files, API signatures or JSON schemas changed in this increment.

Coverage remains Maven-only and dependent on profile-supported identities and reliable version evidence. Existing databases are not silently repaired; a failed first download may leave a directory requiring explicit `vulnerabilities update`. Approved executable and cache files must not be mutated concurrently. OSV flags enforce the qualified executable's offline behavior; the wrapper is not an OS egress sandbox. Existing in-process LIEF timeout and parser-memory limitations remain. Stage 3 must preserve public field meanings, unknown-version semantics and assessment attribution while internal fingerprints and databases evolve.
