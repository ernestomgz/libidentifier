# OSV distribution and version compatibility validation

Validated 2026-10-16 (Europe/Madrid). Pre-production development work, not a production release.

## Diagnosis and change

The installed WinGet executable reported OSV-Scanner **2.6.0**. Its SHA-256 exactly matches the [official WinGet manifest](https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/g/Google/OSVScanner/2.6.0/Google.OSVScanner.installer.yaml), which downloads the GitHub v2.6.0 asset. The previous four-hash allowlist accepted only v2.7.0 release assets; the failure was an overly narrow approval policy, not an unofficial WinGet binary.

The adapter now accepts trusted local native **v2** installations by interface compatibility instead of installation channel or a single build's hash. Version and bounded offline help probes check the supported major and required flags. Actual inventory coordinates, JSON and exit-code consistency remain checked. An optional `scanner_sha256` option / `--osv-scanner-sha256` pin preserves exact executable approval policies; mismatch is rejected before execution. Actual executable path, version and SHA-256 remain recorded in the existing schema-1 `ScannerRecord`.

Native GitHub assets, WinGet, Scoop/native package-manager launchers, Linux distribution builds, and identifiable v2 source builds use the same checks. Compatibility probes do not authenticate a publisher; the installed executable must be trusted by the operator. Verify it through trusted packaging, publisher checksums or provenance, and pin it when required. No executable downloads or online checksum lookups occur during scanning. The approach follows upstream's [documented installation channels and same-major compatibility policy](https://google.github.io/osv-scanner/installation/).

This does not claim compatibility with every historical/future release. v1, future major versions, unidentifiable development versions and missing required flags fail with `scanner_incompatible`. Other v2 builds may pass runtime checks, but only versions below were exercised natively. Script/batch wrappers are unsupported; supported platform scope remains Windows/Linux. Executable pinning is optional rather than implicitly provided by a fixed built-in allowlist.

## Executed checks

- Windows Python 3.13.14, LIEF 0.17.1: **159 passed in 117.49 seconds**. Both GitHub v2.7.0 and WinGet v2.6.0 executed known affected/unaffected synthetic dependencies and CLI correlation, including exact pins.
- Linux WSL Ubuntu, Python 3.14.4, LIEF 0.17.1: **159 passed in 388.67 seconds**, entirely under `unshare -n`. Official GitHub v2.6.0 and v2.7.0 binaries were tested with no internet route. ARM64 hardware and bare-metal Linux were unavailable.
- An initial focused Windows run passed **61 tests in 52.65 seconds**.
- Synthetic coverage includes compatible v2 versions/build metadata/pre-releases, rejected major versions/unidentifiable output, each required flag, earlier v2 help exit code 128, optional pin match/mismatch/invalid format, both cache prefixes, hard-link fallback, and all existing malformed-output, timeout, missing/corrupt/stale-database and identification-contract checks.
- All six cached real-APK inventories were reassessed with **each** release on **each** platform. Input APK hashes were rechecked; component assessments, findings and original advisory records exactly matched the preceding snapshots. All sample versions remain unknown and findings remain potential; no confirmed vulnerability was manufactured. The full suites separately cover actual identification of all six APKs.
- The reported Allsafe CLI invocation was reproduced using default WinGet discovery, the original reference-profile database, and an explicitly local advisory database with `--offline`. It completed with two potential OkHttp advisory groups and no `scanner_unapproved` warning.
- `git diff --check` passed. No additional dependencies were introduced; API signatures and result schema fields are unchanged. Options gain only a trailing optional checksum field.

## Executable qualification

| Platform/source | Runtime | SHA-256 |
| --- | --- | --- |
| Windows GitHub release | 2.7.0 | `9964ed64ec9a387391eb4cc006ad5c531154821aef29b793e02c448de4686438` |
| Windows WinGet (GitHub asset) | 2.6.0 | `e0ed7644118b717b028c249ee9d3515024e55e8510747ca08906eb96765354d6` |
| Linux GitHub release | 2.7.0 | `160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b` |
| Linux GitHub release | 2.6.0 | `ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108` |

The additional Linux v2.6.0 asset was downloaded as explicit test setup and verified against that release's publisher checksum file, before network-isolated testing. These hashes document the test matrix; they are not a new runtime allowlist.

## Offline execution and reproducibility

Assessment still uses generated dependency coordinates only, never the APK itself, with `shell=False`, full `--offline`, no dependency resolution and no database-download flag. Private cache views expose the verified Maven archive under both official v2 cache prefixes (`osv-scalibr` and `osv-scanner`), using hard links or bounded local copies. Snapshot contents, hashes, schema and source index remain unchanged. Version/help probes are bounded and isolated; the help probe also uses `--offline`. Strict OS egress enforcement remains a host responsibility.

Reproduce tests with the existing development environment and `LIBIDENTIFIER_TEST_OSV` selecting the primary executable. Set `LIBIDENTIFIER_TEST_OSV_ALTERNATE` for the second Linux release; Windows also discovers an installed PATH scanner for the matrix. `test-results/validate-scanner-compatibility.py` performs cached-inventory regression. Detailed results: [Windows](scanner-compatibility-windows.json), [Linux](scanner-compatibility-linux.json). Older reports describe the earlier pinned-v2.7.0 approval policy and are historical evidence.

Modified files: scanner runner, vulnerability options/setup, CLI checksum option and warning, scanner-compatibility tests, existing probe-aware tests, README, integration/quickstart/limitations guides and this report/script/output. The identification engine, matching/version-confidence semantics and public JSON schemas remain unchanged.
