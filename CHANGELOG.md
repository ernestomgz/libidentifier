# Changelog

## Unreleased

- Recognize known AndroidX `.version` metadata, preserving identity/version/file
  evidence even without code matches. Shared Maven/AndroidX corroboration and
  conflict checks prevent metadata-only confirmed vulnerability assessment.
  Public schemas, API signatures, compact CLI and profile format are unchanged.

## 0.2.0rc1 — Stage 2 preview (publication pending)

- Complete PyPI/GitHub source installation routes, Windows activation-free
  commands, result interpretation, managed-path updates and user troubleshooting.
  README/PyPI links lead to installation/usage before the advanced API reference.

- Managed `scan app.apk` first-run setup with one consent prompt, `--yes`, strict
  `--offline`, project-pinned scanner downloads and persistent per-user resources.
- `--vulns` alias, table default for managed scans, preserved explicit-profile
  JSON defaults and download-free analysis APIs; optional failures retain inventory.

- Explicit profile packaging/acquisition APIs and CLI, portable release manifests,
  hashes, engine compatibility, bounded downloads/decompression, SQLite integrity
  checks and atomic install with explicit replacement. Analysis remains offline.
- Single-source package version, PyPI metadata, wheel/sdist content checks,
  Trusted Publishing workflow and maintainer publication instructions.

- Release-first roadmap: preview package and small schema-2 profile distribution
  before catalog expansion and Stage 3 accuracy qualification.
- Removed obsolete generated validation output and schema-1 sample databases;
  retained selected dated evidence under `docs/development/validation/`.
- Canonical DEX implementation now uses `fingerprint/dex_v2.py`; optional local
  qualification resources use ignored `.local/` and `.tools/` directories.

- Canonical DEX descriptors/interfaces and location-aware ownership uncertainty.
- Additive evidence, analysis status, unattributed clusters and typed structural,
  ordinary invocation, published-dependency and component relationship models.
- Internal reference schema 2 separates releases, artifacts, variants, fingerprints
  and occurrences; canonical fingerprints require an explicit profile rebuild.
- Direct POM/local-property interpretation and attributable embedded Maven metadata.
- Contributor documentation, preserved historical specification, contract fixtures,
  platform CI and a benchmark harness. Existing OSV provisioning/discovery/offline
  execution and compact table behavior are preserved.
- CI validates regular package installations and retains per-environment runtime,
  scanner and JUnit evidence, including skip reasons.

## 0.1.0

- Initial Stage 1 implementation with APK/DEX/ELF inspection, DEX shape fingerprints, ELF identity fingerprints, SQLite profile building, offline matching, JSON output, CLI commands, and CycloneDX export for exact high-confidence versions.

