# Initial distribution readiness (Phase A)

Priority: publish an independently usable preview package and a small validated
profile snapshot, then qualify consumers. Catalog size and production accuracy
improve later. This checklist does not claim publication has occurred.

| Requirement | Status | Acceptance |
|---|---|---|
| Stage 2 public models, detection and offline assessment | Implemented | Preserve APIs, JSON schema 1, CLI and native OSV regressions |
| Advisory maintenance and CLI provisioning | Implemented | Missing-only provisioning; offline prohibits downloads; explicit refresh |
| PyPI package release | Pending | Versioned wheel/sdist, installed-package smoke test, release provenance |
| Official profile snapshot | Rebuilt locally; publication pending | Small schema-2 snapshot, integrity and engine validation, documented coverage |
| Distribution manifest/checksums | Pending | Immutable snapshot ID, SHA-256, schema/engine compatibility, provenance and catalog coverage; no machine-specific paths |
| Generic profile acquisition | Pending | Explicit download/import, bounded validated input, checksum/compatibility checks, atomic install and offline local input |
| Standalone release instructions | Pending | Clean installation, profile acquisition, optional OSV setup, offline use and explicit updates |
| Clean-install qualification | Pending | Use packaged artifacts and downloaded release assets on supported platforms; record skips and provenance |

The retained ignored development snapshot is `.local/profiles/profiles.sqlite`:
schema 2, fingerprint bundle `dex-shape-v2-canonical+elf-identity-v1`, six families,
eight releases, eight artifacts/variants and 1,154 fingerprints. It is a preview
catalog with no published POM metadata, not a production accuracy benchmark.
Its adjacent build manifest is historical generation evidence, not the proposed
release distribution manifest. Do not relabel its manifest schema as DB schema 2.

Phase B belongs to each consuming application: install pinned engine/profiles,
provision OSV-Scanner and advisory data during initialization, validate health,
coordinate explicit updates and render/correlate public results. Analysis APIs
never provision resources. Application-specific code and installation notes do
not belong in this project's published source or documentation.

Phase C expands the catalog, adds POM metadata and improves detection through
[Stage 3](stages/stage-3.md), without redesigning the public concepts.
