# Initial distribution readiness (Phase A)

Priority: publish an independently usable preview package and a small validated
profile snapshot, then qualify consumers. Catalog size and production accuracy
improve later. This checklist does not claim publication has occurred.

| Requirement | Status | Acceptance |
|---|---|---|
| Stage 2 public models, detection and offline assessment | Implemented | Preserve APIs, JSON schema 1, CLI and native OSV regressions |
| Advisory maintenance and CLI provisioning | Implemented | Missing-only provisioning; offline prohibits downloads; explicit refresh |
| PyPI package release | Code/workflow prepared; account setup and publication manual | Versioned wheel/sdist, installed-package smoke test, release provenance |
| Official profile snapshot | Rebuilt; portable preview assets prepared; publication manual | Small schema-2 snapshot, integrity and engine validation, documented coverage |
| Distribution manifest/checksums | Implemented | Immutable snapshot ID, SHA-256, schema/engine compatibility, provenance and catalog coverage; no machine-specific paths |
| Generic profile acquisition | Implemented in public API and CLI | Explicit download/import, bounded validated input, checksum/compatibility checks, atomic install and offline local input |
| Managed first-run CLI setup | Implemented; local Windows qualification passed | Consent/yes/offline, pinned scanner, persistent profiles/advisories, table defaults and legacy/API compatibility |
| Standalone release instructions | Implemented; see release guide | Clean installation, profile acquisition, optional OSV setup, offline use and explicit updates |
| Clean-install qualification | Local Windows qualification passed; public/hosted checks pending | Use packaged artifacts and downloaded release assets on supported platforms; record skips and provenance |

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

Implementation and exact manual publication steps: [release guide](../releases.md).
Publication and fresh acquisition from the real hosted assets cannot be claimed
until the maintainer has created the accounts/releases and executed those steps.

Local execution evidence: [Phase A Windows validation](validation/phase-a-windows-2026-10-20.md).
The code is prepared; Phase A publication gates remain open until PyPI/GitHub
releases and acquisition of those real public artifacts succeed.

Managed CLI follow-up: [216 Windows tests and installed-wheel checks](validation/managed-cli-windows-2026-10-21.md).
First-run setup requires the official profile asset URL to be published before
the package is offered to new users.
