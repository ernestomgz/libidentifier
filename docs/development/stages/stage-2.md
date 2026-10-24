# Stage 2 functional foundations

Status: M0–M4 implementation and local native/offline qualification complete.
See the [validation report](../validation/stage2-validation.md) for exact
commands, environments and remaining hosted-CI scope.
Optional OSV provisioning/discovery/fallback and compact CLI behavior are preserved.

Acceptance checklist (only mark complete with recorded checks):

- [x] M0: original specification archived verbatim, authorities and links reconciled.
- [x] M1: canonical descriptors/interfaces, duplicate definitions and ambiguous ownership tested.
- [x] M1: additive evidence/run models and legacy JSON tested.
- [x] M1: OSV discovery, automatic missing-DB provisioning, offline prohibition,
  existing-DB nonrefresh and graceful fallback retained.
- [x] M2: release/artifact/build/fingerprint/occurrence separation and explicit rebuild.
- [x] M2: direct POM/simple property interpretation; unresolved declarations preserved.
- [x] M2: one supported attributable version metadata path with negative controls.
- [x] M3: inheritance/interfaces/signature edges and ordinary/range invocations.
- [x] M3: correct widths/payloads; malformed/special invocations report partial coverage.
- [x] M3: complete deterministic unknown clusters; unknown origin; singleton support.
- [x] M3: component aggregation retains evidence and excludes ambiguous ownership.
- [x] M4: existing APIs/schema meanings/compact CLI protected; public consumer fixture.
- [x] M4: native Windows/Linux, no-egress OSV and rebuild checks recorded.
- [x] M4: installed-package Python 3.11/3.12/3.13 Windows/Linux matrix and
  per-version Linux no-egress checks recorded, with explicit test exclusions.
- [x] M4: benchmark protocol and initial measurements; exact-version coverage separate.

Tests: `tests/test_stage2.py` plus the existing native extraction, ownership,
profile, OSV, renderer and compatibility suites. The benchmark pilot has no
complete ground truth; production accuracy remains a Stage 3 gate. The local
Python 3.11/3.12/3.13 Windows/WSL matrix passed; the hosted CI matrix retains
runtime/JUnit evidence. Context, scanner-bootstrap and fresh-checkout temporary
directory corrections are recorded in the validation report. All six hosted
jobs passed at `7cd1019`. Application-specific adapters and their qualification
records belong in the consuming repositories.

Consumer integration follows the [initial distribution gates](../release-readiness.md). A CI definition
alone does not constitute platform validation. No full Maven resolver, call
graph, runtime dispatch, data-flow or R8 generation is required in Stage 2.

Repository cleanup and schema-2 resource layout were requalified on local Windows:
[184 passing tests, 2026-10-20](../validation/cleanup-windows-2026-10-20.md).
This follow-up did not run WSL or replace historical platform evidence.

Phase A distribution implementation is locally qualified: public profile
packaging/install/validation, portable manifests, package build and publishing
workflow. [Phase A evidence](../validation/phase-a-windows-2026-10-20.md) records
201 Windows tests and the final 17-case distribution follow-up. Manual publication
and real hosted acquisition remain open in the [release checklist](../release-readiness.md).

Managed CLI first-use setup and clearer user documentation are qualified locally:
[216 Windows tests, 2026-10-21](../validation/managed-cli-windows-2026-10-21.md).
Explicit CLI defaults and analysis APIs remain compatible. Hosted results for
the follow-up commit are separate from this local evidence.

The user-documentation audit adds complete PyPI/GitHub installation routes,
activation-free Windows usage and exact managed update paths. Normal Windows
source installation plus profile-free inspection passed; see the follow-up in
[local evidence](../validation/managed-cli-windows-2026-10-21.md). No analysis API
or runtime behavior changed in that documentation follow-up.

AndroidX version-file follow-up reuses the completed public evidence/assessment
contract without API/JSON/profile-schema changes. Known declarations are preserved
without profiles and require code/reference corroboration before version promotion.
Maven/AndroidX conflicts abstain. Validation and platform scope are recorded in
[AndroidX metadata evidence](../validation/androidx-metadata-windows-2026-10-23.md);
230 native Windows tests passed with no skips. Stage 3 accuracy qualification
remains independent.
