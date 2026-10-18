# Stage 2 functional foundations

Status: M0–M4 implementation and local native/offline qualification complete.
See the [validation report](../../../test-results/stage2-validation.md) for exact
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
runtime/JUnit evidence when executed. Context and scanner-bootstrap errors were
corrected; the next hosted run exposed a missing `.pytest_tmp` parent during
fixture setup. Workflow initialization now creates it explicitly. Fresh-checkout
qualification is recorded in the validation report; hosted test qualification
remains pending.

Moraine integration is eligible only after required gates pass. A CI definition
alone does not constitute platform validation. No full Maven resolver, call
graph, runtime dispatch, data-flow or R8 generation is required in Stage 2.
