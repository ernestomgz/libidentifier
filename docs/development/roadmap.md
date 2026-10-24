# Development roadmap

Delivery sequence: completed M0 → M1 → M2 → M3 → M4 → Phase A initial
distribution → Phase B consumer integration → Phase C / Stage 3 improvements.
See [release readiness](release-readiness.md) for the authoritative Phase A checklist.
Publish a small validated preview catalog first; expansion is not an integration blocker.
Stage 2 establishes working external concepts; Stage 3 improves algorithms and
coverage through those concepts. No identical-results guarantee is implied.

| Milestone | Scope | Main files | Gate |
|---|---|---|---|
| M0 | Documentation authorities, archive, contributor entry point | README, AGENTS, docs | Preserved original and navigable nonduplicated documentation |
| M1 | Canonical extraction, interfaces, location-aware ambiguous ownership, run status | extractors/dex, inventory, matcher, models, api | Structural/ownership fixtures and existing OSV/CLI contracts |
| M2 | Releases/artifacts/variants/fingerprints/occurrences; direct POM declarations; attributable version metadata | profiles, metadata, tests | Variant deduplication, rebuild, unresolved metadata tests |
| M3 | Bounded explicit invocation references, structural edges, unknown clusters, component aggregation | decoder, relationships, grouping, API/models | Instruction/payload correctness, exact evidence, complete cluster accounting |
| M4 | Contract fixtures, consumer harness, platform CI, benchmark protocol | tests, workflow, integration/testing docs | Compatible JSON/API, offline platform checks and recorded acceptance |

M0 changes no API/database. M1/M3 add defaulted public fields and capability status.
M2 increments internal database schema and requires explicit rebuild; existing
generation calls remain supported. M4 freezes semantics, not scores or findings.
Stage status is recorded only in the linked [Stage 2 checklist](stages/stage-2.md).

Post-integration priorities (2026-10-23):

1. Preserve consumer compatibility and expose a stable approved-scanner descriptor/
   preflight maintenance API; current CLI pin lookup is not a public integration API.
2. AndroidX version-file declarations now reuse existing evidence models,
   preserving unsupported/unattributed data conservatively; qualify their measured
   benefit through the benchmarks below. See the [contract](../integration.md#stage-2-evidence-clusters-and-relationships).
3. Establish representative build-ground-truth benchmarks and negative controls,
   then expand trusted profiles, AndroidX coverage and published metadata.
4. Measure metadata gains and errors (exact-version precision and coverage
   separately), then prioritize D8/R8 variants and matching improvements.

Consumer completion and successful publication reported by the maintainer do not
replace platform-specific qualification or measured Stage 3 accuracy acceptance.

[Stage 1](stages/stage-1.md) is the baseline. [Stage 3](stages/stage-3.md)
targets production quality; [future work](stages/future.md) is optional research.
