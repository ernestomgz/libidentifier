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

[Stage 1](stages/stage-1.md) is the baseline. [Stage 3](stages/stage-3.md)
targets production quality; [future work](stages/future.md) is optional research.
