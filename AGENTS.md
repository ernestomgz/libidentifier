# LibIdentifier contributor entry point

Independent Python Android component identification; LIEF is the primary parser.
Moraine consumes this package and must never be imported here. Current work is
Stage 2; public production release follows measured Stage 3 acceptance.

Read `docs/development/README.md`, `docs/development/roadmap.md`, then the relevant
stage and technical page. `docs/integration.md` is the public contract authority;
`docs/architecture.md` describes implementation. Archived proposals are history.

Preserve public API signatures, existing JSON field meanings and compact CLI
layout. Add result fields with defaults and tolerant nested deserialization.
Fingerprint/database versions are internal and independent of public schema 1.
Never infer exact versions from structural candidates or unknown origin from a
namespace. Static references do not establish runtime execution or exploitability.

Identification and Python assessment APIs never download. Actual OSV assessment
always uses offline mode. Assessment CLI may provision a wholly missing advisory
database unless `--offline`; existing databases require explicit update. Preserve
scanner discovery and graceful fallback. Never execute submitted APK code.

Run `python -m pytest -q` with a supported Python and pinned LIEF; see
`docs/development/testing.md` for native OSV, platform and environment details.
Use meaningful fixtures, record skips and checks actually executed. Do not mark
cross-platform acceptance complete from one platform or historical reports.

Each implementation task updates its technical page, Stage 2 acceptance status,
public guide when contracts change, and relevant tests. Keep one authority per
topic and link to it instead of duplicating contracts. Stage 3 accuracy targets
remain provisional until representative benchmarks justify them.
