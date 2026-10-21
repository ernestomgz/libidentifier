# Development documentation

For end-user setup, start with [installation](../installation.md) and
[usage](../quickstart.md). This directory owns contributor/release internals.

Start with the [roadmap](roadmap.md), [release readiness](release-readiness.md),
[Stage 2 checklist](stages/stage-2.md), [testing](testing.md) and [release instructions](../releases.md).
The [public integration contract](../integration.md) owns API/JSON behavior.
Implementation authorities are [architecture](../architecture.md),
[fingerprints](../fingerprints.md), [formats](../formats.md) and
[profile database](../profile-database.md); [limitations](../limitations.md)
defines scope.

Repository layout:

- `src/libidentifier/`: independent runtime package and CLI.
- `tests/`: synthetic fixtures and optional external-asset regressions.
- `catalog/`: trusted reference coordinates and hashes (catalog format schema 1).
- `benchmarks/`: benchmark driver and example corpus.
- `docs/development/validation/`: selected dated Stage 2 evidence and current local validation.
- `docs/development/archive/`: verbatim original proposal, retained as history.
- `test-results/`: ignored generated output; no bundled reference databases.
- `.local/`, `.tools/`, `.development-deps/`, `samples/`: ignored local resources.

Stage pages own acceptance status; the roadmap owns sequence and release
readiness owns the initial distribution checklist. [Decisions](decisions/0001-stage-2.md)
record durable architectural choices. Historical reports identify their original
paths and environments; they do not describe the current resource layout.
