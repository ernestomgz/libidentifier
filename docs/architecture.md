# Architecture

LibIdentifier is API-first. The CLI delegates to the same `identify()`, `inspect()`, `build_profile()`, and `export_cyclonedx()` functions exposed from `libidentifier`.

The scan pipeline is:

1. Detect top-level format from magic bytes.
2. Traverse ZIP/APK members with bounded, safe reads.
3. Extract DEX class features and ELF identity features with LIEF.
4. Convert features to deterministic fingerprints.
5. Query a local read-only SQLite profile database.
6. Score candidates conservatively and emit deterministic JSON.

The package has no Moraine dependency. Moraine or another host application owns vulnerability analysis, application ownership decisions, and OSV-Scanner execution.

