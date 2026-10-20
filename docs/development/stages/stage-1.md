# Stage 1 baseline

Implemented foundation: bounded APK/DEX/ELF/directory inspection, actual DEX
definitions, normalized structural hashes, weighted/partial matching, exact ELF
matching, SQLite references, catalog fetch/rebuild, local D8 JAR/AAR conversion,
version candidates, framework indicators, evidence/unknown inventories, API/CLI,
JSON and conservative CycloneDX export. See technical pages for current details.

Tests cover synthetic inputs and optional six real APK samples. Selected historical
evidence is retained under `docs/development/validation/`.
These demonstrate a foundation, not representative production precision/recall.
Native parser memory/time isolation remains a host responsibility.
