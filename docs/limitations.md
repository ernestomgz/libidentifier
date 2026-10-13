# Limitations

- No vulnerability scanning.
- No OSV, Maven, Gradle, npm, or remote lookup.
- No JavaScript, Hermes, Dart AOT, or Flutter package inventory.
- DEX shape matching can miss heavily optimized or obfuscated libraries.
- Structural DEX matches do not prove an exact release version in Stage 1.
- Generic class shapes can be ambiguous; weak evidence is kept out of the component list.
- LIEF is native code; hostile malformed binaries may still be best handled by invoking the CLI in a managed worker process from a host application.

