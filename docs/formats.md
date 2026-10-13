# Supported Formats

Stage 1 supports:

- APK/ZIP archives containing `classes*.dex` and native `.so` ELF files.
- Standalone DEX files.
- Standalone ELF files.
- Directories containing supported standalone files.

File magic is authoritative. Extensions are used only as hints for ZIP subtypes and member selection. Nested archives are not recursively expanded.

Archive handling rejects unsafe paths, encrypted members, excessive compression ratios, oversized selected members, unsupported compression methods, and symlink entries.

