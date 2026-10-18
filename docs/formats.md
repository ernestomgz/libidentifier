# Supported Formats

Stage 1 supports:

- APK/ZIP archives containing `classes*.dex` and native `.so` ELF files.
- Standalone DEX files.
- Standalone ELF files.
- Directories containing supported standalone files.

File magic is authoritative. Extensions are used only as hints for ZIP subtypes and member selection. Nested archives are not recursively expanded.

Supplementary DEX tables support standard versions 035/037/038/039/040 with
canonical type/prototype/interface decoding. DEX 041 containers, reverse-endian
and optimized instruction formats are not supported. Supported ordinary invoke
references are bounded static observations, with partial coverage for unsupported
dynamic forms or malformed method instruction streams.

Archive handling rejects unsafe paths, encrypted members, excessive compression ratios, oversized selected members, unsupported compression methods, and symlink entries.

