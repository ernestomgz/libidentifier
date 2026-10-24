# Supported Formats

Stage 1 supports:

- APK/ZIP archives containing `classes*.dex` and native `.so` ELF files.
- Standalone DEX files.
- Standalone ELF files.
- Directories containing supported standalone files.

File magic is authoritative. Extensions are used only as hints for ZIP subtypes and member selection. Nested archives are not recursively expanded.

Known version metadata is selected separately: canonical Maven `pom.properties`
and `META-INF/androidx.<group>_<artifact>.version`. Unrelated `.version` files are
not classified as AndroidX dependencies. See the [public metadata contract](integration.md#stage-2-evidence-clusters-and-relationships)
for declaration evidence and code corroboration. AndroidX files are limited to
4 KiB and one literal version token of at most 256 characters; malformed known
files report partial metadata coverage without inventing a version. ZIP member
limits, duplicate-name rejection and safe-path rules still apply.

The convention is documented by AndroidX's own
[version-file build task](https://android.googlesource.com/platform/frameworks/support/+/50776d9f9558466e4e002cae381c292c4ae8a62f/buildSrc/private/src/main/kotlin/androidx/build/VersionFileWriterTask.kt).

Supplementary DEX tables support standard versions 035/037/038/039/040 with
canonical type/prototype/interface decoding. DEX 041 containers, reverse-endian
and optimized instruction formats are not supported. Supported ordinary invoke
references are bounded static observations, with partial coverage for unsupported
dynamic forms or malformed method instruction streams.

Archive handling rejects unsafe paths, encrypted members, excessive compression ratios, oversized selected members, unsupported compression methods, and symlink entries.

