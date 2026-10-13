# Fingerprints

## dex-shape-v1

`dex-shape-v1` hashes normalized class structure. It includes access categories, field and method counts, normalized field types, method parameter and return type categories, method flags, superclass category, and interface categories.

Application and library-specific object type names are normalized to `OBJECT`; stable platform descriptors such as `Ljava/lang/Object;` and Android/JDK descriptors are preserved. Method and field names are not part of the digest, except constructors are categorized specially.

This is a conservative structural signal. It is not equivalent to LibScout and is not robust against all R8 transformations, code removal, inlining, or class merging.

## elf-identity-v1

`elf-identity-v1` stores exact ELF SHA-256, ABI, SONAME when available, build-id when available, and a symbol digest when symbols are present. Exact SHA-256 is the only Stage 1 exact-version ELF signal.

## Research Attribution

The profile-generation and matching philosophy is influenced by LibScout, while the implementation here is original and uses LIEF parser APIs directly. No LibScout or Androguard source files are copied.

