# Profile Database

Profiles are stored in a local SQLite database with schema version `1` and fingerprint algorithm `dex-shape-v1+elf-identity-v1`.

Core tables:

- `library_family`
- `library_release`
- `dex_shape`
- `elf_identity`
- `db_meta`

`profiles build` imports a trusted local DEX or ELF directly. JAR/AAR profile generation requires explicit local D8 and, when needed, an explicit local `android.jar`. Identification opens the database read-only and refuses incompatible schema or fingerprint versions.

The profile database is a generated artifact. It is separate from the source package and should record provenance and source hashes for trusted references.

