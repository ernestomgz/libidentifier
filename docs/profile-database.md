# Profile Database

Profiles use internal SQLite schema **2**, with bundle compatibility identifier
`dex-shape-v2-canonical+elf-identity-v1`. Public identification JSON stays schema 1.

Core tables:

- `library_family`
- `library_release`
- `reference_artifact`: original SHA-256, format, provenance, source release
- `build_variant`: artifact, output hash, compiler/configuration, primary selection
- `fingerprint`: algorithm/digest values, deduplicated independently of sources
- `fingerprint_occurrence`: variant, reference locator and multiplicity
- `published_metadata`: hashed original POM and interpreted declarations
- `elf_identity`
- `db_meta`

`dex_class` and `dex_shape` are matching views over the primary DEX variant.
Stage 2 retains all variants but uses the first imported DEX variant per release
for structural scoring; it does not union variant evidence or inflate confidence.
ELF hashes remain individually available. Stage 3 can improve variant selection
without changing external models. Release IDs no longer depend on artifact bytes.

`profiles build` imports a trusted local DEX or ELF directly. JAR/AAR profile generation requires explicit local D8 and, when needed, an explicit local `android.jar`. Identification opens the database read-only and refuses incompatible schema or fingerprint versions.

The profile database is a generated artifact. It is separate from the source package and should record provenance and source hashes for trusted references.

Schema-1 databases and old fingerprint bundles are rejected, never silently
migrated. Keep the old engine/database pair for rollback. Explicitly rebuild a
new destination from trusted cached artifacts, then deploy the new pair:

```sh
libidentifier profiles rebuild --catalog catalog/references.json --cache reference-artifacts --database profiles-v2.sqlite --d8 /local/d8 --android-jar /local/android.jar --offline
libidentifier profiles validate profiles-v2.sqlite
```

Canonical class types/interfaces changed, so an old database cannot safely be
relabeled. Existing `build_profile` and catalog fetch/rebuild calls remain valid.
Catalogs may contain multiple artifact hashes for one PURL; new caches use hash
directories, with verified legacy flat-cache reuse. Optional paired `pom_url` and
`pom_sha256` fetch a pinned POM during explicit maintenance. A sibling `.pom` is
read during local reference building; no dependency resolution/network occurs.

POM support: direct dependencies, local bounded property substitution, raw
expressions, scope/optionality/type/classifier/exclusions. Unresolved values stay
null with the original declaration retained. Parent/BOM/managed/profile context
is preserved as XML and limitations, not invented effective dependencies.
Missing metadata remains distinguishable from a POM declaring zero dependencies.

D8 configuration records executable hash, reported version (or explicit unavailable status), Android API artifact
hash and output hash. Multidex D8 output is rejected explicitly instead of silently
dropping secondary DEX files. R8 generation is Stage 3. Canonical reproducibility
excludes local paths/timestamps; byte-identical SQLite distribution is not claimed.

