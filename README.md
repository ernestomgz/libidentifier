# LibIdentifier

LibIdentifier is a small offline Python package and CLI for identifying known compiled Android and native components from locally built reference profiles. Stage 1 supports APK/ZIP, standalone DEX, standalone ELF, and directories containing those files.

It uses LIEF for DEX and ELF parsing, SQLite for the local profile database, and standard-library archive handling. Scanning does not call the network, Java, D8, OSV-Scanner, Androguard, LibScout, or submitted binaries.

## Install

```powershell
python -m pip install -e .
```

The project targets Python 3.11+ and pins `lief==0.17.1`.

For setup, profile database creation and first scans, see [docs/quickstart.md](docs/quickstart.md).

## CLI

```powershell
libidentifier inspect app.apk --format json --output inspect.json
libidentifier identify app.apk --profiles profiles.sqlite --format json --output libraries.json
libidentifier identify app.apk --profiles profiles.sqlite --format table
libidentifier profiles build library.dex --purl pkg:maven/example/library@1.0.0 --database profiles.sqlite
libidentifier profiles build libfoo.so --purl pkg:generic/foo@1.2.3 --database profiles.sqlite
libidentifier profiles validate profiles.sqlite
libidentifier sbom libraries.json --output components.cdx.json
```

JAR and AAR profile building requires an explicit local D8 executable:

```powershell
libidentifier profiles build library.jar --purl pkg:maven/example/library@1.0.0 --database profiles.sqlite --d8 C:\Android\build-tools\...\d8.bat --android-jar C:\Android\platforms\android-35\android.jar
```

## Python API

```python
from pathlib import Path
from libidentifier import IdentifyOptions, build_profile, identify, inspect, export_cyclonedx

build_profile(
    Path("library.dex"),
    purl="pkg:maven/example/library@1.0.0",
    database=Path("profiles.sqlite"),
)

result = identify(Path("app.apk"), profiles=Path("profiles.sqlite"), options=IdentifyOptions())
result.write_json(Path("libraries.json"))

summary = inspect(Path("app.apk"))
export_cyclonedx(result, Path("components.cdx.json"))
```

## What Stage 1 Identifies

- DEX class-shape fingerprints using `dex-shape-v1`.
- Exact ELF identity using `elf-identity-v1`, primarily whole-file SHA-256.
- Multiple DEX files in one APK.
- Multiple libraries in the same DEX when their reference shapes are strong and non-overlapping.
- Unknown classes and parser errors as explicit output, not silent success.

Structural DEX matches normally identify the library family only. Exact versions are reported only when a strong exact-version signal is available, such as an exact trusted artifact hash or exact ELF identity. Otherwise `version` remains `null` and `version_candidates` lists bounded compatible releases.

## Limitations

- No vulnerability scanning or OSV integration.
- No JavaScript, Hermes, Dart AOT, Flutter package, or npm dependency identification.
- DEX matching is conservative and shape-based; aggressive R8/ProGuard transformations may reduce confidence or prevent matches.
- Stage 1 thresholds are configurable starting points, not calibrated accuracy claims.
- JAR/AAR ingestion is a trusted profile-build operation and depends on user-supplied local D8.

## Test Fixtures

The tests generate small synthetic DEX/APK/ELF binaries during the run. They do not vendor third-party libraries and do not mock LIEF parser objects.

