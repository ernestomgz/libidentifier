# Quick Start

LibIdentifier identifies compiled Android/Java and native components from a local signature database. APK identification is offline; reference downloads only happen when you explicitly run profile maintenance commands.

## Clone and Install

Windows PowerShell:

```powershell
git clone <repo-url> libidentifier
cd libidentifier
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .[dev]
```

Linux/macOS shell:

```sh
git clone <repo-url> libidentifier
cd libidentifier
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

If your Windows `python.exe` launches the Microsoft Store instead of Python, install Python from python.org or use the `py` launcher.

## Build a Signature Database

The repository includes a small curated catalog at `catalog/references.json`. It is intentionally small and aimed at validation, not broad package coverage.

Fetch the referenced artifacts into a local cache:

```powershell
libidentifier profiles fetch --catalog catalog\references.json --cache reference-artifacts
```

```sh
libidentifier profiles fetch --catalog catalog/references.json --cache reference-artifacts
```

Rebuild the SQLite profile database:

```powershell
libidentifier profiles rebuild --catalog catalog\references.json --cache reference-artifacts --database profiles.sqlite --d8 C:\Android\Sdk\build-tools\36.1.0\d8.bat --android-jar C:\Android\Sdk\platforms\android-35\android.jar
```

```sh
libidentifier profiles rebuild --catalog catalog/references.json --cache reference-artifacts --database profiles.sqlite --d8 "$ANDROID_HOME/build-tools/36.1.0/d8" --android-jar "$ANDROID_HOME/platforms/android-35/android.jar"
```

DEX and ELF references do not need D8. JAR and AAR references do. Rebuilding works offline when all artifacts are already cached:

```sh
libidentifier profiles rebuild --catalog catalog/references.json --cache reference-artifacts --database profiles.sqlite --d8 "$ANDROID_HOME/build-tools/36.1.0/d8" --android-jar "$ANDROID_HOME/platforms/android-35/android.jar" --offline
```

Validate the database:

```sh
libidentifier profiles validate profiles.sqlite
```

## Identify an APK

Table output:

```sh
libidentifier identify samples/ovaa-1.0.0-app-debug.apk --profiles profiles.sqlite --format table
```

JSON output:

```sh
libidentifier identify samples/ovaa-1.0.0-app-debug.apk --profiles profiles.sqlite --format json --output libraries.json
```

You can also set a default profile database:

```sh
export LIBIDENTIFIER_PROFILES="$PWD/profiles.sqlite"
libidentifier identify samples/ovaa-1.0.0-app-debug.apk --format table
```

Windows PowerShell:

```powershell
$env:LIBIDENTIFIER_PROFILES = "$PWD\profiles.sqlite"
libidentifier identify samples\ovaa-1.0.0-app-debug.apk --format table
```

LibIdentifier never downloads references during `identify`.

## Inspect Without Matching

Use `inspect` to parse an input and report coverage, unknown classes and parser errors without a profile database:

```sh
libidentifier inspect samples/ovaa-1.0.0-app-debug.apk --format json --output inspect.json
```

## Python API

```python
from pathlib import Path
from libidentifier import IdentifyOptions, identify, inspect, export_cyclonedx

result = identify(
    Path("samples/ovaa-1.0.0-app-debug.apk"),
    profiles=Path("profiles.sqlite"),
    options=IdentifyOptions(),
)
result.write_json("libraries.json")

summary = inspect(Path("samples/ovaa-1.0.0-app-debug.apk"))
export_cyclonedx(result, "components.cdx.json")
```

CycloneDX export includes only high-confidence exact-version components. Structural DEX matches usually identify a family and leave `version` as `null`.

## Updating the Catalog

Add a reviewed reference to `catalog/references.json` with:

- Versioned `purl`
- `repository` and explicit `url`
- Pinned SHA-256
- License/provenance notes where useful

Then run:

```sh
libidentifier profiles fetch --catalog catalog/references.json --cache reference-artifacts
libidentifier profiles rebuild --catalog catalog/references.json --cache reference-artifacts --database profiles.sqlite --d8 "$ANDROID_HOME/build-tools/36.1.0/d8" --android-jar "$ANDROID_HOME/platforms/android-35/android.jar"
```

Do not add automatic upstream version discovery to the catalog workflow. Catalog entries are curated.

## Common Errors

- `no profile database specified`: pass `--profiles`, set `LIBIDENTIFIER_PROFILES`, or build `profiles.sqlite`.
- `profile database fingerprint algorithm is incompatible`: rebuild the database with the current code and catalog.
- `JAR/AAR profile building requires explicit d8`: pass `--d8` and usually `--android-jar`.
- `downloaded reference hash mismatch`: the downloaded artifact does not match the catalog; do not build a profile until the catalog is reviewed.
- Empty components with many unknown classes: parsing succeeded, but the database did not contain sufficient matching profiles.

## Limitations

- APK scanning is offline and does not perform vulnerability analysis.
- JavaScript, Hermes, Dart AOT and Flutter package dependency identification are not supported.
- DEX fingerprints are conservative and shape-based. R8 shrinking or partial embedded libraries can reduce confidence.
- Exact versions are not guessed from structural similarity. Version remains unknown unless there is a strong exact-version signal.
