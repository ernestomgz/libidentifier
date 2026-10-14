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

Linux shell:

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

Both `inspect` and `identify` report framework presence separately from profile-backed libraries. Hints preserve evidence locations and confidence; Flutter, React Native, Compose, Cordova, Unity and Xamarin / .NET MAUI detection does not infer framework versions or analyze unsupported application payloads. Table output includes a concise framework section.

See [the public integration guide](integration.md) for complete API examples, result fields, failure handling and the compatibility policy Stage 3 must preserve.

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

Table output labels these as `Unknown [reference candidates]`. Candidate reference versions are not confirmed installed versions. `family_purl` preserves a versionless package identity for downstream advisory discovery, while coverage reports unmatched-class totals and truncation. The filtered SBOM declares incomplete inventory; an empty SBOM does not mean the APK has no dependencies.

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

- Identification is offline. Optional local advisory assessment uses OSV-Scanner only for generated dependencies, without sending APK contents or accessing the network.
- JavaScript, Hermes, Dart AOT and Flutter package dependency identification are not supported.
- DEX fingerprints are conservative and shape-based. R8 shrinking or partial embedded libraries can reduce confidence.
- Exact versions are not guessed from structural similarity. Version remains unknown unless there is a strong exact-version signal.

## Complete Output and Optional Advisory Assessment

All parsed unmatched definitions are returned by default. To request a deliberately capped JSON view, add `--max-unknown-classes 1000`; original totals and truncation remain visible. Matching and extraction are unaffected. Prefer `--output` or `result.write_json()` for large results; serialization streams without a full extra dictionary/string.

Install a native OSV-Scanner v2.7.0 executable from the [official release](https://github.com/google/osv-scanner/releases/tag/v2.7.0) on PATH or in your working directory. Then:

```sh
libidentifier identify samples/ovaa-1.0.0-app-debug.apk --profiles profiles.sqlite --vulnerabilities --format table
```

The CLI finds the scanner automatically and selects `./advisory-db` if present, otherwise a persistent user cache. A missing database is downloaded and validated before strictly offline assessment. Add `--offline` to prohibit downloads. `--osv-scanner <path>` and `--osv-db <directory>` override discovery. Missing scanners give a warning and complete identification; JSON reports `scanner_missing` and `not_assessed`, never a clean vulnerability result. Existing stale/corrupt databases require an explicit update:

The original release filenames work without renaming: `osv-scanner_windows_amd64.exe`, `osv-scanner_windows_arm64.exe`, `osv-scanner_linux_amd64`, and `osv-scanner_linux_arm64`, on their respective platforms. Conventional `osv-scanner` / `osv-scanner.exe` names also work. Darwin binaries are unsupported and `osv-scanner_SHA256SUMS` is not an executable. Missing-scanner warnings link to [downloads](https://github.com/google/osv-scanner/releases).

```sh
libidentifier vulnerabilities update --database advisory-db --ecosystem Maven
libidentifier vulnerabilities validate --database advisory-db
libidentifier scan samples/ovaa-1.0.0-app-debug.apk --profiles profiles.sqlite --vulnerabilities --osv-scanner /opt/tools/osv-scanner --osv-db advisory-db --format table
```

On Windows, substitute your `osv-scanner.exe` path if using an override. Only setup of an absent database or explicit `update` downloads the fixed Maven archive; OSV assessment is always offline. Python scanning APIs never download. Air-gapped users can use `vulnerabilities provision --database advisory-db --archive Maven-all.zip --fetched-at <actual-retrieval-ISO-timestamp>` and assess with `--offline`.

High-confidence exact versions can produce affected-version matches. Unknown versions can produce potential package advisories but never confirmed applicability. Advisory attribution requires a valid identity score of at least 0.75 by default, including qualifying medium-confidence identities; use `--min-identity-score 0.85` to change it, or Python `VulnerabilityOptions(min_identity_score=0.85, scanner=..., database=...)`. Unsupported ecosystems remain unassessed. Existing APK samples do not have reliable installed library versions; expect potential or unassessed results. Findings do not prove reachability or exploitability. Full commands, public models, Python examples and error handling are in [integration.md](integration.md).

Tables show library names, identity labels with scores, unknown versions with reference candidates, and advisory counts when requested. The vulnerability section distinguishes confirmed and potential matches and preserves affected-range boundaries from OSV; unavailable version ranges have no `Affected:` message. Columns wrap in narrow terminals, with stacked fields on very narrow screens. In OVAA, Retrofit's score of 0.837 qualifies at the default threshold despite its medium identity label.
