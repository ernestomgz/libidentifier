# Quick start

Install from either [PyPI or GitHub](installation.md), then follow this guide.
Both routes provide the same commands. This page covers [your first scan](#run-your-first-scan),
[first-time setup](#first-time-setup), [saving results](#table-json-and-scripts),
[result meanings](#understand-the-results), [advanced commands](#existing-explicit-commands),
[resource updates](#update-the-resources-you-actually-use) and [troubleshooting](#troubleshooting).

## Run your first scan

In the environment where you installed LibIdentifier:

```powershell
libidentifier scan "app.apk" --vulns
```

Replace `app.apk` with your actual APK path. Quote paths containing spaces.
`--vulnerabilities` is the equivalent long spelling. For library identification
without advisory assessment:

```powershell
libidentifier scan "app.apk"
```

The initial six-family/eight-release catalog is deliberately limited. Until the
official profile assets are published, both PyPI/source installations need a
compatible local database for library identification; see [verification without profiles](installation.md#verify-without-profiles).

## First-time setup

With no `--profiles` and no `LIBIDENTIFIER_PROFILES` environment variable, `scan`
selects managed resources. It lists only missing resources, displays their
location and asks once:

```text
First-time setup

The following resources are missing:
  - Library profiles: official preview snapshot
  - OSV-Scanner: project-supported executable (2.7.0)
  - Maven vulnerability database: current snapshot

Your APK will stay on this computer.
Installed resources will be reused for future scans.

Download and set up these resources? [y/N]:
```

Answer `y` to authorize setup. First setup needs Internet access and can take
longer than later scans because the scanner and advisory archive are downloaded.
Identification without `--vulns` needs only profiles.
The scanner is checksum-verified before execution, checked for the required offline
interface and installed at its pinned version. The selected advisory snapshot is
validated. Actual identification and vulnerability assessment then run locally.

Default managed layout:

```text
Windows: %LOCALAPPDATA%/LibIdentifier/
Linux:   ${XDG_CACHE_HOME:-~/.cache}/libidentifier/
  profiles/profiles.sqlite
  tools/osv-scanner/2.7.0/<platform-specific-executable>
  advisory-db/
```

Set `LIBIDENTIFIER_HOME` to choose another root. Explicit `--osv-scanner` and
`--osv-db` override their paths. The latter's destination is also displayed when
outside the managed root. Automatic scanner downloads support qualified
Windows/Linux x64 builds only; unsupported systems preserve identification and
report advisory assessment unavailable. Explicit compatible native Windows/Linux
scanner overrides retain the existing behavior.

Installed resources are reused. Existing stale/corrupt resources are never
silently replaced. A discovered scanner is reused automatically only if its bytes
match the project pin; explicit scanner overrides use compatibility checking and
an optional caller-provided hash.

## Table, JSON and scripts

Managed scans default to the compact table. Setup/progress/warnings go to stderr,
so JSON remains machine-readable:

```powershell
libidentifier scan app.apk --vulns --format json
libidentifier scan app.apk --vulns --output results.json
libidentifier scan app.apk --format table --output results.txt
libidentifier scan app.apk --vulns --yes --output results.json
libidentifier scan app.apk --vulns --offline
```

`--yes` authorizes missing-resource setup without prompting. Without it,
noninteractive execution never waits for input. `--offline` prohibits all setup
downloads, even with `--yes`. If required profiles are unavailable, the command
stops with an actionable error. If optional vulnerability setup is declined or
fails, identification is retained and the advisory result is explicitly blocked;
that is not a finding of zero vulnerabilities. See [exit codes](integration.md).

## Understand the results

| What you see | Meaning |
|---|---|
| Library identity with confidence/score | Evidence supports a library family; the score is not a calibrated probability. |
| `Unknown [reference candidates]` | The installed version is unknown. Listed references are possibilities, not proven installed versions. |
| Framework presence | Static evidence of a framework, not a complete inventory of its application logic/dependencies. |
| `CONFIRMED` advisory/version match | The identified version matches advisory conditions; application reachability/exploitability is still unproven. |
| `POTENTIAL` | Package-level advisory information with insufficient installed-version evidence to confirm applicability. |
| `NOT ASSESSED` or blocked status | Assessment could not establish a result. An empty findings list does not mean no vulnerabilities. |
| No matched libraries | No supported match within this catalog/coverage; it does not establish that the app contains no libraries. |

`scan` JSON contains `identification` and `vulnerabilities` sections, even when
advisory scanning was not requested. `identify` returns the identification result
itself. Scripts should read status, errors and coverage as well as findings; exit
codes express operational success, not whether an application is safe. The
[public API/JSON contract](integration.md) defines the complete models.

## Existing explicit commands

Explicit profile paths or `LIBIDENTIFIER_PROFILES` retain the existing JSON
default. They do not enter the new managed setup path:

```powershell
libidentifier identify app.apk --profiles profiles.sqlite --format table
libidentifier scan app.apk --profiles profiles.sqlite --format json --output results.json
libidentifier scan app.apk --profiles profiles.sqlite --vulns --osv-scanner /path/to/osv-scanner --osv-db advisory-db --offline
libidentifier inspect app.apk --output inventory.json
```

Legacy advisory discovery remains PATH/working-directory based. Its CLI can
provision a wholly absent advisory database unless `--offline`; it does not install
a scanner. `identify` and `inspect` retain their defaults. Python analysis APIs
always require their configured inputs and never download or prompt. See the
[public contract](integration.md).

## Update the resources you actually use

Package updates, profiles, the scanner and advisory data are independent.
[Updating the installed package](installation.md#use-it-again-update-or-uninstall)
does not refresh cached data. Nothing is silently upgraded during a scan.

The following examples select the managed root, including `LIBIDENTIFIER_HOME`
when set. If you scan with explicit `--profiles` or `--osv-db`, maintain **those
exact paths** instead. Updating a different `./advisory-db` will not repair the
database used by your scan.

### Windows PowerShell

```powershell
$resourceRoot = if ($env:LIBIDENTIFIER_HOME) { $env:LIBIDENTIFIER_HOME } else { Join-Path $env:LOCALAPPDATA 'LibIdentifier' }
libidentifier vulnerabilities update --database "$resourceRoot/advisory-db" --ecosystem Maven
libidentifier vulnerabilities validate --database "$resourceRoot/advisory-db"
```

### Linux shell

```sh
resource_root="${LIBIDENTIFIER_HOME:-${XDG_CACHE_HOME:-$HOME/.cache}/libidentifier}"
libidentifier vulnerabilities update --database "$resource_root/advisory-db" --ecosystem Maven
libidentifier vulnerabilities validate --database "$resource_root/advisory-db"
```

To install newer profiles, obtain a trusted compatible release and keep the old
engine/database pair for rollback. With `resourceRoot`/`resource_root` from above,
use the appropriate command after placing its assets in `download/`:

```powershell
libidentifier profiles install --manifest ./download/profiles-manifest.json --database "$resourceRoot/profiles/profiles.sqlite" --offline --replace
```

```sh
libidentifier profiles install --manifest ./download/profiles-manifest.json --database "$resource_root/profiles/profiles.sqlite" --offline --replace
```

Existing files require `--replace`. Stop other readers before replacing a database.
The default official manifest is pinned; new catalogs are not silently discovered.
See [release assets](releases.md) for compatibility, checksums and acquisition.

An incomplete directory left by a failed advisory download requires explicit
`vulnerabilities update` too. For an air-gapped host, copy a trusted Maven archive
and run `vulnerabilities provision --database <actual-database-path> --archive
Maven-all.zip --fetched-at <actual-retrieval-ISO-timestamp>` with your real values.

Managed scanner version/URLs/hashes are in `cli_resources.py`; new qualified pins
arrive with package releases. Existing scanner files are never silently replaced.
No APK or inventory is sent during provisioning or assessment.

## Troubleshooting

| Problem | Next step |
|---|---|
| Command not found, activation blocked, or pip installation fails | Follow [installation troubleshooting](installation.md#installation-problems) using the same Python environment. |
| Profile download returns 404 | Confirm the official profile release is published. Cloning source does not include it. Use `inspect` or a compatible explicit local database meanwhile. |
| `--offline` cannot find resources | Prepare them first with consent, or transfer trusted offline assets; `--yes` cannot override offline mode. |
| A script refuses first-time setup | Supply `--yes` to authorize downloads, or preinstall resources and use `--offline`. It will not read piped input as consent. |
| Advisory database is missing, corrupt, incomplete or stale | Run explicit `vulnerabilities update` against the actual managed/overridden path above, then retry. Identification is preserved if advisory setup fails. |
| Scanner checksum fails | Do not run the rejected file. Verify its provenance; select a reviewed explicit scanner, or investigate/remove the invalid managed file and repeat setup. Existing files are not automatically repaired. |
| A version is unknown or there are no library matches | Check catalog coverage and evidence. Do not treat reference candidates as installed versions or an empty result as proof of safety. |

## Use the Python API

Install from either route above. Provision a chosen local profile path once,
if it does not already exist (requires the published official release):

```powershell
libidentifier profiles install --database profiles.sqlite
```

Then use that path explicitly from Python:

```python
from pathlib import Path
from libidentifier import identify

result = identify(Path("app.apk"), profiles=Path("profiles.sqlite"))
result.write_json(Path("libraries.json"))
```

Provisioning is separate from analysis. Reuse the existing file on later calls;
analysis never downloads or prompts. For vulnerability options, error handling,
large results and JSON models, use the [public API guide](integration.md).

## Advanced reference generation and results

APK metadata can improve version coverage: known AndroidX `.version` and Maven
`pom.properties` declarations are preserved with their file locations in full
JSON, including `inspect` without profiles. Only code-corroborated versions enter
the library table and exact-version advisory assessment. An embedded declaration
alone is not proof of an installed dependency; unrelated `.version` files are
ignored. See the [metadata contract](integration.md#stage-2-evidence-clusters-and-relationships).

```powershell
libidentifier inspect app.apk --output inventory.json
```

Look for `evidence_records` with `kind: "version_metadata"`: `details.declared`
contains the coordinates/version and `location.member` names the file. This
also makes declarations useful before the reference catalog covers that library;
the compact table continues to summarize code-identified components.

You do not need to build profiles for the quick-start workflow. For custom
libraries, use the [profile database guide](profile-database.md) and
[release guide](releases.md). Older schema-1 databases must be rebuilt, never
relabeled as schema 2.

Full JSON includes evidence, ownership uncertainty, unknown classes, clusters
and typed relationships. All parsed unmatched definitions are returned by default;
`--max-unknown-classes` affects output only and retains total/truncation metadata.
`--no-calls`, `--no-relationships` and `--no-grouping` reduce optional enrichment.
Tables summarize identity/version confidence and distinguish confirmed version
matches, potential package advisories and unassessed components. Static references
do not prove runtime execution, reachability or exploitability.

For a trusted standalone DEX reference whose coordinates/version you know, a
minimal custom-profile workflow is:

```powershell
libidentifier profiles build ./trusted/library.dex --purl pkg:maven/example/library@1.0.0 --database custom.sqlite
libidentifier scan "app.apk" --profiles custom.sqlite --format table
```

The version labels the reference, not a guaranteed installed version in the APK.
JAR/AAR generation requires a local D8 toolchain; it is not required to use the
official profiles.
