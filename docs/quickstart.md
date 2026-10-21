# Quick start

## Install and run

After the preview package and official profiles have been published:

```powershell
python -m pip install "libidentifier==0.2.0rc1"
libidentifier scan app.apk --vulnerabilities
```

`--vulns` is an equivalent shorter option. Omit it for library identification only:

```powershell
libidentifier scan app.apk
```

Before publication, clone the reviewed repository and run
`python -m pip install -e ".[dev]"` instead. Release status and maintainer steps
are in [releases](releases.md). The initial six-family/eight-release catalog is
small; it is not a complete inventory of every possible embedded dependency.

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

Answer `y` to authorize setup. Identification without `--vulns` needs only profiles.
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

## Explicit maintenance and updates

Profiles and advisory data are independent. Install a new trusted compatible
profile release explicitly, keeping the old engine/database pair for rollback:

```powershell
libidentifier profiles install --manifest ./download/profiles-manifest.json --database ./profiles.sqlite --offline --replace
libidentifier profiles validate ./profiles.sqlite
```

For the managed database, substitute the actual managed `profiles/profiles.sqlite`
path above. The default official manifest is pinned; new catalogs are not
silently discovered or refreshed. See [release assets](releases.md).

Refresh or repair advisory data explicitly using its actual managed/overridden path:

```powershell
libidentifier vulnerabilities update --database ./advisory-db --ecosystem Maven
libidentifier vulnerabilities validate --database ./advisory-db
```

These example relative paths are explicit destinations, not automatic managed-path
aliases. An incomplete directory left by a failed advisory download also requires
explicit `update`; it is not automatically overwritten on the next scan.
For an air-gapped host, use `vulnerabilities provision --database ./advisory-db
--archive Maven-all.zip --fetched-at <actual-retrieval-ISO-timestamp>`.

A managed scanner is not upgraded automatically. Its version/URLs/hashes are
published in `cli_resources.py`; a new qualified pin arrives with a package
release. Investigate checksum failures rather than executing the rejected file;
select a reviewed explicit scanner or remove the invalid managed file and rerun
setup. No APK or inventory is sent during provisioning or assessment.

## Advanced reference generation and results

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
