# LibIdentifier

Identify known libraries and frameworks in Android APKs, DEX and native ELF files.
LibIdentifier is an independent Python package and CLI. Analysis runs locally;
your APK is never uploaded. Optional OSV assessment uses a local advisory database
and does not establish reachability or exploitability.

**Preview:** the initial official profile catalog covers six library families and
eight releases. No match does not mean no third-party code. See
[limitations](docs/limitations.md). Package/profile publication is pending; the
commands below work after the maintainer completes [publication](docs/releases.md).

## Install and scan

```powershell
python -m pip install "libidentifier==0.2.0rc1"
libidentifier scan app.apk --vulns
```

`--vulnerabilities` is the long spelling of `--vulns`. For library identification
without advisory assessment:

```powershell
libidentifier scan app.apk
```

On first use, the CLI lists missing resources, shows their destination and asks
`Download and set up these resources? [y/N]`. Accept to install the official
profiles and, when requested, the project-qualified OSV-Scanner and Maven advisory
data. Later scans reuse them. Existing resources are never silently updated.
Without vulnerability assessment, only profiles are needed.

Managed scans print the compact table. Setup messages go to stderr. Windows
resources live under `%LOCALAPPDATA%/LibIdentifier`; Linux uses
`${XDG_CACHE_HOME:-~/.cache}/libidentifier`. `LIBIDENTIFIER_HOME` overrides the
managed root. Automatic scanner installation currently supports Windows/Linux
x64 and uses project-pinned URLs and SHA-256 values, never GitHub's latest tag.

## Useful options

```powershell
# Authorize missing-resource setup in scripts; never prompts.
libidentifier scan app.apk --vulns --yes

# Reuse installed resources without any downloads.
libidentifier scan app.apk --vulns --offline

# JSON instead of a table; --output alone also selects JSON in managed mode.
libidentifier scan app.apk --vulns --output results.json

# Existing explicit usage retains its JSON default and resource overrides.
libidentifier scan app.apk --profiles custom.sqlite --format json --output results.json
libidentifier identify app.apk --profiles custom.sqlite --format table
```

A noninteractive first run needs `--yes` or preinstalled resources. `--offline`
overrides `--yes`. If optional vulnerability setup fails, identification is
preserved with an explicit unassessed result. Required profile failures stop the
scan. Full setup, updates and troubleshooting: [quick start](docs/quickstart.md).

## Python API

```python
from pathlib import Path
from libidentifier import identify

result = identify(Path("app.apk"), profiles=Path("profiles.sqlite"))
result.write_json(Path("libraries.json"))
```

Analysis APIs never prompt, install tools or download data. Explicit maintenance
APIs are available for consumers that manage their own setup. The authoritative
[API/JSON guide](docs/integration.md) documents models, coverage, errors, SBOM,
profile provisioning and offline advisory assessment. Structural matching normally
identifies families; exact installed versions require stronger evidence.

## Development

Python 3.11+; `lief==0.17.1`. To use a reviewed checkout before publication:

```powershell
python -m pip install -e ".[dev]"
```

Tests generate synthetic DEX/APK/ELF fixtures. JAR/AAR **profile generation** needs
local D8; ordinary scans do not need Java or the Android SDK. See the
[developer index](docs/development/README.md), [release checklist](docs/development/release-readiness.md),
[Stage 2 acceptance](docs/development/stages/stage-2.md) and [contributor instructions](AGENTS.md).
