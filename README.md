# LibIdentifier

Identify known libraries and frameworks in Android APKs, DEX and native ELF files.
LibIdentifier is an independent Python package and CLI. Analysis runs locally;
your APK is never uploaded. Optional OSV assessment uses a local advisory database
and does not establish reachability or exploitability.

**Preview:** the initial official profile catalog covers six library families and
eight releases. No match does not mean no third-party code. See
[limitations](https://github.com/ernestomgz/libidentifier/blob/main/docs/limitations.md). The PyPI route requires a published package, and managed
library scans require published profiles. Check [installation availability](https://github.com/ernestomgz/libidentifier/blob/main/docs/installation.md#before-you-start)
or use the source route and profile-free inspection below.

## Install from PyPI or GitHub

Python 3.12 is recommended. New to Python environments? Follow the complete
[Windows/Linux installation guide](https://github.com/ernestomgz/libidentifier/blob/main/docs/installation.md), including the
activation-free Windows option.

**Released package from PyPI** (after publication), in your Python environment:

```powershell
python -m pip install "libidentifier==0.2.0rc1"
```

**Reviewed source from GitHub**, in your Python environment:

```powershell
git clone https://github.com/ernestomgz/libidentifier.git
cd libidentifier
python -m pip install .
```

Both methods provide the same command. Check the installation, then scan your
own APK (replace the example path):

```powershell
libidentifier --version
libidentifier scan "app.apk" --vulns
```

The source route installs the code before PyPI publication, but automatic library
scans still require the official profiles to be available. Until then,
`libidentifier inspect "app.apk" --format table` works without profiles; see
[installation verification](https://github.com/ernestomgz/libidentifier/blob/main/docs/installation.md#verify-without-profiles).

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
scan. Continue with [first scan, result meanings, advanced options and resource updates](https://github.com/ernestomgz/libidentifier/blob/main/docs/quickstart.md).

## Python API

Use a local database you explicitly provisioned; the managed CLI cache is not
automatically copied to your working directory. See the
[complete API setup example](https://github.com/ernestomgz/libidentifier/blob/main/docs/quickstart.md#use-the-python-api).

```python
from pathlib import Path
from libidentifier import identify

result = identify(Path("app.apk"), profiles=Path("profiles.sqlite"))
result.write_json(Path("libraries.json"))
```

Analysis APIs never prompt, install tools or download data. Explicit maintenance
APIs are available for consumers that manage their own setup. The authoritative
[API/JSON guide](https://github.com/ernestomgz/libidentifier/blob/main/docs/integration.md) documents models, coverage, errors, SBOM,
profile provisioning and offline advisory assessment. Structural matching normally
identifies families; exact installed versions require stronger evidence.

## Documentation and development

| I want to… | Read |
|---|---|
| Install from pip, GitHub or a source ZIP | [Installation](https://github.com/ernestomgz/libidentifier/blob/main/docs/installation.md) |
| Scan, save output, use offline mode or repair setup | [Usage guide](https://github.com/ernestomgz/libidentifier/blob/main/docs/quickstart.md) |
| Integrate the Python API or consume JSON | [Public contract](https://github.com/ernestomgz/libidentifier/blob/main/docs/integration.md) |
| Build my own reference catalog | [Profile database](https://github.com/ernestomgz/libidentifier/blob/main/docs/profile-database.md) |
| Publish/update official releases | [Maintainer release guide](https://github.com/ernestomgz/libidentifier/blob/main/docs/releases.md) |

Python 3.11+; `lief==0.17.1`. To use a reviewed checkout before publication:

```powershell
python -m pip install -e ".[dev]"
```

Tests generate synthetic DEX/APK/ELF fixtures. JAR/AAR **profile generation** needs
local D8; ordinary scans do not need Java or the Android SDK. See the
[developer index](https://github.com/ernestomgz/libidentifier/blob/main/docs/development/README.md), [release checklist](https://github.com/ernestomgz/libidentifier/blob/main/docs/development/release-readiness.md),
[Stage 2 acceptance](https://github.com/ernestomgz/libidentifier/blob/main/docs/development/stages/stage-2.md) and [contributor instructions](https://github.com/ernestomgz/libidentifier/blob/main/AGENTS.md).
