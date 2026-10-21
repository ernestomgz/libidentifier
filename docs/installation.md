# Installation: PyPI or GitHub

Choose **one** installation method below. Both install the same CLI and Python
API. After installation, continue with [your first scan](quickstart.md).

## Before you start

- Use **Python 3.12** for the simplest tested setup. The package requires Python
  3.11+; the CI matrix covers 3.11, 3.12 and 3.13.
- Automatic OSV-Scanner setup supports **Windows x64 and Linux x64**. Other
  environments are not qualified for automatic scanner installation; see
  [limitations](limitations.md) before relying on them.
- Use an ordinary user account and a virtual environment. Scanning does not
  require Java, Go, D8, Android SDK or manually installed OSV-Scanner.
- Installing from GitHub additionally requires Git. A downloaded source ZIP can
  also be extracted and installed from its directory with `python -m pip install .`.

**Publication status, checked 2026-10-21:** PyPI `0.2.0rc1` and the official
profile snapshot are not published yet. Method A works after package publication;
Method B installs the code now. Managed library scans from either method still
need the official profiles to be published, or an explicitly supplied compatible
local database. Cloning GitHub does not bypass this requirement. Use
[verify without profiles](#verify-without-profiles) to check an installation now.
Maintainer publication steps are in [releases](releases.md).

Both installation methods may download Python dependencies/build tools. A CLI
`--offline` flag does not control pip; fully disconnected installation requires
a separately prepared local wheelhouse as well as local profile/advisory assets.

## Method A: install the released package from PyPI

If you already have an activated Python 3.12 virtual environment, the installation
command is `python -m pip install "libidentifier==0.2.0rc1"`. Otherwise use the
complete sequence for your system below. Run it in a directory where you keep
your analysis work; `.venv` must be a new environment or one intended for this tool.

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install "libidentifier==0.2.0rc1"
libidentifier --version
```

If `py` is unavailable, install Python 3.12 from [python.org](https://www.python.org/downloads/)
or use the full path to an existing Python 3.12 executable. If PowerShell blocks
activation, use the [activation-free commands](#windows-without-activation).

### Linux shell

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install "libidentifier==0.2.0rc1"
libidentifier --version
```

If your Python 3.12 interpreter is named `python3`, substitute that name after
checking `python3 --version`. If the venv module is unavailable, install your
Linux distribution's venv support for that Python version and repeat creation.

Both sequences should report `libidentifier 0.2.0rc1`. No APK or resource download
occurs when checking the version. An exact prerelease version does not require
`--pre`; unpinned upgrade commands may need it to select preview versions.

## Method B: install from GitHub source

Use this to run reviewed source before PyPI publication or to develop changes.
`main` may be newer than a published package. For reproducible work, check out a
reviewed commit/tag before installation rather than relying on a moving branch.

### Windows PowerShell

```powershell
git clone https://github.com/ernestomgz/libidentifier.git
cd libidentifier
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
libidentifier --version
```

### Linux shell

```sh
git clone https://github.com/ernestomgz/libidentifier.git
cd libidentifier
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install .
libidentifier --version
```

Run `pip install .` from the directory containing `pyproject.toml`. It installs
LibIdentifier and its declared Python dependencies; it does not require you to
build a wheel manually. The CLI can then run from any directory while that
environment is active. A normal source install is a copy: reinstall after edits.

For development, use `python -m pip install -e ".[dev]"` instead. Editable installs
use your source edits directly and add pytest. Developer checks are described in
[testing](development/testing.md). Ordinary users do not need the dev extra.

## Windows without activation

Activation only makes the environment's commands available by short names.
If `Activate.ps1` is blocked, keep the existing policy and invoke the executables
directly. After creating `.venv`, choose the installation line for your method:

```powershell
# PyPI (after publication):
.\.venv\Scripts\python.exe -m pip install "libidentifier==0.2.0rc1"

# Or GitHub source, from the cloned repository:
.\.venv\Scripts\python.exe -m pip install .

.\.venv\Scripts\libidentifier.exe --version
.\.venv\Scripts\libidentifier.exe scan "C:\path to\app.apk" --vulns
```

Do not run both installation lines unless you deliberately want to replace one
installation with the other. On Linux you can likewise use `.venv/bin/python`
and `.venv/bin/libidentifier` without activation.

## Verify without profiles

This works before the official profiles are published:

```powershell
libidentifier --help
libidentifier inspect "app.apk" --format table
```

Replace `app.apk` with an existing local APK, quoting paths containing spaces.
`inspect` checks parsing/inventory/framework hints without a reference database;
it does **not** identify libraries by profile matching. To do that before official
publication, obtain/build a trusted compatible local database and use
`libidentifier scan "app.apk" --profiles profiles.sqlite --format table`.
See [custom profiles](profile-database.md) for the advanced generation workflow.

## Use it again, update or uninstall

Open a terminal and reactivate the same environment:

| System | Command, from the directory containing `.venv` |
|---|---|
| Windows PowerShell | `.\.venv\Scripts\Activate.ps1` |
| Linux shell | `. .venv/bin/activate` |

Or use the direct executables above. Run `deactivate` to leave an activated
environment; this does not uninstall anything.

For an already published PyPI preview, `python -m pip install --upgrade --pre
libidentifier` selects the newest available package including prereleases.
For reproducible integrations, install the exact version from its release notes.
For a clean GitHub checkout tracking `main`, use `git pull --ff-only`, then
`python -m pip install .` again (or the editable command). Do not discard local
changes merely to upgrade.

**Package upgrades do not refresh profiles, the managed scanner or advisory data.**
Check compatibility/release notes and use the [explicit resource update steps](quickstart.md#update-the-resources-you-actually-use).

`python -m pip uninstall libidentifier` removes the package from the selected
environment. Cached resources and your scan results remain on disk; uninstalling
never silently deletes them.

## Installation problems

| Symptom | What to do |
|---|---|
| `libidentifier` is not recognized / command not found | Activate the environment where you installed it, or invoke its direct executable above. Confirm with `python -m pip show libidentifier`. Cloning alone does not install the command. |
| PowerShell refuses `Activate.ps1` | Use the activation-free route; no policy change is necessary. |
| Windows opens the Store instead of Python | Use `py -3.12` or the actual installed interpreter path. |
| `No matching distribution found` for this preview | Confirm the package is published, the index is correct and Python is supported. While unpublished, use Method B. |
| No compatible LIEF wheel / pip tries to compile LIEF | Use a supported Python/platform with a published `lief==0.17.1` wheel; Python 3.12 x64 is the recommended tested route. |
| First scan reports a missing/404 profile release | Source installation does not supply the database. Wait for profile publication or supply a trusted local `--profiles` database. |

The virtual-environment approach follows the [Python packaging guide](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/)
and [Python venv documentation](https://docs.python.org/3/library/venv.html).
