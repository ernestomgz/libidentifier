# Phase A distribution validation — 2026-10-20

## Implemented scope

Preview engine `0.2.0rc1`; single-source version, package metadata, release extra,
portable wheel/sdist checks and a separate Trusted Publishing workflow. New
public `package_profiles`, `install_profiles`, `validate_profiles` maintenance
APIs and CLI packaging/install commands preserve all analysis API signatures,
public JSON schema 1 and internal database schema 2.

Release assets contain portable catalog provenance, compatibility, coverage,
source hashes, compressed/database hashes and sizes. A sanitized backup retains
six families/eight releases and 1,154 fingerprints; the original development
DB is unchanged. It contains no published POM metadata and establishes no new
accuracy claims. Profile installation is explicit, bounded, validates SQLite
integrity and foreign keys and publishes atomically. Existing installations
require explicit replacement. Analysis never invokes acquisition.

## Executed local checks

Windows only, Python 3.12.14, LIEF 0.17.1, pytest 9.1.1. No WSL, new Linux run,
hosted workflow execution or public publication was performed.

- Full suite: **201 passed in 405.02 s**, zero failures/errors/skips. Native OSV
  was required; the six optional APK regressions and local published Maven
  advisory snapshot case ran.
- Final distribution follow-up after the additive local validation API and
  shared CLI default: **17 passed in 8.99 s**. Includes schema/engine/manifest
  rejection, pins, corrupt/truncated content, decompression bounds, inventory
  mismatch, rollback, concurrent destination protection and CLI roundtrip.
- Native assessment was exercised; Windows host-level network isolation was not
  configured. Controlled HTTPS transport fixtures test acquisition behavior,
  not the still-unpublished default GitHub URL.
- Wheel and sdist built, `twine check --strict` passed and content checks excluded
  local resources, databases and consumer-specific files. A clean local private
  venv installed regular wheels from a local wheelhouse with no source import.
  Installed CLI acquired the local release offline, validated it and identified
  Gson, OkHttp and Retrofit in the existing OVAA test APK without parser errors.
- A separate offline `pip wheel` rebuild from the final sdist passed content
  checks. An initial sandboxed backend stalled and was stopped; the host retry
  passed. Installed Python modules match final source bytes, including the
  public validation helper.
- Both workflow files passed actionlint. Current Markdown file links and
  `git diff --check` passed. Historical original proposal remains unmodified.

Commands used a working explicit bundled interpreter and project-local
`.development-deps`, with `PYTHONDONTWRITEBYTECODE=1`:

```powershell
$env:PYTHONPATH = "$PWD/src;$PWD/.development-deps"
$env:LIBIDENTIFIER_TEST_OSV = "$PWD/.tools/osv-scanner_windows_amd64.exe"
$env:LIBIDENTIFIER_TEST_PROFILES = "$PWD/.local/profiles/profiles.sqlite"
$env:LIBIDENTIFIER_REQUIRE_OSV = "1"
python -m pytest -q -ra -p no:cacheprovider --basetemp .pytest_tmp/phase-a --junitxml=test-results/phase-a-windows.xml
python -m pytest -q -ra tests/test_profile_distribution.py -p no:cacheprovider --basetemp .pytest_tmp/distribution-accepted --junitxml=test-results/phase-a-distribution.xml
python -m build --no-isolation
python -m twine check --strict dist/*.whl dist/*.tar.gz
python tools/check_distributions.py dist
```

## Remaining manual gates

[Release guide](../../releases.md) owns the exact account/publisher fields, tags,
upload files and steps. Confirm PyPI name ownership, configure environments and
Trusted Publishers, push commits/tags, pass the hosted matrix, publish the engine
and profile assets, then qualify installation from their real public locations.
The first preview must remain explicitly limited; production accuracy and catalog
expansion are Stage 3 work. Application initialization and scanner provisioning
belong to consuming repositories.
