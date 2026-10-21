# Managed CLI validation — 2026-10-21

## Scope

Managed `scan` without an explicit/environment profile path obtains one consent
for missing profiles and optional pinned scanner/advisory data, then uses offline
analysis. `--yes`, `--offline`, per-user cache reuse and `--vulns` are supported.
Managed output defaults to a compact table; explicit profiles retain JSON.
Explicit format/output flags remain authoritative. Progress/consent use stderr.
Python analysis APIs, public models and existing explicit resource paths are
unchanged. No existing resource is automatically upgraded or repaired.

`cli_resources.py` owns the Windows/Linux x64 OSV 2.7.0 publisher URLs and hashes
used both by managed installation and native CI. Hash verification precedes any
execution. Other platforms do not silently select a foreign architecture.
Required profile setup failures stop; optional failures retain identification
with a blocked/unassessed advisory report. Setup refusal/offline mode cannot be
bypassed by a later assessment helper.

## Executed local evidence

Windows only; Python 3.12.14, LIEF 0.17.1, pytest 9.1.1 and native OSV 2.7.0.
**216 tests passed in 171.81 seconds, with zero failures, errors or skips.**
The suite includes 15 managed-setup cases, native scanner copy/check/execute,
consent/noninteractive/yes/offline, explicit/environment defaults, file output,
corrupt resource preservation, API nonprovisioning, all existing profile/OSV
regressions and the six available APK regressions.

```powershell
$env:PYTHONPATH = "$PWD/src;$PWD/.development-deps"
$env:PYTHONDONTWRITEBYTECODE = "1"
$env:LIBIDENTIFIER_TEST_OSV = "$PWD/.tools/osv-scanner_windows_amd64.exe"
$env:LIBIDENTIFIER_TEST_PROFILES = "$PWD/.local/profiles/profiles.sqlite"
$env:LIBIDENTIFIER_REQUIRE_OSV = "1"
python -m pytest -q -ra -p no:cacheprovider --basetemp .pytest_tmp/managed-final --junitxml=test-results/managed-windows.xml
```

A regular wheel was installed in the private `.local/release-qa` environment
without a source import path. All installed Python sources matched the checkout.
Using an isolated `LIBIDENTIFIER_HOME`, the installed executable demonstrated:

- No prompt wait or download on a noninteractive first run without consent.
- Download-free local profile import, followed by table-default managed scan.
- `--vulns --offline`, native scanner override and the existing published Maven
  snapshot producing JSON in the requested file and no stdout contamination.
- Gson, OkHttp and Retrofit identified in the existing OVAA APK without parser
  errors. This is integration qualification, not complete accuracy ground truth.

The wheel and sdist built and passed strict twine checks and content checks,
including the new CLI modules and exclusion of local resources. Both workflows
passed actionlint; current Markdown file links and Python syntax passed.

No WSL or new Linux tests were executed locally. Native offline invocation and
controlled download fixtures do not establish Windows host-level egress isolation.
Real profile acquisition from the public default URL remains pending until the
maintainer uploads the official release assets. See the [release checklist](../release-readiness.md)
and [publication instructions](../../releases.md). Hosted CI for the new commit
is separate evidence; do not infer its completion from this local run.

JUnit, installed CLI transcript/JSON and final artifact hashes are retained in
ignored `test-results/`; publication artifacts are in ignored `dist/`.
