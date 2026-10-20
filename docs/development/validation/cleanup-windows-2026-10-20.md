# Repository cleanup validation — 2026-10-20

## Scope and outcome

Stage 2 remains complete. Prioritize [Phase A distribution](../release-readiness.md)
with a small validated profile snapshot before catalog expansion. No PyPI package
or official profile asset was published by this cleanup.

- Removed obsolete schema-1 sample databases, generated JSON/text inventories,
  superseded ad hoc validation scripts, copied checkouts, historical test venvs,
  pytest/build caches and consumer integration staging.
- Preserved selected dated Stage 2 evidence here; the original specification
  remains byte-for-byte identical to its Git version in the archive. Removed its
  redundant root pointer.
- Moved the current development profile database to ignored
  `.local/profiles/profiles.sqlite`; preserved its historical build manifest,
  trusted reference cache and optional advisory snapshot under `.local/`.
- Preserved native tools under ignored `.tools/`, active local dependencies under
  `.development-deps/`, and the existing optional APK test inputs under `samples/`.
- Retained only the ignored root `moraine-integration.md` consumer note; no adapter
  implementation remains in this repository. Consuming application files were
  not modified.
- Renamed the canonical internal DEX module to `fingerprint/dex_v2.py` and updated
  all runtime/test imports. Public API signatures, public JSON schema 1, database
  schema 2 and fingerprint values are unchanged. Catalog/build-manifest schema 1
  is independent and was not relabeled.

## Executed checks

Local Windows only: Python 3.12.14, pytest 9.1.1, LIEF 0.17.1, native OSV-Scanner.
No WSL, new Linux test, hosted CI dispatch or remote publication was performed.

```powershell
$env:PYTHONPATH = "$PWD/src;$PWD/.development-deps"
$env:LIBIDENTIFIER_TEST_OSV = "$PWD/.tools/osv-scanner_windows_amd64.exe"
$env:LIBIDENTIFIER_REQUIRE_OSV = "1"
$env:LIBIDENTIFIER_TEST_PROFILES = "$PWD/.local/profiles/profiles.sqlite"
$env:PYTHONDONTWRITEBYTECODE = "1"
New-Item -ItemType Directory -Force .pytest_tmp
python -m pytest -q -ra -p no:cacheprovider --basetemp .pytest_tmp/cleanup-windows --junitxml=test-results/cleanup-windows.xml
```

The working explicit bundled interpreter was used instead of a Store alias.
**184 passed in 161.83 seconds; zero failures, errors or skips.** This includes
native advisory assessment, the published local Maven snapshot, six real-APK
regressions and schema-2 reference handling. Windows OS network isolation was
not established; offline behavior tests/native assessment are not a new claim
of host-level egress isolation.

The wheel built offline with `pip wheel . --no-build-isolation --no-deps --no-index`.
Its archive contains `dex_v2.py` and no old DEX module, consumer files or SQLite
database. Extracted-wheel CLI profile validation passed. SQLite integrity passed;
profile SHA-256 remains
`cded7aa798d8466e1b31f19ce629e2be25c427e2f9eb7d69ba447034fdec406d`.
All source/test/benchmark Python ASTs parsed, current Markdown file links resolved
and `git diff --check` passed. Dated verbatim archive links are historical.

Exact local environment/tool/wheel hashes and JUnit results are retained in
ignored `test-results/cleanup-environment.json` and `test-results/cleanup-windows.xml`.
Test scratch directories and temporary extracted package/build output were removed
following verification. The working wheel is retained under `test-results/package/`.
