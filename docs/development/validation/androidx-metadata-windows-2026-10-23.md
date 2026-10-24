# AndroidX metadata validation — 2026-10-23

Native Windows; Python 3.12.14, LIEF 0.17.1, project-qualified OSV 2.7.0.
No WSL or new Linux run. Public signatures, JSON schema 1, compact tables and
profile database/fingerprint versions are unchanged; no profile rebuild is needed.

Executed focused checks:

- `python -m pytest -q tests/test_androidx_versions.py tests/test_stage2.py`:
  39 passed before the native-advisory follow-up was added.
- Final `python -m pytest -q tests/test_androidx_versions.py`: 15 passed,
  including actual native offline assessment, with no skips.
- Existing OVAA APK ZIP-resource smoke: 31 of 32 candidate AndroidX files parsed.
  The remaining file contained Gradle task/property text rather than a version
  and was correctly rejected. This checked metadata parsing, not exact-version
  accuracy or code corroboration on a benchmark corpus.
- Local current Markdown file targets and `git diff --check` passed.

The first full-suite attempt and a separate full `inspect` smoke were interrupted
without a completion result. They are not acceptance evidence. The completed
ZIP-resource smoke above does not claim complete APK inspection.

Full-suite retry: **230 passed in 363.33 seconds, zero failures/errors/skips**.
Command: `python -m pytest -q -ra --basetemp .pytest_tmp/androidx-full-retry
--junitxml test-results/androidx-windows.xml`, with native
`LIBIDENTIFIER_TEST_OSV`, `LIBIDENTIFIER_REQUIRE_OSV=1` and the existing schema-2
`LIBIDENTIFIER_TEST_PROFILES` configured. Source imports used the local runtime
package and isolated development dependencies. This was a local Windows source
run, not installed-wheel or newly executed hosted CI qualification.

Negative controls include unrelated filename conventions, invalid/multiline/
oversized contents, absent code, wrong coordinates, unsupported reference version,
weak descriptors, cross-container declarations, conflicting Maven/AndroidX
versions and duplicate ZIP names. Native assessment proves the synthetic
corroborated version can match an advisory while an unrepresented declared
version remains package-only potential; metadata-only inventory has no findings.

Generated JUnit is retained in ignored `test-results/androidx-windows.xml`.
These fixtures establish functional guardrails, not Stage 3 precision/coverage
thresholds or independent OS network isolation. Broader AndroidX reference and
build-ground-truth benchmark coverage remains future work.
