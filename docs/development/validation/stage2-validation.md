# Stage 2 development validation

Checks began 2026-10-16; finalization 2026-10-18 (Europe/Madrid).
Development foundations, not production accuracy
qualification. The [Stage 2 checklist](../stages/stage-2.md) owns
milestone status; this report records executed evidence.

## Implementation

Canonical DEX descriptors/interfaces, actual method/field definitions, ambiguous
location-aware ownership, additive evidence/analysis models, bounded ordinary
invocations, structural/component relationships, complete unattributed clusters,
direct POM interpretation and attributable embedded Maven version metadata.
Public calls/schema meanings and compact CLI remain compatible. OSV discovery,
missing-database provisioning, offline prohibition, nonrefresh of existing data
and graceful fallback are retained. No Moraine integration or R8 generation.

Reference schema 2 separates releases/artifacts/build variants/fingerprints/
occurrences. Explicit offline rebuild of all eight cached catalog references
succeeded through real JAR/AAR D8 conversion. Recorded compiler:
`D8 9.0.3-dev`, build `750a21b4f4281b1f453b649e0b84f1ba9c04f4fc`.
Old databases were preserved; new qualification data is under ignored
`test-results/tmp/stage2/final-profiles.sqlite`. Synthetic canonical rebuilds,
variant noninflation, pinned POM caches and incompatible-version refusal are tested.

## Executed checks

- Baseline before implementation: 159 passed on Windows.
- First expanded suites: 178 passed on Windows (484.75 s) and WSL Linux (566.84 s).
- Broad final regression sweeps: **183 passed on Windows** in 363.01 s;
  **182 passed on Linux** in 566.61 s. Counts differ because the existing scanner
  compatibility fixture finds one additional installed binary on Windows.
  The last cross-family guard fixture was added after collection; final targeted
  checks below cover that guard and all Stage 2 cases against the finished source.
- Native OSV/offline/Stage 2 integration under Linux `unshare -n`: **57 passed**
  in 308.86 s. Fixtures simulate permitted provisioning; actual OSV executes
  without an internet route.
- Final safety/model/metadata follow-up including native affected/unaffected OSV:
  **26 passed on Windows** in 9.88 s and **26 passed on Linux without networking**
  in 27.62 s. This includes cross-APK metadata attribution, inspection-versus-
  identification status, output-cap independence and identical reference bytes
  assigned to competing DEX families never establishing exact versions.
- The final collected inventory is 184 Windows cases / 183 Linux cases. All are
  covered by the broad sweeps plus final targeted follow-up; no required OSV test
  was skipped. An earlier Windows run spanned a session pause; its elapsed time
  is excluded from performance discussion.
- Documentation links resolved, original specification archive matches Git blob
  byte-for-byte, and `git diff --check` passed.
  Final staged whitespace checks exclude the verbatim archive, whose inherited
  Markdown hard line breaks are preserved; its staged blob matches the original.
- Raw class-definition counts independently read from all six APKs' DEX headers
  exactly equal the extracted inventory counts in the pilot; Python source syntax
  checks also passed.

Earlier broad-suite runtimes: Windows Python 3.12.14 and WSL Ubuntu Python
3.14.4, both with LIEF 0.17.1 and qualified native OSV 2.7.0 amd64.

### Installed-package compatibility follow-up, 2026-10-18

[Machine-readable matrix evidence](stage2-matrix.json) records runtime/tool
provenance, source digest and JUnit suite results. Each environment used an
isolated Python installation and a regular built-package install with
`PYTHONPATH` unset. All 40 installed Python modules matched the working source
byte for byte. The installed `libidentifier --help` command passed in all six
environments.

| Python | Windows regression | WSL Linux regression | Linux without networking |
|---|---:|---:|---:|
| 3.11.17 | 176 passed | 175 passed | 58 passed |
| 3.12.15 | 176 passed | 175 passed | 58 passed |
| 3.13.16 | 176 passed | 175 passed | 58 passed |

There were no failures, errors or skips in the selected tests. Each regression
run explicitly deselected eight optional external-asset cases: the six real-APK
regressions, Flutter sample inspection and the published Maven advisory snapshot
check. Those cases were exercised in the earlier broad sweeps. The one-case
Windows/Linux difference remains the additional installed scanner fixture.
Each Linux no-egress run used `unshare -n` for the offline/CLI/Stage 2 subset and
deselected only the published advisory snapshot case. The machine-readable
record includes the exact selections. All runs required native OSV integration;
timings reflect concurrent qualification, not performance benchmarks.

The CI workflow now installs a regular package, checks its console entry point,
records Python/LIEF/pytest/scanner/revision provenance and uploads JUnit results
with skip reasons for every environment. It supports manual dispatch as well as
push/pull-request triggers. Its embedded Python steps compile. Downloaded tools
and generated reports are ignored. A transient Linux runtime installation rename
failure succeeded on retry; Windows console launchers required host execution
because sandbox path resolution was restricted.

ARM hardware, bare-metal Linux and hosted GitHub runners remain unqualified.
No hosted CI run was triggered for this uncommitted checkout. The completed local
matrix is separate evidence from the defined hosted Windows/Linux matrix.

### Workflow expression correction after first push

GitHub rejected the first published workflow before any matrix jobs ran:
`runner.os` was used in job-level `env`, where the runner context is unavailable.
The scanner suffix now uses `matrix.os == 'windows-latest'`, preserving `.exe`
on Windows and no suffix on Linux. This follows GitHub's
[context availability rules](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#context-availability).

The official checksum-verified actionlint 1.7.12 binary reproduced the original
context error and accepted the corrected workflow with no diagnostics. This is
workflow validation, not a hosted regression run. No Python implementation changed;
the recorded local matrix remains applicable. Hosted execution awaits the fix
being pushed. Workflow maintenance instructions now require actionlint.

### Scanner bootstrap and action-runtime correction

The public job API for [run 39150638487](https://github.com/ernestomgz/libidentifier/actions/runs/39150638487)
shows all six environments failed scanner provisioning, with runtime recording
and regression tests skipped. The upload step succeeded but had no reports to
upload. Detailed job logs required authenticated access; locally, executing the
old bootstrap reproduced `ImportError` for the removed `runner.APPROVED_HASHES`.

The bootstrap now owns its two OSV 2.7.0 qualification hashes, verified against
the publisher's release checksums. This does not restore a runtime allowlist.
It records download/checksum failures before raising them. Basic environment
evidence is created after Python setup, before package installation. Checkout,
setup-python and upload-artifact now use v7, whose action metadata targets Node
24; the Node 20 and punycode messages were warnings, not the provisioning failure.

Actionlint 1.7.12 accepts the updated workflow. The exact embedded bootstrap and
runtime-recording programs executed successfully on Windows and Linux Python
3.12 with the existing verified native OSV 2.7.0 binaries. Controlled local
download fixtures also exercised network errors and checksum mismatch on both
platforms: each failed and preserved its diagnostic JSON. These checks used
cached binary bytes in place of network downloads; official URLs and checksums
were independently checked against release metadata. Full hosted qualification
still requires pushing this correction and completing the matrix.

### Fresh-checkout temporary-directory correction

The supplied run #3 log reached pytest but failed fixture setup because the
ignored `.pytest_tmp` parent was absent. Pytest's explicit nested basetemp paths
do not create that parent. Existing local directories had masked this condition.
Workflow initialization now creates `.pytest_tmp` before the regression and
offline commands; application code and test selections are unchanged.

Tracked-files-only Git archives on Windows and WSL Linux began without ignored
directories. On both platforms, the old initialization reproduced the same
`FileNotFoundError` in one fixture-driven test. After executing the corrected
initialization, the exact full regression command passed on Python 3.11.17 with
LIEF 0.17.1, pytest 9.1.1 and required native OSV 2.7.0:

- Windows: 176 passed, 8 skipped (113.52 s).
- WSL Linux: 175 passed, 8 skipped (387.42 s).
- WSL Linux `unshare -n` offline command: 58 passed, 1 skipped (153.54 s).

The eight skips are the six optional real-APK regressions, Flutter sample
inspection and published Maven snapshot check; those external assets are absent
from a fresh checkout. The offline command skipped only the absent published
snapshot. No required native OSV check was skipped. Actionlint
1.7.12 accepts the corrected workflow. Hosted matrix completion remains pending.

Reproduction: install dependencies, set `PYTHONPATH=src` when not installed,
`LIBIDENTIFIER_REQUIRE_OSV=1`, `LIBIDENTIFIER_TEST_OSV` to the platform executable,
and `LIBIDENTIFIER_TEST_PROFILES` to a schema-2 rebuild. Create `.pytest_tmp`
before using the nested basetemp paths below. Run
`python -m pytest -q --basetemp .pytest_tmp/qualification`. Under a privileged
Linux network namespace run the same interpreter with
`tests/test_offline_assessment.py tests/test_osv_convenience.py tests/test_stage2.py`.
Environment-specific local runtime/dependency directories remain ignored.

## Hosted qualification follow-up

Hosted follow-up: [run 39159541566](https://github.com/ernestomgz/libidentifier/actions/runs/39159541566)
completed successfully for commit `7cd10193fb99ba461b8d444521339a4b0f8839f5`.
The public run/job API confirms all six Windows/Linux Python 3.11/3.12/3.13 jobs
passed. This supersedes the earlier pending hosted-run status in this historical
report. Consumer-specific integration qualification belongs in each consuming
repository.

## Performance pilot and remaining limits

[Machine-readable pilot](stage2-pilot.json), generated by `benchmarks/run.py`.
Measurements preceded final attribution/status refinements and ran under concurrent
test load; they are preliminary, not a controlled cross-version comparison.

| APK | Classes | Relationships | Clusters | Seconds | Peak MiB |
|---|---:|---:|---:|---:|---:|
| Allsafe | 12,077 | 441,841 | 310 | 97.89 | 995.8 |
| AndroGoat | 7,448 | 272,241 | 247 | 72.52 | 655.0 |
| DIVA | 6,493 | 227,619 | 187 | 28.56 | 557.4 |
| InjuredAndroid | 3,798 | 133,009 | 73 | 13.60 | 348.0 |
| InsecureBankv2 | 6,529 | 186,606 | 40 | 29.47 | 469.2 |
| OVAA | 7,907 | 264,362 | 424 | 50.05 | 632.5 |

Complete enrichment has material cost. API options/CLI switches can disable
calls, structural/published relationships and grouping independently without
changing component identification. Parser memory/time isolation remains a host
responsibility. Output caps do not silently cap analysis or cluster membership.

The six APKs have no complete independently established dependency ground truth;
quality metrics are null, not fabricated zero/100% accuracy. Stage 3 must establish
representative held-out builds and thresholds; report exact-version precision
separately from coverage. Advanced Maven resolution, dynamic call targets and
R8 generation remain deliberately unsupported. Stage 2 structural matching uses
one primary DEX reference variant per release; variants are retained for later
algorithm improvements. SQLite sidecar manifest publication remains separate
from database replacement; the database contains its own provenance.
