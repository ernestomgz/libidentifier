# Testing and acceptance

Use Python 3.11+ with `lief==0.17.1` and the dev dependencies. Run
`python -m pytest -q` (optionally `--basetemp .pytest-tmp`). Test fixtures create
synthetic DEX/ELF and temporary databases. Never use production data as test output.
Windows Store Python aliases may be unavailable in restricted environments; use
a working explicit interpreter and an isolated dependency directory if needed.

Qualified integration: set `LIBIDENTIFIER_TEST_OSV` to an approved native OSV
2.7.0 executable. Missing tools may skip developer integration tests, but required
release jobs must run them. JAR/AAR qualification needs local Java, D8/android.jar;
these are build prerequisites, never scan prerequisites.

For the optional six real-APK regressions, set `LIBIDENTIFIER_TEST_PROFILES` to a
database rebuilt with this engine (default historical location:
`test-results/samples/reference-profiles.sqlite`). A schema-1 local fixture is
incompatible and must not be relabeled. Set `LIBIDENTIFIER_REQUIRE_OSV=1` for
qualification jobs so missing scanner integration cannot silently skip.

Run Windows and Linux separately. For offline integration deny network at the OS
boundary (Linux network namespace or managed host policy). Python network mocks
alone do not establish subprocess isolation. Test automatic CLI provisioning in
a separate controlled test; `--offline` and Python APIs must not download.

Record interpreter/LIEF/tool versions, commands, counts, skips and limitations.
The Windows/Linux Python 3.11–3.13 CI matrix installs the built package (without
editable source paths) and retains runtime provenance and JUnit results, including
skip reasons, as one artifact per environment. Linux repeats the offline subset
inside a network namespace. The workflow supports manual dispatch after it has
been published; a workflow definition is not evidence of an executed hosted run.
Before publishing workflow edits, run `actionlint .github/workflows/tests.yml`.
Python compilation and YAML parsing alone do not validate Actions expression
contexts. Job-level environment expressions must use contexts available at that
scope (for example `matrix.os`); `runner.os` is available in step conditions.
CI writes bootstrap evidence before package installation and records scanner
download/checksum errors before re-raising them. Qualification downloads use
workflow-local publisher checksum pins; runtime scanner acceptance remains based
on capabilities and any caller-supplied hash. When artifacts are missing, inspect
the first failing step; the final upload warning is not the original failure.
Historical reports under `test-results/` are evidence for their recorded checkout.
The [Stage 2 checklist](stages/stage-2.md) owns acceptance status.

Benchmark protocol: use reproducible apps with build-ground-truth coordinates,
versions, compiler/keep settings and hashes; include independent held-out families,
negative controls, full/renamed/shrunk libraries and shared generic code. Keep
training/calibration and held-out evaluation separate. Report family precision/
recall, false positives, version precision AND coverage, evidence correctness,
cluster pairwise purity/fragmentation, wall time and peak RSS by input size and
platform. No production threshold is final before a representative baseline.

Run `python benchmarks/run.py --profiles profiles.sqlite --corpus corpus.json`.
The [example corpus](../../benchmarks/corpus.example.json) describes the format;
paths are relative to the manifest. Each input runs in an isolated process with a
five-minute timeout, wall-clock time and process peak RSS. Quality metrics require
`ground_truth_complete=true`; incomplete real-world samples are performance
pilots, never precision/recall ground truth. Record build variants, input hashes,
tool/database provenance and independent train/evaluation splits.
