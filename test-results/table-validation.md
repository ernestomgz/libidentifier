# Compact table and score-based assessment validation

Validated 2026-10-15 (Europe/Madrid). Development prototype; not a production-readiness claim.

## Result

`--format table` now renders an input title, aligned library/identity/version/advisory columns, framework evidence where present, and a vulnerability section only when assessment is requested. Very narrow terminals use stacked fields. Scores are displayed to two decimals; assessment uses the full stored score.

Advisory eligibility is now score-based: default `min_identity_score=0.75`, inclusive and configurable via `VulnerabilityOptions` or `--min-identity-score`. Categorical confidence labels remain unchanged. Missing, invalid or below-threshold scores are unassessed. Exact-version confidence remains independent; candidates are never queried as installed versions. Public API signatures and JSON model fields/schema versions are unchanged; the trailing options field is additive. Successful reports retain the selected threshold in their existing limitations list.

Affected-version display uses only the attributed package's OSV metadata. Fixed bounds remain exclusive; introduced and last-affected bounds remain inclusive. Disjoint ranges are not merged. Maven strings and qualifiers are not sorted or compared. Complex/unsorted timelines and limits remain explicit OSV events. Long explicit lists show exact counts and refer to complete JSON. Missing, unsupported or nullable ranges never cause an invented interval. CVE/GHSA aliases and component attribution remain available. Unknown future applicability labels are not rendered as confirmed findings.

## Executed checks

- Complete Windows suite: **132 passed in 92.71 seconds**, Python 3.12, LIEF 0.17.1, approved native OSV-Scanner 2.7.0 amd64.
- Complete Linux suite: **132 passed in 193.90 seconds**, WSL Ubuntu, Python 3.14.4, LIEF 0.17.1, approved native OSV-Scanner 2.7.0 amd64.
- Final focused score/renderer checks, including qualified cached PURLs: **33 passed on Windows in 13.96 seconds**, **33 passed on Linux in 69.73 seconds** under `unshare -n` with no internet route.
- Final nullable-range guard: **11 range-related checks passed in 1.55 seconds** on Windows. This guard only changes handling of absent/invalid display data.
- Real CLI scans: all six APKs on Windows and Linux; Linux sample verification ran under `unshare -n`. Full `ScanResult` equality against each platform's preceding snapshot protected component identities, candidate versions, framework evidence, exact class locations, coverage and complete unmatched definitions. Input hashes remained unchanged.
- Tables verified at 100, 64 and 40 columns for every APK; synthetic tests also cover 20/8 columns, long unbroken names, East Asian/combining width behavior, ANSI/control stripping, correct package attribution, disjoint and unsorted ranges, Maven qualifiers, inclusive/exclusive bounds, aliases, known affected/unaffected versions and scanner failures.
- `git diff --check` passed. No new dependencies or network paths were added.

The earlier full-suite runs (132 Windows/132 Linux) and focused increment (112 checks) preceded final compact-list/alignment refinements. Results above are the subsequent verification, with targeted checks for the final cache/nullable refinements. ARM64 hardware and bare-metal Linux were unavailable; native Windows and WSL Linux amd64 were tested.

## Actual sample assessments

| APK | Component | Score | Assessment | Advisory groups |
| --- | --- | ---: | --- | ---: |
| Allsafe | OkHttp | 0.990261 | Potential | 2 |
| Allsafe | RootBeer | 1.0 | Not assessed: version unknown, no package advisories in snapshot | 0 |
| AndroGoat | OkHttp | 0.990261 | Potential | 2 |
| OVAA | Gson | 0.725598 | Not assessed: score below 0.75 | 0 |
| OVAA | OkHttp | 0.917068 | Potential | 2 |
| OVAA | Retrofit | 0.837021 | Potential | 2 |

DIVA, InjuredAndroid and InsecureBankv2 have no profile-backed components to assess (`not_applicable`, not a clean/exhaustive scan); InjuredAndroid retains its Flutter presence indicator. All sample library versions remain unknown and all advisory findings are potential. OVAA's Retrofit is intentionally newly assessed despite its medium identity label. Its advisories are `CVE-2018-1000850` / `GHSA-8p8g-f9vg-r7xr` and `CVE-2018-1000844` / `GHSA-j379-9jr9-w5cq`, with declared affected interval 2.0.0 inclusive to 2.5.0 exclusive and seven explicitly listed versions. Its reference candidate 2.9.0 is not an installed-version claim and therefore cannot prove applicability or non-applicability.

OkHttp retains `CVE-2021-0341` / `GHSA-3cqm-mf7h-prrj` and `CVE-2016-2402` / `GHSA-4hc2-jh7r-wrc3`. The latter's actual separate ranges are before 2.7.4 and 3.0.0 inclusive to 3.1.2 exclusive; they are not collapsed into a vague “older versions” statement. Reachability/exploitability remain unassessed.

Reproduction: `test-results/validate-table.py`. Detailed scores, statuses and scanner/database provenance: [Windows](table-validation-windows.json), [Linux](table-validation-linux.json). Actual 64-column example: [OVAA table](table-ovaa.txt). Complete width-specific snapshots and raw assessments are generated under ignored `test-results/tmp/table-{platform}`.

Changed source: `cli.py`, new `table.py`, advisory options/setup/correlation. Tests: new `test_table_and_score.py`, updated earlier table assertions. Documentation: README, integration guide and quickstart. The identification engine, official offline scanner adapter, database formats and SBOM filter were preserved. Future Stage 3 changes must retain separate identity/version confidence and candidate uncertainty; numeric scores and detection outcomes may evolve.
