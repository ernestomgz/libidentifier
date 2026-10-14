# LibIdentifier Stage 1 Real APK Validation

Date: 2026-10-14

Latest follow-up: [Complete output and optional offline assessment validation](offline-assessment-validation.md) records Windows/Linux test results, full unmatched output and local OSV integration. The measurements below are historical identification-only results.

Follow-up: [Final SCA readiness validation](sca-readiness-validation.md) independently rechecks the six APKs, corrects version-candidate presentation, validates CycloneDX exports and records the targeted OkHttp 3.14.9 comparison. The historical measurements below describe the earlier seven-profile database.

## Summary

Stage 1 is now substantially stronger than the initial validation pass. LibIdentifier parses the six sample APKs without parser errors, filters DEX inventories to actual class definitions, rejects old contaminated fingerprint databases, rebuilds a profile database from a Git-tracked catalog, and produces profile-backed matches with clean code evidence.

The current small catalog identifies:

- Allsafe: OkHttp and RootBeer.
- AndroGoat: OkHttp.
- OVAA: OkHttp, Retrofit and a partial Gson match.

DIVA, InjuredAndroid and InsecureBankv2 still produce no profile-backed components with this small database. That is expected: the catalog does not yet include legacy support libraries, Firebase/Google Play Services, Flutter/Dart package signatures, or the relevant Volley/old Google artifacts.

No exact DEX versions are claimed. Version confidence remains `unknown` for structural DEX matches, even when only one catalog version is available.

## Implementation Changes Validated

Key fixes and improvements:

- DEX extraction now filters LIEF class output through the raw DEX `class_defs` table.
- The fingerprint algorithm compatibility string is now `dex-shape-v1-defs+elf-identity-v1`, so old contaminated databases are rejected.
- Profile databases now store reference class descriptors in addition to shape digests.
- The matcher uses exact descriptor evidence for matched-code locators when available, avoiding attribution of common structural shapes to unrelated classes.
- Cross-family runner-up suppression now ignores tiny generic-shape overlaps and only treats material overlap as competition.
- Conservative partial-library medium confidence was added for cases with substantial exact descriptor evidence, many anchors and explicit limitations.
- A catalog/fetch/rebuild workflow now exists:
  - `catalog/references.json`
  - `libidentifier profiles fetch`
  - `libidentifier profiles rebuild`
  - rebuild writes a manifest and replaces the database atomically on success.
- `identify` can use `LIBIDENTIFIER_PROFILES` when `--profiles` is omitted; it never downloads automatically.

## Environment and Setup

- Python used: `C:\Users\Windows 11\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe`
- Installed validation dependencies: editable `libidentifier`, `lief==0.17.1`, `pytest==9.1.1`
- Android D8 used for JAR/AAR profile builds: Android SDK build-tools `36.1.0`
- Java used for D8: Android Studio JBR `21.0.10`
- Local validation D8 wrapper: `test-results/d8-wrapper.cmd`

The default Windows Store `python.exe` shim was unusable on this host. Pytest and profile building were run with workspace-local temp directories to avoid sandbox temp path issues.

## Tests Executed

Command:

```powershell
& 'C:\Users\Windows 11\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -q --basetemp .pytest-tmp
```

Result:

```text
19 passed
```

New coverage includes:

- Reference-only DEX types are excluded from class inventory.
- Incompatible fingerprint metadata is rejected.
- Tiny cross-library shape overlap does not suppress distinct libraries.
- Catalog parsing, explicit fetch, offline rebuild and default `LIBIDENTIFIER_PROFILES` lookup.

## Reference Catalog and Database

Catalog:

- `catalog/references.json`

Validation DB:

- `test-results/samples/reference-profiles.sqlite`

Maintenance artifacts:

- `test-results/samples/profile-fetch-results.json`
- `test-results/samples/profile-rebuild-results.json`
- `test-results/samples/reference-profiles.sqlite.manifest.json`

The validation database was rebuilt through:

```powershell
libidentifier profiles rebuild --catalog catalog\references.json --cache test-results\reference-artifacts --database test-results\samples\reference-profiles.sqlite --d8 test-results\d8-wrapper.cmd --android-jar C:\Users\Windows 11\AppData\Local\Android\Sdk\platforms\android-35\android.jar --offline
```

Catalog entries:

| Artifact | Version | SHA-256 | Profile shapes |
| --- | --- | --- | ---: |
| Gson | 2.11.0 | `57928d6e5a6edeb2abd3770a8f95ba44dce45f3b23b7a9dc2b309c581552a78b` | 226 |
| Commons IO | 2.16.1 | `f41f7baacd716896447ace9758621f62c1c6b0a91d89acee488da26fc477c84f` | 716 |
| Retrofit | 2.9.0 | `e6ea1929c46852f5bec66ab3357da383476cef4e8d1deefdbf195b79cc4d6581` | 111 |
| converter-gson | 2.9.0 | `32aa206b9a29c9df5eda93a092cfb3b0b9133e232c062baa882f0319f0e79f0e` | 4 |
| OkHttp | 4.9.0 | `dbc2bb04ecb002b9f4046263ccad996f4a3d3c59a0cc98837e300a6700571f7c` | 326 |
| OkHttp | 4.9.3 | `93ecd6cba19d87dccfe566ec848d91aae799e3cf16c00709358ea69bd9227219` | 326 |
| RootBeer | 0.0.8 | `4750bedff6605ed4ca96e2dd9b13fd6216ba55eb7abf914cbd9f9f00566ad82a` | 6 |

The shape counts dropped from the initial contaminated profiles because reference-only classes are no longer included.

## Samples Inspected

Full inspect JSON:

- `test-results/samples/*.inspect.json`

Summary:

| APK | DEX members | ELF members | Defined classes | Parse errors |
| --- | ---: | ---: | ---: | ---: |
| `allsafe-1.6.apk` | 7 | 8 | 12,076 | 0 |
| `AndroGoat-2.0.1.apk` | 2 | 0 | 7,448 | 0 |
| `diva.apk` | 1 | 0 | 6,493 | 0 |
| `InjuredAndroid-1.0.12-release.apk` | 1 | 15 | 3,771 | 0 |
| `InsecureBankv2-2.3.1.apk` | 1 | 0 | 6,529 | 0 |
| `ovaa-1.0.0-app-debug.apk` | 9 | 4 | 7,907 | 0 |

Compared with the initial validation, defined class counts are lower because reference-only DEX types are excluded.

## Identification Results

Full identify JSON:

- `test-results/samples/*.identify.json`

Supporting analysis:

- `test-results/samples/python-api-identify-summary.json`
- `test-results/samples/match-analysis.json`
- `test-results/samples/candidate-coverage.json`

| APK | Components | Confidence | Version result |
| --- | --- | --- | --- |
| `allsafe-1.6.apk` | OkHttp, RootBeer | high, high | unknown; candidates `4.9.0, 4.9.3` for OkHttp and `0.0.8` for RootBeer |
| `AndroGoat-2.0.1.apk` | OkHttp | high | unknown; candidates `4.9.0, 4.9.3` |
| `diva.apk` | none | n/a | n/a |
| `InjuredAndroid-1.0.12-release.apk` | none | n/a | n/a |
| `InsecureBankv2-2.3.1.apk` | none | n/a | n/a |
| `ovaa-1.0.0-app-debug.apk` | OkHttp, Retrofit, Gson | high, medium, medium partial | unknown; candidates from catalog |

Important score details:

- Allsafe OkHttp: 321 exact descriptor matches / 326 profile classes, weighted coverage `0.990261`.
- Allsafe RootBeer: 6 / 6 exact descriptor matches, weighted coverage `1.0`.
- AndroGoat OkHttp: 321 / 326 exact descriptor matches, weighted coverage `0.990261`.
- OVAA OkHttp: 273 / 326 exact descriptor matches, weighted coverage `0.917068`.
- OVAA Retrofit: 81 / 111 exact descriptor matches, weighted coverage `0.837161`.
- OVAA Gson: 143 / 226 exact descriptor matches, weighted coverage `0.727350`, marked partial.

Matched-code evidence check:

- `test-results/samples/match-analysis.json` reports `platform_like_matched: 0` for every component.
- Matched locators now use real embedded class descriptors such as `Lokhttp3/...`, `Lretrofit2/...`, `Lcom/google/gson/...` and `Lcom/scottyab/rootbeer/...`.

## Before / After

Initial validation:

- DEX inventory included reference-only types.
- OkHttp matches contained unrelated Java/Android/AndroidX locators.
- Gson, Retrofit and RootBeer were missed or suppressed.
- Profiles were manually built one at a time.

Current validation:

- DEX inventory is class-definition-only.
- Old fingerprint DBs are incompatible.
- Matched-code evidence is descriptor-clean.
- RootBeer is detected in Allsafe.
- Retrofit and partial Gson are detected in OVAA.
- The database rebuild is catalog-driven and offline when cached.

## Remaining Undetected Libraries

- DIVA support libraries: not in the current catalog.
- InjuredAndroid Firebase/Flutter/Volley/etc.: not covered by the current catalog; Dart AOT package identification remains out of scope.
- InsecureBankv2 Google Play Services/support libraries: not in the current catalog.
- OVAA Commons IO: candidate evidence exists but exact descriptor coverage is too low for the current conservative policy.
- converter-gson: very small profile, only 2 of 4 exact descriptors in OVAA; not enough for a confident standalone component.

## Limitations

- DEX structural matching still does not prove exact version. `version` remains `null` unless a stronger exact-version signal is available.
- R8 shrinking and partial embedded libraries can reduce coverage.
- The catalog is intentionally small and should not be treated as comprehensive intelligence.
- No vulnerability analysis, OSV integration, JavaScript, Hermes or Dart package identification is included.

## Conclusion

Stage 1 now works for libraries supported by its clean reference database on the tested real APKs, while preserving uncertainty and unknown coverage. The remaining misses are primarily catalog coverage and partial-library limitations rather than parser failures or contaminated evidence. Broader ecosystem coverage and deeper version discrimination should remain Stage 2/Stage 3 work.
