# Framework and public contract validation

Historical report: see [Final SCA readiness validation](sca-readiness-validation.md) for the subsequent independent audit, corrections and current test results.

Date: 2026-10-14. Executed on Windows with Python 3.11+ runtime and LIEF 0.17.1. Linux execution was not available in this session; implementation uses portable Python APIs.

## Automated checks

```powershell
& 'C:\Users\Windows 11\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -q --basetemp .pytest-tmp
```

Result: **41 passed**. Original 19 tests retained. Added coverage for all six framework families, low versus corroborated confidence, ambiguous/generic and reference-only negatives, parsed native artifacts, Cordova bootstrap content, ELF SONAME/export metadata, multiple frameworks, exact evidence paths, API/JSON/table consistency, deterministic output, old hint construction, additive fields, schema refusal, missing/corrupt/incompatible databases, mixed release algorithms, partial results, directory scans and UTF-8 subprocess JSON.

The complete Python processing example in `docs/integration.md` was executed against OVAA with `test-results/samples/reference-profiles.sqlite`. The documented subprocess approach was executed against InjuredAndroid, and the existing profile database passed `profiles validate`. Initial subprocess verification exposed a Windows code-page failure on non-ASCII class descriptors; CLI stdout/stderr now use UTF-8, with a regression test forcing an ASCII process environment.

## Real APK checks

All six APKs were identified with the existing Stage 1 validation database. No parser errors occurred. Profile-backed library results remained consistent with the previous report.

| Sample | Framework presence | Profile-backed libraries |
| --- | --- | --- |
| Allsafe 1.6 | none detected | OkHttp, RootBeer |
| AndroGoat 2.0.1 | none detected | OkHttp |
| DIVA | none detected | none |
| InjuredAndroid 1.0.12 | Flutter, high confidence | none |
| InsecureBankv2 2.3.1 | none detected | none |
| OVAA 1.0.0 | none detected | Gson, OkHttp, Retrofit |

Full framework observations and sample summaries: `test-results/framework-validation.json`.

InjuredAndroid evidence:

- Actual class definition `Lio/flutter/embedding/android/FlutterActivity;` in `classes.dex`.
- Asset layout `assets/flutter_assets/AssetManifest.json`.
- Parsed ELF runtime files `lib/arm64-v8a/libflutter.so`, `lib/armeabi-v7a/libflutter.so` and `lib/x86_64/libflutter.so`.

This provides three evidence kinds (DEX, asset, native). Multiple ABIs do not count as separate corroborating kinds. Member SHA-256 hashes and exact container/member/class locators are retained. No Dart application logic or dependencies were analyzed; no Flutter version is inferred.

## Contract and implementation notes

- Schema 1 and existing scan signatures remain unchanged. Existing framework fields remain; structured evidence, stable framework IDs and application-logic coverage are additive with defaults.
- Deserialization ignores additive model fields and rejects unsupported public schema versions. Database schema and fingerprint compatibility are managed separately from output schema.
- Missing/corrupt/incompatible SQLite databases produce `ProfileError`; top-level read failures produce `InputError`; member parser failures retain partial results.
- Archive omissions now make DEX/ELF coverage partial. Directory scans no longer attempt to hash the directory as a file, and framework evidence distinguishes child APK containers.
- `docs/integration.md` is the official application-independent guide and specifies the contract Stage 3 must preserve. Old specification examples and algorithm strings are design history, not current evidence.

Remaining limitations: detection heuristics are not calibrated probabilities, markers can be imitated, renamed/stripped runtimes can be missed, presence does not prove active use, and Xamarin versus MAUI is conservatively grouped. No Dart/JS/Hermes/IL2CPP/.NET reverse engineering, vulnerability analysis or database coverage expansion was added. Unknown-class output remains capped and `max_scan_seconds` remains unenforced; both are documented. Engine/database upgrades may alter findings and require a reference rebuild while retaining the public scan contract.
