# Limitations

- Stage 2 adds deterministic unattributed clusters and evidence-backed structural,
  ordinary invocation and component references. Namespace/connectivity does not
  establish library origin. Dynamic call-site targets, runtime dispatch,
  reachability and full dependency trees are not reconstructed.
- Standard DEX 035/037/038/039/040 is supported by the supplementary reader;
  container DEX 041, reverse-endian and optimized instruction formats are rejected.
- POM interpretation is direct/local only; unresolved parent/BOM/profile context
  remains explicit. Declarations from candidate releases are conditional.
- Simple canonical Maven `pom.properties` can corroborate an observed candidate
  version only with exact-descriptor code evidence. It is a modifiable declaration,
  not authenticated release provenance; unsupported properties syntax is ignored.
- Multiple reference variants are retained; Stage 2 structural scoring uses one
  primary DEX variant per release. Actual R8 generation and calibrated fusion are
  deferred. Production thresholds require representative held-out benchmarks.

- Optional offline Maven advisory assessment uses a trusted local OSV-Scanner v2 executable with runtime interface checks. v2.6.0 and v2.7.0 are tested; all historical/future releases are not individually qualified. v1, unidentified builds, future major versions and missing required flags are rejected. It never performs online advisory queries, dependency resolution, reachability analysis or exploitability decisions.
- Assessment-enabled CLI setup downloads a wholly absent advisory database unless `--offline` is supplied. Existing stale/corrupt databases require explicit maintenance. Python identification/correlation APIs never download. Executable SHA-256 pinning is optional; compatibility checks do not authenticate a publisher. Install from trusted channels and supply a publisher-verified pin for exact executable approval policies.
- No JavaScript, Hermes, Dart AOT, or Flutter package inventory.
- Framework presence hints cover Flutter, React Native, Compose, Cordova, Unity and Xamarin / .NET MAUI. Presence does not prove active use, exact version or coverage of application logic. Unity IL2CPP and .NET assemblies are not analyzed.
- DEX shape matching can miss heavily optimized or obfuscated libraries.
- Structural DEX matches do not prove an exact release version in Stage 1.
- Generic class shapes can be ambiguous; weak evidence is kept out of the component list.
- LIEF is native code; hostile malformed binaries may still be best handled by invoking the CLI in a managed worker process from a host application.
- `max_scan_seconds` is compatibility-only and unenforced in-process. Use a host subprocess timeout and external memory limits; byte/member limits do not bound all parser allocations.
- Reference coverage is always limited. Unknown versions and candidate releases are not confirmed installed versions; the CycloneDX export is an explicitly incomplete exact-version subset.
- Unknown-class locators are complete by default; optional caps retain original totals and truncation flags. Successfully parsed unassigned ELF artifacts remain visible in `analyzed_files`.
- Package-only advisory discovery is bounded and cannot establish version applicability. Candidate versions are not installed versions. Unsupported ecosystems and insufficient-confidence identities remain unassessed.
- Advisory snapshot freshness is based on retrieval provenance. Local import timestamps must describe the actual data retrieval; hashes prove integrity, not feed completeness. Missing/corrupt/stale snapshots block assessment.
- The trusted executable and full `--offline` flags do not constitute an OS sandbox. Deploy under host egress policy when independent enforcement is required. LIEF and OSV native allocations are not hard memory-isolated by Python. The private dual-layout cache view may copy bounded archives when hard links are unavailable.
