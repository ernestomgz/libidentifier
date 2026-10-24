# Stage 3 production quality

Initial incremental work: AndroidX version-file declarations now use the existing
evidence/attribution models; see the [metadata contract](../../integration.md#stage-2-evidence-clusters-and-relationships).
This adds a detection signal, not a measured accuracy/coverage claim. Matching
reference coverage remains necessary before a declaration can establish a version.

Expand trusted historical/current Android catalog coverage (C1–C2); improve
hierarchy and attributable metadata evidence (C2), version differential features
(C2–C3), selected D8/R8 variants, normalized opcodes if measured useful, evidence
fusion and partial matching (C3). Improve existing clusters/relationships without
redesigning public concepts. Prevent correlated evidence inflation.

First establish independent build-ground-truth APK benchmarks, split by family,
release and compiler transformations to prevent leakage. Publish family precision
and recall, false positives, exact-version precision AND coverage/abstention,
ownership/relationship correctness, grouping fragmentation/purity, runtime/RSS,
catalog provenance and Windows/Linux/offline results with denominators and
uncertainty. Accuracy thresholds remain provisional until baseline measurements.

Release requires agreed measured thresholds, compatible public contracts,
reproducible canonical database contents, rollback and documented catalog scope.
Algorithm quantity or six sample APKs alone cannot establish production readiness.
