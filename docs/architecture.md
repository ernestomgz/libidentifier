# Architecture

LibIdentifier is API-first. The CLI delegates to the same `identify()`, `inspect()`, `build_profile()`, and `export_cyclonedx()` functions exposed from `libidentifier`.

The scan pipeline is:

1. Detect top-level format from magic bytes.
2. Traverse ZIP/APK members with bounded, safe reads.
3. Extract DEX class features and ELF identity features with LIEF. A bounded
   standard DEX table reader supplies canonical descriptors, interface lists,
   method references and code-item locations unavailable in LIEF's Python API.
4. Convert features to deterministic fingerprints.
5. Query a local read-only SQLite profile database.
6. Score candidates conservatively and resolve location-aware ownership claims.
   Conflicting claims, shape multiplicity ambiguity and duplicate descriptors
   remain unattributed for component-edge aggregation.
7. Extract structural/signature relationships and bounded explicit invocation
   references; aggregate only uniquely attributed embedded endpoints.
8. Group unmatched definitions deterministically by meaningful exact packages
   and inheritance/interface links. Preserve singleton groups and unknown origin.
9. Attach published reference declarations and supported embedded Maven version
   metadata, reporting capability status, evidence, uncertainty and limitations.
10. Emit deterministic JSON; unknown-output caps apply after enrichment.

The package has no dependency on any consuming application. Optional `scan()`/`correlate()` assessment
uses a verified local OSV executable and advisory snapshot. Python scan APIs never
download; the assessment CLI may provision a wholly absent database unless
`--offline`. Existing databases require explicit update. Assessment itself always
runs offline. Hosts retain application ownership, reachability and exploitability
decisions. See the [public contract](integration.md) and [roadmap](development/roadmap.md).

`extractors/instructions.py` traverses standard DEX widths and switch/array
payloads. Ordinary invoke/range forms yield declared references with absolute
member byte offsets; special dynamic formats and undecodable methods report
partial coverage. No runtime dispatch, execution, reachability or data-flow is
inferred. External/ambiguous targets have no embedded target location.

`profiles/pom.py` handles direct dependencies/local properties only. Parent,
BOM, dependency-management and profile context remains preserved but unresolved.
Source release declarations stay distinct from observed APK code references.
See [profile storage](profile-database.md) for internal schema/rebuild rules.


`cli_setup.py` is a CLI-only orchestration layer for managed scans without profile
overrides. It gathers missing resources, obtains one consent decision, invokes
explicit profile/advisory maintenance and installs a scanner pinned by
`cli_resources.py`. Scanner bytes are bounded and checked before execution.
The same pin catalog is used by native CI; no GitHub latest lookup occurs.
After setup the managed assessment path is forced offline, including when setup
was declined or failed. Existing explicit commands and analysis APIs keep their
previous resource policies.
