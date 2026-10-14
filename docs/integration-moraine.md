# Moraine Integration

The official, application-independent contract is [integration.md](integration.md). This page supplies supplemental Moraine context.

Moraine imports LibIdentifier; LibIdentifier never imports Moraine.

```python
from libidentifier import identify

result = identify(apk_path, profiles=managed_profile_db)
```

LibIdentifier returns component identities, version ambiguity, matched locators, unknown classes, coverage, and parser errors. Its optional `scan()`/`correlate()` APIs handle offline OSV-Scanner assessment. Moraine remains responsible for command/evidence persistence, application ownership decisions, exposure and reachability policy, advisory triage, and final findings.
