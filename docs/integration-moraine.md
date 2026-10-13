# Moraine Integration

Moraine imports LibIdentifier; LibIdentifier never imports Moraine.

```python
from libidentifier import identify

result = identify(apk_path, profiles=managed_profile_db)
```

LibIdentifier returns component identities, version ambiguity, matched locators, unknown classes, coverage, and parser errors. Moraine remains responsible for command/evidence persistence, application ownership decisions, OSV-Scanner execution, advisory interpretation, and final findings.

