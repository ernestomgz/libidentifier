"""CycloneDX 1.5 JSON export for exact, high-confidence components."""

from __future__ import annotations

import json
from pathlib import Path

from .models import ScanResult
from .purl import reference_coordinates


def export_cyclonedx(result: ScanResult, path) -> None:
    components = []
    excluded = []
    for component in result.components:
        if not component.purl or not component.version:
            excluded.append({"component_id": component.component_id, "reason": "exact version or PURL unavailable"})
            continue
        if component.identity_confidence != "high" or component.version_confidence != "high":
            excluded.append({"component_id": component.component_id, "reason": "identity and version confidence must both be high"})
            continue
        try:
            _, _, name, version, _ = reference_coordinates(component.purl)
        except ValueError:
            excluded.append({"component_id": component.component_id, "reason": "invalid reference PURL"})
            continue
        if version != component.version or name != component.name:
            excluded.append({"component_id": component.component_id, "reason": "PURL disagrees with component identity/version"})
            continue
        components.append(
            {
                "type": "library",
                "bom-ref": component.component_id,
                "name": component.name,
                "version": component.version,
                "purl": component.purl,
                "properties": [{"name": "libidentifier:matched_code", "value": json.dumps(
                    [loc.to_dict() for loc in component.matched_code], sort_keys=True, separators=(",", ":"))}],
            }
        )
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [{"name": result.tool_name, "version": result.tool_version}],
            "properties": [
                {"name": "libidentifier:inventory_scope", "value": "Only high-confidence exact-version matches; not a complete software inventory"},
                {"name": "libidentifier:input", "value": json.dumps(result.input.to_dict(), sort_keys=True)},
                {"name": "libidentifier:profile_database", "value": json.dumps(result.profile_database.to_dict(), sort_keys=True)},
                {"name": "libidentifier:fingerprint_algorithm", "value": result.fingerprint_algorithm},
                {"name": "libidentifier:scan_schema_version", "value": str(result.schema_version)},
                {"name": "libidentifier:excluded_components", "value": json.dumps(excluded, sort_keys=True)},
                {"name": "libidentifier:coverage", "value": json.dumps(result.coverage.to_dict(), sort_keys=True)},
                {"name": "libidentifier:errors", "value": json.dumps([e.to_dict() for e in result.errors], sort_keys=True)},
            ],
        },
        "compositions": [{"aggregate": "incomplete"}],
        "components": sorted(components, key=lambda c: c["bom-ref"]),
    }
    Path(path).write_text(json.dumps(bom, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

