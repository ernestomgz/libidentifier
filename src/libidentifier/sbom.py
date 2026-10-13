"""CycloneDX 1.5 JSON export for exact, high-confidence components."""

from __future__ import annotations

import json
from pathlib import Path

from .models import ScanResult


def export_cyclonedx(result: ScanResult, path) -> None:
    components = []
    for component in result.components:
        if not component.purl or not component.version:
            continue
        if component.identity_confidence != "high" or component.version_confidence != "high":
            continue
        components.append(
            {
                "type": "library",
                "bom-ref": component.component_id,
                "name": component.name,
                "version": component.version,
                "purl": component.purl,
            }
        )
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"tools": [{"name": result.tool_name, "version": result.tool_version}]},
        "components": sorted(components, key=lambda c: c["bom-ref"]),
    }
    Path(path).write_text(json.dumps(bom, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

