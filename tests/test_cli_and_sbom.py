from __future__ import annotations

import json

from libidentifier.cli import main
from libidentifier.models import ComponentMatch, CoverageRecord, InputRecord, ProfileDatabaseRecord, ScanResult
from libidentifier.sbom import export_cyclonedx

from conftest import lib_classes, make_apk, make_dex


def test_cli_identify_matches_api(tmp_path, demo_db):
    apk = make_apk(tmp_path / "sample.apk", {"classes.dex": make_dex(lib_classes("lib/alpha", 6))})
    out = tmp_path / "out.json"
    assert main(["identify", str(apk), "--profiles", str(demo_db), "--format", "json", "--output", str(out)]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["components"][0]["name"] == "libalpha"
    assert data["components"][0]["version"] is None


def test_sbom_exports_only_exact_versioned_high_confidence(tmp_path):
    result = ScanResult(
        schema_version=1,
        tool_name="libidentifier",
        tool_version="0.1.0",
        fingerprint_algorithm="dex-shape-v1+elf-identity-v1",
        profile_database=ProfileDatabaseRecord(),
        input=InputRecord("x.apk", "apk", "x", 1),
        analyzed_files=[],
        frameworks_detected=[],
        components=[
            ComponentMatch(
                component_id="cmp-exact",
                name="exact",
                ecosystem="Maven",
                purl="pkg:maven/example/exact@1.0.0",
                version="1.0.0",
                version_candidates=["1.0.0"],
                identity_confidence="high",
                version_confidence="high",
                identification_methods=["elf_identity_v1"],
                score=1.0,
                score_details={},
                matched_code=[],
                source_artifacts=[],
            ),
            ComponentMatch(
                component_id="cmp-ambiguous",
                name="ambiguous",
                ecosystem="Maven",
                purl=None,
                version=None,
                version_candidates=["1.0.0", "1.1.0"],
                identity_confidence="high",
                version_confidence="unknown",
                identification_methods=["dex_shape_v1"],
                score=1.0,
                score_details={},
                matched_code=[],
                source_artifacts=[],
            ),
        ],
        class_ownership_hints=[],
        unknown_classes=[],
        coverage=CoverageRecord(),
        errors=[],
    )
    out = tmp_path / "bom.json"
    export_cyclonedx(result, out)
    bom = json.loads(out.read_text(encoding="utf-8"))
    assert [c["name"] for c in bom["components"]] == ["exact"]

