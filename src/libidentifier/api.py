"""Python API entry points."""

from __future__ import annotations

from pathlib import Path

from .config import FINGERPRINT_ALGORITHM, SCHEMA_VERSION, IdentifyOptions
from .inventory import empty_scan_result, inspect_path
from .matcher import match_inventory
from .models import ScanResult
from .profiles.builder import build_profile
from .profiles.store import connect_readonly, database_record
from .sbom import export_cyclonedx
from .version import __version__


def inspect(path, *, options: IdentifyOptions | None = None) -> ScanResult:
    opts = options or IdentifyOptions()
    inv = inspect_path(Path(path), opts)
    unknown = inv.dex_classes[: opts.max_emitted_unknown_classes]
    result = empty_scan_result(inv, __version__)
    return ScanResult(
        schema_version=result.schema_version,
        tool_name=result.tool_name,
        tool_version=result.tool_version,
        fingerprint_algorithm=result.fingerprint_algorithm,
        profile_database=result.profile_database,
        input=result.input,
        analyzed_files=result.analyzed_files,
        frameworks_detected=result.frameworks_detected,
        components=result.components,
        class_ownership_hints=result.class_ownership_hints,
        unknown_classes=[c.locator for c in unknown],
        coverage=result.coverage,
        errors=result.errors,
    )


def identify(path, *, profiles, options: IdentifyOptions | None = None) -> ScanResult:
    opts = options or IdentifyOptions()
    inv = inspect_path(Path(path), opts)
    conn = connect_readonly(profiles)
    try:
        components, hints, unknown = match_inventory(conn, inv, opts)
    finally:
        conn.close()
    return ScanResult(
        schema_version=SCHEMA_VERSION,
        tool_name="libidentifier",
        tool_version=__version__,
        fingerprint_algorithm=FINGERPRINT_ALGORITHM,
        profile_database=database_record(profiles),
        input=inv.input,
        analyzed_files=sorted(inv.analyzed_files, key=lambda a: (a.member or "", a.sha256)),
        frameworks_detected=inv.frameworks_detected,
        components=components,
        class_ownership_hints=hints,
        unknown_classes=unknown[: opts.max_emitted_unknown_classes],
        coverage=inv.coverage,
        errors=inv.errors,
    )

