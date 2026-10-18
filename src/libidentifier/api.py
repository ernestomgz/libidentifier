"""Python API entry points."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

from .config import FINGERPRINT_ALGORITHM, SCHEMA_VERSION, IdentifyOptions
from .errors import ProfileError
from .inventory import empty_scan_result, inspect_path
from .matcher import match_inventory
from .models import ScanResult
from .profiles.builder import build_profile
from .profiles.store import connect_readonly, database_record
from .sbom import export_cyclonedx
from .version import __version__
from .vulnerabilities.models import AssessmentResult, VulnerabilityOptions, VulnerabilityReport


def _result_coverage(coverage, *, total: int, emitted: int, identification: str):
    limitations = list(coverage.limitations)
    limitations.append("Identification is limited to supplied reference profiles; no matches does not mean no third-party code")
    if identification == "not_performed":
        limitations.append("Library matching was not performed (inspect has no reference database)")
    elif identification == "no_profiles":
        limitations.append("The reference database contains no profiles")
    if emitted < total:
        limitations.append(f"Unknown class output truncated: emitted {emitted} of {total} unmatched definitions")
    return replace(coverage, library_identification=identification,
                   unknown_classes_total=total, unknown_classes_emitted=emitted,
                   unknown_classes_truncated=emitted < total, limitations=limitations)


def inspect(path, *, options: IdentifyOptions | None = None) -> ScanResult:
    opts = options or IdentifyOptions()
    inv = inspect_path(Path(path), opts)
    result = empty_scan_result(inv, __version__)
    from .relationships import enrich
    from .extractors.version_metadata import apply_version_metadata
    result = enrich(apply_version_metadata(result, inv), inv, opts)
    unknown = result.unknown_classes if opts.max_emitted_unknown_classes is None else result.unknown_classes[:opts.max_emitted_unknown_classes]
    return replace(result, unknown_classes=unknown,
        coverage=_result_coverage(result.coverage, total=len(inv.dex_classes), emitted=len(unknown), identification="not_performed"))


def identify(path, *, profiles, options: IdentifyOptions | None = None) -> ScanResult:
    opts = options or IdentifyOptions()
    inv = inspect_path(Path(path), opts)
    conn = connect_readonly(profiles)
    try:
        components, hints, unknown = match_inventory(conn, inv, opts)
        database = database_record(profiles)
        result = ScanResult(
            schema_version=SCHEMA_VERSION, tool_name="libidentifier", tool_version=__version__,
            fingerprint_algorithm=FINGERPRINT_ALGORITHM, profile_database=database,
            input=inv.input,
            analyzed_files=sorted(inv.analyzed_files, key=lambda a: (a.member or "", a.sha256)),
            frameworks_detected=inv.frameworks_detected, components=components,
            class_ownership_hints=hints, unknown_classes=unknown, coverage=inv.coverage, errors=inv.errors)
        from .extractors.version_metadata import apply_version_metadata
        from .relationships import enrich
        result = enrich(apply_version_metadata(result, inv), inv, opts, conn)
    except sqlite3.Error as exc:
        raise ProfileError(f"cannot query profile database: {exc}") from exc
    finally:
        conn.close()
    emitted = unknown if opts.max_emitted_unknown_classes is None else unknown[:opts.max_emitted_unknown_classes]
    return replace(result, unknown_classes=emitted,
        coverage=_result_coverage(inv.coverage, total=len(unknown), emitted=len(emitted),
                                  identification="limited" if database.profile_count else "no_profiles"))



def correlate(result: ScanResult, *, options: VulnerabilityOptions) -> VulnerabilityReport:
    """Assess an existing inventory using explicitly configured local OSV data."""
    from .vulnerabilities.correlate import correlate as assess
    return assess(result, options=options)


def scan(path, *, profiles, options: IdentifyOptions | None = None,
         vulnerabilities: VulnerabilityOptions | None = None) -> AssessmentResult:
    """Identify, then optionally assess; never provision or download dependencies."""
    from .vulnerabilities.models import AssessmentResult, VulnerabilityReport
    result = identify(path, profiles=profiles, options=options)
    report = correlate(result, options=vulnerabilities) if vulnerabilities is not None else VulnerabilityReport(
        "not_requested", result.input, result.tool_version, result.profile_database,
        limitations=["Vulnerability assessment was not requested"],
        identification_coverage=result.coverage, identification_errors=result.errors)
    return AssessmentResult(result, report)
