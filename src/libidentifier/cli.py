"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .api import identify, inspect, scan, correlate
from .vulnerabilities.models import AssessmentResult
from .vulnerabilities.setup import prepare_options
from .vulnerabilities.correlate import unavailable_report
from .vulnerabilities.database import provision_advisory_database, update_advisory_database, validate_advisory_database
from .errors import AdvisoryError, InputError, LibIdentifierError, ProfileError
from .models import ScanResult
from .config import IdentifyOptions
from .serialization import write_stream
from .table import write_table
from .profiles.builder import build_profile, validate_database
from .profiles.catalog import load_catalog
from .profiles.fetcher import fetch_catalog, rebuild_database
from .sbom import export_cyclonedx
from .version import __version__


def _write_result(result: ScanResult, args) -> None:
    if args.format == "json":
        if args.output:
            result.write_json(args.output)
        else:
            write_stream(result, sys.stdout)
    else:
        write_table(result)


def _identify_options(args):
    return IdentifyOptions(max_emitted_unknown_classes=args.max_unknown_classes,
        extract_relationships=not args.no_relationships, extract_calls=not args.no_calls,
        group_unknown_classes=not args.no_grouping)


def _cmd_inspect(args) -> int:
    result = inspect(args.path, options=_identify_options(args))
    _write_result(result, args)
    return 4 if any(e.severity == "error" for e in result.errors) else 0


def _cmd_identify(args) -> int:
    profiles = args.profiles or os.environ.get("LIBIDENTIFIER_PROFILES")
    if not profiles:
        raise ProfileError(
            "no profile database specified; pass --profiles, set LIBIDENTIFIER_PROFILES, "
            "or build one with 'libidentifier profiles rebuild'"
        )
    result = identify(args.path, profiles=profiles, options=_identify_options(args))
    if args.vulnerabilities:
        assessment = AssessmentResult(result, _assess(result, args))
        _write_assessment(assessment, args)
        return _assessment_exit(assessment)
    _write_result(result, args)
    return 4 if any(e.severity == "error" for e in result.errors) else 0


def _cmd_profiles_build(args) -> int:
    built = build_profile(
        args.path,
        purl=args.purl,
        database=args.database,
        d8=args.d8,
        android_jar=args.android_jar,
        reference_sha256=args.sha256,
    )
    sys.stdout.write(json.dumps(built.to_dict(), sort_keys=True, separators=(",", ":")) + "\n")
    return 0


def _cmd_profiles_validate(args) -> int:
    validate_database(args.database)
    sys.stdout.write("profile database is valid\n")
    return 0


def _cmd_profiles_fetch(args) -> int:
    catalog = load_catalog(args.catalog)
    rows = fetch_catalog(catalog, args.cache, offline=args.offline)
    sys.stdout.write(json.dumps(rows, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


def _cmd_profiles_rebuild(args) -> int:
    rows = rebuild_database(
        args.catalog,
        cache_dir=args.cache,
        database=args.database,
        d8=args.d8,
        android_jar=args.android_jar,
        offline=args.offline,
    )
    sys.stdout.write(json.dumps(rows, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


def _cmd_sbom(args) -> int:
    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    export_cyclonedx(ScanResult.from_dict(data), args.output)
    return 0


def _assess(result, args):
    try:
        report = correlate(result, options=prepare_options(args))
    except (AdvisoryError, OSError) as exc:
        report = unavailable_report(result, exc)
    if report.errors:
        issue = report.errors[0]
        download = (' Download OSV-Scanner v2 from https://github.com/google/osv-scanner/releases.'
                    if issue.code == 'scanner_missing' else '')
        print(f"libidentifier: warning: advisories not fully assessed ({issue.code}): {issue.message}{download}", file=sys.stderr)
    return report


def _write_assessment(result, args):
    if args.format == "json":
        if args.output:
            result.write_json(args.output)
        else:
            write_stream(result, sys.stdout)
    else:
        inventory = result.identification if hasattr(result, 'identification') else None
        report = result.vulnerabilities if inventory is not None else result
        write_table(inventory, report)


def _assessment_exit(result):
    report = result.vulnerabilities if hasattr(result, "identification") else result
    if any(e.severity == "error" for e in report.identification_errors):
        return 4
    if report.errors and all(e.code == 'scanner_missing' for e in report.errors):
        return 0  # Identification completed; assessment is explicitly unavailable.
    if report.status in {"blocked", "failed"}:
        return 3
    if report.errors or any(e.severity == "error" for e in report.identification_errors):
        return 4
    return 0


def _cmd_scan(args):
    profiles = args.profiles or os.environ.get("LIBIDENTIFIER_PROFILES")
    if not profiles:
        raise ProfileError("scan requires --profiles or LIBIDENTIFIER_PROFILES")
    if args.vulnerabilities:
        identification = identify(args.path, profiles=profiles,
            options=_identify_options(args))
        result = AssessmentResult(identification, _assess(identification, args))
    else:
        result = scan(args.path, profiles=profiles,
            options=_identify_options(args))
    _write_assessment(result, args)
    return _assessment_exit(result)


def _cmd_correlate(args):
    try:
        result = ScanResult.from_dict(json.loads(Path(args.input).read_text(encoding="utf-8")))
    except (KeyError, TypeError, ValueError) as exc:
        raise InputError(f"invalid identification JSON: {exc}") from exc
    report = _assess(result, args)
    _write_assessment(report, args)
    return _assessment_exit(report)


def _cmd_advisories(args):
    if args.advisory_command == "provision":
        record = provision_advisory_database(args.database, archives={args.ecosystem: args.archive}, fetched_at=args.fetched_at)
    elif args.advisory_command == "update":
        record = update_advisory_database(args.database, ecosystems=[args.ecosystem])
    else:
        record = validate_advisory_database(args.database, max_age_days=args.max_database_age_days)
    sys.stdout.write(record.to_json() + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="libidentifier")
    parser.add_argument("--version", action="version", version=f"libidentifier {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    inspect_p = sub.add_parser("inspect")
    inspect_p.add_argument("path")
    inspect_p.add_argument("--format", choices=["json", "table"], default="json")
    inspect_p.add_argument("--output")
    inspect_p.add_argument("--max-unknown-classes", type=int, default=None)
    inspect_p.set_defaults(func=_cmd_inspect)

    identify_p = sub.add_parser("identify")
    identify_p.add_argument("path")
    identify_p.add_argument("--profiles")
    identify_p.add_argument("--format", choices=["json", "table"], default="json")
    identify_p.add_argument("--output")
    identify_p.add_argument("--max-unknown-classes", type=int, default=None)
    identify_p.add_argument("--vulnerabilities", action="store_true")
    identify_p.set_defaults(func=_cmd_identify)

    profiles_p = sub.add_parser("profiles")
    profiles_sub = profiles_p.add_subparsers(dest="profiles_command", required=True)
    build_p = profiles_sub.add_parser("build")
    build_p.add_argument("path")
    build_p.add_argument("--purl", required=True)
    build_p.add_argument("--database", required=True)
    build_p.add_argument("--d8")
    build_p.add_argument("--android-jar")
    build_p.add_argument("--sha256")
    build_p.set_defaults(func=_cmd_profiles_build)
    validate_p = profiles_sub.add_parser("validate")
    validate_p.add_argument("database")
    validate_p.set_defaults(func=_cmd_profiles_validate)
    fetch_p = profiles_sub.add_parser("fetch")
    fetch_p.add_argument("--catalog", default="catalog/references.json")
    fetch_p.add_argument("--cache", default="reference-artifacts")
    fetch_p.add_argument("--offline", action="store_true")
    fetch_p.set_defaults(func=_cmd_profiles_fetch)
    rebuild_p = profiles_sub.add_parser("rebuild")
    rebuild_p.add_argument("--catalog", default="catalog/references.json")
    rebuild_p.add_argument("--cache", default="reference-artifacts")
    rebuild_p.add_argument("--database", required=True)
    rebuild_p.add_argument("--d8")
    rebuild_p.add_argument("--android-jar")
    rebuild_p.add_argument("--offline", action="store_true")
    rebuild_p.set_defaults(func=_cmd_profiles_rebuild)

    sbom_p = sub.add_parser("sbom")
    sbom_p.add_argument("input")
    sbom_p.add_argument("--output", required=True)
    sbom_p.set_defaults(func=_cmd_sbom)

    scan_p = sub.add_parser("scan")
    scan_p.add_argument("path")
    scan_p.add_argument("--profiles")
    scan_p.add_argument("--vulnerabilities", action="store_true")
    scan_p.add_argument("--max-unknown-classes", type=int, default=None)
    scan_p.set_defaults(func=_cmd_scan)
    correlate_p = sub.add_parser("correlate")
    correlate_p.add_argument("input")
    correlate_p.set_defaults(func=_cmd_correlate)
    for command in (inspect_p, identify_p, scan_p):
        command.add_argument('--no-relationships', action='store_true', help='skip structural and published relationships')
        command.add_argument('--no-calls', action='store_true', help='skip explicit invocation extraction')
        command.add_argument('--no-grouping', action='store_true', help='skip unattributed clustering')
    for command in (scan_p, correlate_p, identify_p):
        if command is not identify_p:
            command.add_argument("--format", choices=["json", "table"], default="json")
            command.add_argument("--output")
        command.add_argument("--osv-scanner")
        command.add_argument("--osv-scanner-sha256", help="optional SHA-256 pin for the selected executable")
        command.add_argument("--osv-db")
        command.add_argument("--offline", action="store_true", help="prohibit advisory database downloads (assessment always runs offline)")
        command.add_argument("--osv-timeout", type=float, default=60)
        command.add_argument("--max-database-age-days", type=float, default=30)
        command.add_argument("--no-potential", action="store_true")
        command.add_argument("--max-potential", type=int, default=100)
        command.add_argument("--min-identity-score", type=float, default=0.75,
                             help="minimum component score for advisory attribution (0 to 1; default: 0.75)")
    advisories = sub.add_parser("vulnerabilities")
    actions = advisories.add_subparsers(dest="advisory_command", required=True)
    for name in ("provision", "update", "validate"):
        action = actions.add_parser(name)
        action.add_argument("--database", required=True)
        if name != "validate":
            action.add_argument("--ecosystem", choices=["Maven"], default="Maven")
        if name == "provision":
            action.add_argument("--archive", required=True)
            action.add_argument("--fetched-at")
        if name == "validate":
            action.add_argument("--max-database-age-days", type=float, default=30)
        action.set_defaults(func=_cmd_advisories)
    return parser


def main(argv: list[str] | None = None) -> int:
    # JSON and table output must preserve non-ASCII descriptors on Windows,
    # including when stdout is a pipe rather than an interactive terminal.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (InputError, ProfileError, LibIdentifierError, OSError, ValueError) as exc:
        print(f"libidentifier: {exc}", file=sys.stderr)
        return 2 if isinstance(exc, InputError) else 3


if __name__ == "__main__":
    raise SystemExit(main())
