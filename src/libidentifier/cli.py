"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .api import identify, inspect
from .errors import InputError, LibIdentifierError, ProfileError
from .models import ScanResult
from .profiles.builder import build_profile, validate_database
from .sbom import export_cyclonedx
from .version import __version__


def _write_result(result: ScanResult, args) -> None:
    if args.format == "json":
        payload = result.to_json() + "\n"
        if args.output:
            Path(args.output).write_text(payload, encoding="utf-8")
        else:
            sys.stdout.write(payload)
    else:
        for component in result.components:
            version = component.version or ",".join(component.version_candidates) or "unknown"
            sys.stdout.write(f"{component.name}\t{version}\t{component.identity_confidence}\t{component.score}\n")
        if not result.components:
            sys.stdout.write("No profile-backed components identified.\n")


def _cmd_inspect(args) -> int:
    result = inspect(args.path)
    _write_result(result, args)
    return 4 if any(e.severity == "error" for e in result.errors) else 0


def _cmd_identify(args) -> int:
    result = identify(args.path, profiles=args.profiles)
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


def _cmd_sbom(args) -> int:
    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    export_cyclonedx(ScanResult.from_dict(data), args.output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="libidentifier")
    parser.add_argument("--version", action="version", version=f"libidentifier {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    inspect_p = sub.add_parser("inspect")
    inspect_p.add_argument("path")
    inspect_p.add_argument("--format", choices=["json", "table"], default="json")
    inspect_p.add_argument("--output")
    inspect_p.set_defaults(func=_cmd_inspect)

    identify_p = sub.add_parser("identify")
    identify_p.add_argument("path")
    identify_p.add_argument("--profiles", required=True)
    identify_p.add_argument("--format", choices=["json", "table"], default="json")
    identify_p.add_argument("--output")
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

    sbom_p = sub.add_parser("sbom")
    sbom_p.add_argument("input")
    sbom_p.add_argument("--output", required=True)
    sbom_p.set_defaults(func=_cmd_sbom)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (InputError, ProfileError, LibIdentifierError, OSError, ValueError) as exc:
        print(f"libidentifier: {exc}", file=sys.stderr)
        return 2 if isinstance(exc, InputError) else 3


if __name__ == "__main__":
    raise SystemExit(main())

