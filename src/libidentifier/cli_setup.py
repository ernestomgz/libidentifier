"""Consent-based setup for the managed CLI scan path; analysis APIs never call it."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile

from .cli_resources import supported_scanner
from .errors import AdvisoryError, InputError, ProfileError
from .profiles.builder import validate_database
from .profiles.distribution import install_profiles, _read_url
from .profiles.store import sha256_file
from .vulnerabilities.database import update_advisory_database, validate_advisory_database
from .vulnerabilities.models import VulnerabilityOptions
from .vulnerabilities.runner import verify_scanner
from .vulnerabilities.setup import discover_scanner


def resource_home():
    if override := os.environ.get("LIBIDENTIFIER_HOME"):
        return Path(override).expanduser().resolve()
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData/Local")
        return base / "LibIdentifier"
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "libidentifier"


def _step(label, operation):
    print(label + "...", end=" ", file=sys.stderr, flush=True)
    try:
        value = operation()
    except Exception:
        print("failed", file=sys.stderr)
        raise
    print("done", file=sys.stderr)
    return value


def _consent(args, missing, root):
    print("\nFirst-time setup\n\nThe following resources are missing:", file=sys.stderr)
    for name in missing:
        print("  - " + name, file=sys.stderr)
    print(f"\nDownloads will be stored in:\n  {root}\n\n"
          "Your APK will stay on this computer.\n"
          "Installed resources will be reused for future scans.\n", file=sys.stderr)
    if args.vulnerabilities and args.osv_db and not Path(args.osv_db).is_relative_to(root):
        print(f"Advisory database override:\n  {args.osv_db}\n", file=sys.stderr)
    if args.offline:
        print("Offline mode: downloads are prohibited.", file=sys.stderr)
        return False
    if args.yes:
        return True
    if not sys.stdin.isatty():
        print("Setup requires an interactive terminal or --yes; no resources downloaded.", file=sys.stderr)
        return False
    print("Download and set up these resources? [y/N]: ", end="", file=sys.stderr, flush=True)
    try:
        answer = sys.stdin.readline().strip().lower()
    except (EOFError, OSError):
        return False
    return answer in {"y", "yes"}


def _options(args, scanner):
    return VulnerabilityOptions(scanner, args.osv_db, scanner_sha256=args.osv_scanner_sha256,
                                timeout_seconds=args.osv_timeout)


def _verify(args, scanner):
    return verify_scanner(_options(args, scanner))


def _install_scanner(args, release, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix=".download-", dir=target.parent) as temporary:
            candidate = Path(temporary) / release.filename
            def download():
                with candidate.open("wb") as output:
                    _read_url(release.url, output, limit=128 * 1024 * 1024, timeout=args.osv_timeout)
            _step("Downloading OSV-Scanner", download)
            def checksum():
                if sha256_file(candidate) != release.sha256:
                    raise AdvisoryError("Downloaded OSV-Scanner checksum does not match the project pin",
                                        code="scanner_unapproved")
            _step("Verifying scanner checksum", checksum)
            candidate.chmod(0o755)
            _step("Checking scanner compatibility", lambda: _verify(args, candidate))
            if os.name == "nt":
                os.rename(candidate, target)  # Refuses a concurrently created destination.
            else:
                os.link(candidate, target)
    except ProfileError as error:
        raise AdvisoryError(str(error), code="scanner_download_failed") from error


def prepare_managed_scan(args):
    """Resolve resources for scan without --profiles/environment; return profile path.

    Consent applies only to missing resources. Existing invalid resources require
    explicit maintenance. Optional setup failures preserve library identification.
    """
    if not Path(args.path).exists():
        raise InputError(f"input does not exist: {args.path}")
    root = resource_home()
    profiles = root / "profiles/profiles.sqlite"
    profile_missing = not profiles.exists()
    if not profile_missing:
        validate_database(profiles)
    missing = ["Library profiles: official preview snapshot"] if profile_missing else []
    scanner_missing = database_missing = False
    release = None
    args._setup_error = None
    if args.vulnerabilities:
        args.osv_db = str(Path(args.osv_db).resolve() if args.osv_db else root / "advisory-db")
        try:
            if args.osv_scanner:
                args.osv_scanner = str(Path(args.osv_scanner).resolve())
                _verify(args, args.osv_scanner)
            else:
                release = supported_scanner()
                if args.osv_scanner_sha256 and args.osv_scanner_sha256.lower() != release.sha256:
                    raise AdvisoryError("Requested hash disagrees with the managed scanner pin; "
                                        "use --osv-scanner for an explicit override", code="scanner_unapproved")
                args.osv_scanner_sha256 = release.sha256
                target = root / "tools/osv-scanner" / release.version / release.filename
                # Reuse a discovered executable only if its bytes match the project pin.
                if not target.exists():
                    try:
                        discovered = discover_scanner()
                        if sha256_file(discovered) == release.sha256:
                            target = discovered
                    except (AdvisoryError, OSError):
                        pass
                args.osv_scanner = str(target)
                scanner_missing = not target.exists()
                if scanner_missing:
                    missing.append(f"OSV-Scanner: project-supported {release.filename} ({release.version})")
                else:
                    _verify(args, target)  # Includes hash validation before execution.
            database_missing = not Path(args.osv_db).exists()
            if database_missing:
                missing.append("Maven vulnerability database: current snapshot")
        except (AdvisoryError, OSError, ValueError) as error:
            args._setup_error = error if isinstance(error, AdvisoryError) else AdvisoryError(str(error), code="setup_failed")

    accepted = _consent(args, missing, root) if missing else False
    if profile_missing:
        if not accepted:
            raise ProfileError("Library profiles are required. Run scan interactively or with --yes, "
                               "or supply local --profiles. --offline prohibits setup downloads.")
        _step("Downloading and validating library profiles", lambda: install_profiles(database=profiles))
    if args.vulnerabilities and args._setup_error is None:
        optional_missing = scanner_missing or database_missing
        if optional_missing and not accepted:
            args._setup_error = AdvisoryError("Vulnerability setup was not authorized or resources are missing "
                                             "in offline mode; identification is retained", code="setup_not_performed")
        elif optional_missing:
            try:
                if scanner_missing:
                    _install_scanner(args, release, Path(args.osv_scanner))
                # Never refresh any existing directory, even an empty/corrupt one.
                if database_missing and not Path(args.osv_db).exists():
                    _step("Downloading vulnerability data", lambda: update_advisory_database(
                        args.osv_db, timeout_seconds=args.osv_timeout))
                    _step("Validating vulnerability data", lambda: validate_advisory_database(
                        args.osv_db, max_age_days=args.max_database_age_days))
            except (AdvisoryError, ProfileError, OSError, ValueError) as error:
                args._setup_error = error if isinstance(error, AdvisoryError) else AdvisoryError(str(error), code="setup_failed")
    # The single consent decision is final. No later assessment path may provision.
    args.offline = True
    if accepted:
        print("\nSetup complete." if args._setup_error is None else
              "\nLibrary profiles ready; vulnerability setup incomplete. Identification will continue.",
              file=sys.stderr)
    return profiles
