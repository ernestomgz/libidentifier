"""CLI convenience setup. Network access is confined to missing-DB provisioning."""
from __future__ import annotations

import os
import platform
from pathlib import Path

from ..errors import AdvisoryError
from .database import update_advisory_database
from .models import VulnerabilityOptions
from .runner import verify_scanner


def _scanner_names(system, machine):
    arch = 'arm64' if machine.lower() in {'arm64', 'aarch64'} else 'amd64'
    other = 'amd64' if arch == 'arm64' else 'arm64'
    if system == 'nt':
        return ('osv-scanner.exe', 'osv-scanner',
                f'osv-scanner_windows_{arch}.exe', f'osv-scanner_windows_{other}.exe')
    return ('osv-scanner', 'osv-scanner.exe',
            f'osv-scanner_linux_{arch}', f'osv-scanner_linux_{other}')


def discover_scanner(explicit=None):
    """Resolve an explicit path, otherwise search PATH then the working directory.

    Discovery does not execute anything. Approval is verified before provisioning
    or invoking the scanner; an unapproved first match is never silently skipped.
    """
    if explicit is not None:
        return Path(explicit).resolve()
    names = _scanner_names(os.name, platform.machine())
    directories = [Path(p) for p in os.environ.get('PATH', '').split(os.pathsep) if p]
    directories.append(Path.cwd())
    for directory in directories:
        for name in names:
            candidate = directory / name
            if candidate.is_file() and (os.name == 'nt' or os.access(candidate, os.X_OK)):
                return candidate.resolve()
    raise AdvisoryError('OSV-Scanner not found in PATH or the working directory', code='scanner_missing')


def user_database():
    if os.name == 'nt':
        base = Path(os.environ.get('LOCALAPPDATA') or Path.home() / 'AppData' / 'Local')
        return base / 'LibIdentifier' / 'advisory-db'
    return Path(os.environ.get('XDG_CACHE_HOME') or Path.home() / '.cache') / 'libidentifier' / 'advisory-db'


def discover_database(explicit=None):
    if explicit is not None:
        return Path(explicit).resolve()
    local = Path.cwd() / 'advisory-db'
    return local if local.exists() else user_database()


def prepare_options(args):
    """Verify scanner first; only a wholly absent database may be downloaded."""
    scanner = discover_scanner(args.osv_scanner)
    database = discover_database(args.osv_db)
    options = VulnerabilityOptions(scanner, database, timeout_seconds=args.osv_timeout,
        max_database_age_days=args.max_database_age_days, discover_unknown_versions=not args.no_potential,
        max_potential_advisories_per_component=args.max_potential, min_identity_score=args.min_identity_score)
    verify_scanner(options)
    # Never replace an existing empty, incomplete, corrupt or stale directory.
    # Maintenance commands provide explicit repair/update authorization.
    if not database.exists() and not args.offline:
        try:
            update_advisory_database(database, timeout_seconds=args.osv_timeout)
        except (AdvisoryError, OSError, ValueError) as exc:
            raise AdvisoryError(f'Maven advisory database provisioning failed: {exc}',
                                code='database_provision_failed') from exc
    return options
