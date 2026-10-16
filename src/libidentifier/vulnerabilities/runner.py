"""Capability-checked OSV-Scanner v2 adapter. Fixed offline arguments, no APK input.

The installed executable is a trusted local dependency. Its distribution channel
is not inferred from its filename/hash; callers may pin a publisher-verified hash.
"""
from __future__ import annotations
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from ..errors import AdvisoryError
from .database import digest, SUPPORTED_ECOSYSTEMS
from .models import ScannerRecord

SUPPORTED_MAJOR = 2
REQUIRED_FLAGS = ('offline', 'no-resolve', 'no-call-analysis', 'all-packages',
                  'all-vulns', 'format', 'config', 'lockfile')
_VERSION = re.compile(r'^osv-scanner version:\s*v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?)\s*$', re.MULTILINE)


def _environment(cache, work):
    env = {k: v for k, v in os.environ.items() if k.upper() in {'SYSTEMROOT', 'WINDIR', 'PATH', 'LANG', 'LC_ALL'}}
    env.update({'OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY': str(cache), 'TEMP': str(work), 'TMP': str(work), 'TMPDIR': str(work)})
    return env


def _execute(command, *, work, cache, timeout, max_bytes):
    stdout, stderr = work / 'stdout.json', work / 'stderr.txt'
    deadline = time.monotonic() + timeout
    with stdout.open('wb') as out, stderr.open('wb') as err:
        process = subprocess.Popen(command, shell=False, cwd=work, env=_environment(cache, work),
                                   stdin=subprocess.DEVNULL, stdout=out, stderr=err)
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise AdvisoryError('OSV-Scanner timed out', code='scanner_timeout')
                if stdout.stat().st_size + stderr.stat().st_size > max_bytes:
                    raise AdvisoryError('OSV-Scanner output exceeds byte limit', code='scanner_output_limit')
                try:
                    process.wait(timeout=min(0.05, max(0.001, deadline - time.monotonic())))
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    if stdout.stat().st_size + stderr.stat().st_size > max_bytes:
        raise AdvisoryError('OSV-Scanner output exceeds byte limit', code='scanner_output_limit')
    return process.returncode, stdout.read_text(encoding='utf-8'), stderr.read_text(encoding='utf-8', errors='replace')


def verify_scanner(options):
    path = Path(options.scanner).resolve()
    if not path.is_file():
        raise AdvisoryError(f'OSV-Scanner executable is missing: {path}', code='scanner_missing')
    sha = digest(path)
    if options.scanner_sha256 and sha != options.scanner_sha256.lower():
        raise AdvisoryError(f'OSV-Scanner checksum mismatch: {path}; expected {options.scanner_sha256.lower()}, actual {sha}',
                            code='scanner_unapproved')
    with path.open('rb') as source:
        header = source.read(4)
    if not (header.startswith(b'MZ') if os.name == 'nt' else header == b'\x7fELF'):
        raise AdvisoryError(f'OSV-Scanner must be a native Windows/Linux executable: {path}', code='scanner_unapproved')
    with tempfile.TemporaryDirectory(prefix='libidentifier-osv-') as temporary:
        work = Path(temporary)
        try:
            code, output, errors = _execute([str(path), '--version'], work=work, cache=work,
                                            timeout=options.timeout_seconds, max_bytes=65536)
            versions = _VERSION.findall(output + '\n' + errors)
            if code != 0 or len(versions) != 1 or int(versions[0].split('.')[0]) != SUPPORTED_MAJOR:
                raise AdvisoryError(f'Unsupported OSV-Scanner at {path}; requires an identifiable v2 release. '
                                    f'Reported: {(output + errors)[:2000]}', code='scanner_incompatible')
            version = versions[0]
            code, help_text, errors = _execute([str(path), 'scan', 'source', '--offline', '--help'],
                work=work, cache=work, timeout=options.timeout_seconds, max_bytes=256 * 1024)
            missing = [flag for flag in REQUIRED_FLAGS if not re.search(
                r'(?<![\w-])--' + re.escape(flag) + r'(?=[\s=,]|$)', help_text + '\n' + errors)]
            # Some earlier v2 releases returned 128 even for explicit help.
            if code not in (0, 128) or missing:
                detail = ', '.join('--' + flag for flag in missing) or f'help exit {code}'
                raise AdvisoryError(f'OSV-Scanner {version} at {path} lacks the required offline interface: {detail}',
                                    code='scanner_incompatible')
        except OSError as exc:
            raise AdvisoryError(f'Cannot execute OSV-Scanner at {path}: {exc}', code='scanner_incompatible') from exc
    return ScannerRecord(str(path), version, sha)


def _cache_view(stage, work):
    """Expose verified archives in both official v2 cache layouts, without migration."""
    cache = work / 'cache'
    for ecosystem in sorted(SUPPORTED_ECOSYSTEMS):
        archive = stage / 'cache/osv-scalibr' / ecosystem / 'all.zip'
        if not archive.is_file():
            continue
        for prefix in ('osv-scalibr', 'osv-scanner'):
            target = cache / prefix / ecosystem / 'all.zip'
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(archive, target)
            except OSError:
                shutil.copyfile(archive, target)
    return cache


def match_versions(scanner, stage, packages, options):
    with tempfile.TemporaryDirectory(prefix='libidentifier-osv-') as temporary:
        work = Path(temporary)
        dependency_file = work / 'osv-scanner.json'
        dependency_file.write_text(json.dumps({'results': [{'packages': [{'package': p} for p in packages]}]}), encoding='utf-8')
        config = work / 'config.toml'
        config.write_text('', encoding='utf-8')
        command = [scanner.path, 'scan', 'source', '--offline', '--no-resolve',
                   '--no-call-analysis', 'go', '--no-call-analysis', 'rust',
                   '--all-packages', '--all-vulns', '--format', 'json', '--config', str(config),
                   '--lockfile', 'osv-scanner:' + str(dependency_file)]
        code, output, errors = _execute(command, work=work, cache=_cache_view(stage, work),
                                        timeout=options.timeout_seconds, max_bytes=options.max_output_bytes)
        if code not in (0, 1):
            raise AdvisoryError(f'OSV-Scanner failed (exit {code}): {errors[:4000]}', code='scanner_failed')
        try:
            data = json.loads(output)
            found = {}
            for source in data['results']:
                for item in source['packages']:
                    package = item['package']
                    key = (package['ecosystem'], package['name'], package['version'])
                    if key in found:
                        raise ValueError('duplicate returned package')
                    found[key] = [v for v in item.get('vulnerabilities', []) if not v.get('withdrawn')]
                    for advisory in found[key]:
                        if not isinstance(advisory.get('id'), str) or not advisory['id']:
                            raise ValueError('advisory lacks a valid ID')
                        if not any(entry.get('package', {}).get('ecosystem') == key[0]
                                   and entry.get('package', {}).get('name') == key[1]
                                   for entry in advisory.get('affected', [])):
                            raise ValueError('advisory package does not match queried component')
            expected = {(p['ecosystem'], p['name'], p['version']) for p in packages}
            if set(found) != expected:
                raise ValueError('OSV returned package inventory does not equal generated input')
            if (code == 1) != bool(any(found.values())):
                raise ValueError('exit status contradicts returned advisories')
            return found
        except (ValueError, KeyError, TypeError) as exc:
            raise AdvisoryError(f'Invalid OSV result: {exc}', code='scanner_invalid_output') from exc
