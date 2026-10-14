"""Qualified OSV-Scanner 2.7.0 adapter. Fixed offline arguments, no APK input."""
from __future__ import annotations
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from ..errors import AdvisoryError
from .database import digest
from .models import ScannerRecord

PINNED_VERSION = '2.7.0'
# Official GitHub release asset SHA-256 digests, independently retrieved at qualification.
APPROVED_HASHES = {
    'nt': {'9964ed64ec9a387391eb4cc006ad5c531154821aef29b793e02c448de4686438',
           '3e630381c1f1fd3c9c4d447e6ff2ef6c737083371722773db8337eead0f97962'},
    'posix': {'160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b',
              '4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7'},
}


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
    if sha not in APPROVED_HASHES.get(os.name, set()):
        raise AdvisoryError('Executable is not an approved OSV-Scanner 2.7.0 release asset', code='scanner_unapproved')
    with tempfile.TemporaryDirectory(prefix='libidentifier-osv-') as temporary:
        work = Path(temporary)
        code, output, errors = _execute([str(path), '--version'], work=work, cache=work,
                                        timeout=options.timeout_seconds, max_bytes=65536)
    if code != 0 or f'osv-scanner version: {PINNED_VERSION}' not in output.splitlines():
        raise AdvisoryError(f'Unsupported OSV-Scanner version: {output} {errors}', code='scanner_incompatible')
    return ScannerRecord(str(path), PINNED_VERSION, sha)


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
        code, output, errors = _execute(command, work=work, cache=stage / 'cache',
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
