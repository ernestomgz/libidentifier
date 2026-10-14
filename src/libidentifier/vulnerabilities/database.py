"""Immutable local OSV archive snapshots and package-only SQLite discovery.

Only update_advisory_database accesses the network. No version comparison here.
"""
from __future__ import annotations
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import uuid
import zipfile
from datetime import datetime, timezone
from contextlib import closing
from pathlib import Path
from urllib.parse import quote
from ..errors import AdvisoryError
from .models import AdvisoryDatabaseRecord

SUPPORTED_ECOSYSTEMS = frozenset({'Maven'})
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def _index(archives, destination):
    conn = sqlite3.connect(destination)
    try:
        conn.executescript('CREATE TABLE advisory(id TEXT PRIMARY KEY, body TEXT NOT NULL, withdrawn INTEGER NOT NULL); CREATE TABLE package(ecosystem TEXT, name TEXT, id TEXT REFERENCES advisory(id), PRIMARY KEY(ecosystem,name,id));')
        for ecosystem, path in sorted(archives.items()):
            if path.stat().st_size > MAX_ARCHIVE_BYTES:
                raise AdvisoryError('OSV archive exceeds compressed byte limit', code='database_invalid')
            with zipfile.ZipFile(path) as archive:
                infos = archive.infolist()
                if len(infos) > 100000 or sum(i.file_size for i in infos) > MAX_UNCOMPRESSED_BYTES:
                    raise AdvisoryError('OSV archive exceeds record/byte limits', code='database_invalid')
                ids = set()
                for info in infos:
                    if info.is_dir():
                        continue
                    if info.flag_bits & 1 or info.file_size > MAX_RECORD_BYTES:
                        raise AdvisoryError('Unsupported or oversized OSV record', code='database_invalid')
                    with archive.open(info) as stream:
                        raw = stream.read(MAX_RECORD_BYTES + 1)
                    if len(raw) > MAX_RECORD_BYTES:
                        raise AdvisoryError('OSV record exceeds byte limit', code='database_invalid')
                    record = json.loads(raw)
                    aid = record.get('id')
                    if not isinstance(aid, str) or not aid or aid in ids:
                        raise AdvisoryError('Invalid or duplicate OSV advisory ID', code='database_invalid')
                    ids.add(aid)
                    affected = record.get('affected')
                    if not isinstance(affected, list) or not isinstance(record.get('modified'), str):
                        raise AdvisoryError('OSV record lacks affected/modified fields', code='database_invalid')
                    conn.execute('INSERT INTO advisory VALUES (?,?,?)', (aid, json.dumps(record, sort_keys=True), bool(record.get('withdrawn'))))
                    for entry in affected:
                        package = entry.get('package', {})
                        if package.get('ecosystem') == ecosystem:
                            if not isinstance(package.get('name'), str) or not package['name']:
                                raise AdvisoryError('Invalid OSV package coordinate', code='database_invalid')
                            conn.execute('INSERT OR IGNORE INTO package VALUES (?,?,?)', (ecosystem, package['name'], aid))
                if not ids:
                    raise AdvisoryError('Empty advisory archive does not establish database coverage', code='database_invalid')
        conn.commit()
    finally:
        conn.close()


def provision_advisory_database(database, *, archives, fetched_at=None, sources=None):
    """Import explicit local ecosystem ZIPs, then atomically publish a generation."""
    if not archives or not set(archives) <= SUPPORTED_ECOSYSTEMS:
        raise AdvisoryError('Only a nonempty Maven archive mapping is supported', code='ecosystem_unsupported')
    root = Path(database).resolve()
    generations = root / 'generations'
    if generations.is_symlink():
        raise AdvisoryError('Advisory generations directory must not be a symlink', code='database_invalid')
    generations.mkdir(parents=True, exist_ok=True)
    generation = uuid.uuid4().hex
    stage = generations / generation
    stage.mkdir()
    pointer_temp = root / (generation + '.tmp')
    try:
        copied = {}
        hashes = {}
        for ecosystem, source in archives.items():
            target = stage / 'cache' / 'osv-scalibr' / ecosystem / 'all.zip'
            target.parent.mkdir(parents=True)
            if Path(source).stat().st_size > MAX_ARCHIVE_BYTES:
                raise AdvisoryError('OSV archive exceeds byte limit', code='database_invalid')
            shutil.copyfile(source, target)
            copied[ecosystem] = target
            hashes[ecosystem] = digest(target)
        _index(copied, stage / 'index.sqlite')
        hashes['index'] = digest(stage / 'index.sqlite')
        stamp = fetched_at or datetime.fromtimestamp(min(Path(p).stat().st_mtime for p in archives.values()), timezone.utc).isoformat()
        manifest = {'schema_version': 1, 'generation': generation, 'fetched_at': stamp,
                    'ecosystems': sorted(archives), 'hashes': hashes,
                    'sources': sources or {eco: str(Path(src).resolve()) for eco, src in archives.items()}}
        (stage / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True), encoding='utf-8')
        # Validate every byte and timestamp before replacing the current generation.
        record = _validate_generation(stage, manifest, max_age_days=None)
        pointer_temp.write_text(json.dumps({'generation': generation, 'manifest_sha256': digest(stage / 'manifest.json')}), encoding='utf-8')
        os.replace(pointer_temp, root / 'CURRENT.json')
    except (OSError, ValueError, TypeError, AttributeError, sqlite3.Error, zipfile.BadZipFile, AdvisoryError) as exc:
        # The generated absolute target is confined to this database's generations.
        if stage.resolve().parent == generations.resolve():
            shutil.rmtree(stage)
        if isinstance(exc, AdvisoryError):
            raise
        raise AdvisoryError(f'Cannot provision advisory database: {exc}', code='database_invalid') from exc
    finally:
        pointer_temp.unlink(missing_ok=True)
    return record


def _validate_generation(stage, manifest, *, max_age_days):
    if manifest.get('schema_version') != 1 or manifest.get('generation') != stage.name:
        raise AdvisoryError('Advisory database schema/generation is incompatible', code='database_invalid')
    ecosystems = manifest.get('ecosystems', [])
    if not ecosystems or not set(ecosystems) <= SUPPORTED_ECOSYSTEMS:
        raise AdvisoryError('Unsupported advisory database ecosystems', code='database_invalid')
    fetched = datetime.fromisoformat(manifest['fetched_at'])
    if fetched.tzinfo is None:
        raise AdvisoryError('Database timestamp must include timezone', code='database_invalid')
    age = (datetime.now(timezone.utc) - fetched).total_seconds() / 86400
    if age < -1 / 1440:
        raise AdvisoryError('Database timestamp is in the future', code='database_invalid')
    expected = manifest['hashes']
    for key, path in [('index', stage / 'index.sqlite')] + [(eco, stage / 'cache/osv-scalibr' / eco / 'all.zip') for eco in ecosystems]:
        if path.is_symlink() or path.resolve().is_relative_to(stage.resolve()) is False or digest(path) != expected[key]:
            raise AdvisoryError(f'Advisory database hash mismatch: {key}', code='database_corrupt')
    with closing(sqlite3.connect(f'file:{quote(str((stage / "index.sqlite").resolve()).replace(chr(92), "/"))}?mode=ro&immutable=1', uri=True)) as conn:
        if conn.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise AdvisoryError('Corrupt advisory index', code='database_corrupt')
        conn.execute('SELECT id,body,withdrawn FROM advisory LIMIT 1').fetchall()
        conn.execute('SELECT ecosystem,name,id FROM package LIMIT 1').fetchall()
    record = AdvisoryDatabaseRecord(stage.name, manifest['fetched_at'], round(max(age, 0), 6), ecosystems, expected, manifest['sources'])
    if max_age_days is not None and age > max_age_days:
        raise AdvisoryError(f'Advisory database is stale ({age:.1f} days; maximum {max_age_days})', code='database_stale', database=record)
    return record


def open_snapshot(database, *, max_age_days=30):
    if max_age_days is not None and (not isinstance(max_age_days, (int, float)) or isinstance(max_age_days, bool)
                                    or not math.isfinite(max_age_days) or max_age_days <= 0):
        raise ValueError('max_age_days must be finite and positive, or None')
    root = Path(database).resolve()
    try:
        pointer = json.loads((root / 'CURRENT.json').read_text(encoding='utf-8'))
        generation = pointer['generation']
        if not re.fullmatch('[0-9a-f]{32}', generation):
            raise AdvisoryError('Invalid advisory database generation', code='database_invalid')
        stage = root / 'generations' / generation
        if not stage.resolve().is_relative_to(root) or digest(stage / 'manifest.json') != pointer['manifest_sha256']:
            raise AdvisoryError('Advisory manifest hash mismatch', code='database_corrupt')
        manifest = json.loads((stage / 'manifest.json').read_text(encoding='utf-8'))
        return _validate_generation(stage, manifest, max_age_days=max_age_days), stage
    except AdvisoryError:
        raise
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        raise AdvisoryError(f'Cannot use advisory database: {exc}', code='database_unavailable') from exc


def validate_advisory_database(database, *, max_age_days=30):
    return open_snapshot(database, max_age_days=max_age_days)[0]


def discover(stage, ecosystem, name, limit):
    path = stage / 'index.sqlite'
    uri = f'file:{quote(str(path.resolve()).replace(chr(92), "/"))}?mode=ro&immutable=1'
    with closing(sqlite3.connect(uri, uri=True)) as conn:
        args = (ecosystem, name)
        query = ' FROM package p JOIN advisory a ON p.id=a.id WHERE p.ecosystem=? AND p.name=? AND a.withdrawn=0'
        total = conn.execute('SELECT COUNT(*)' + query, args).fetchone()[0]
        records = [json.loads(row[0]) for row in conn.execute('SELECT a.body' + query + ' ORDER BY a.id LIMIT ?', (*args, limit))]
    return records, total


def update_advisory_database(database, *, ecosystems=('Maven',), timeout_seconds=60):
    """Explicit network maintenance. Failed downloads/publication preserve CURRENT."""
    from urllib.request import urlopen
    import tempfile
    if not ecosystems or not set(ecosystems) <= SUPPORTED_ECOSYSTEMS:
        raise AdvisoryError('Only Maven advisory updates are currently supported', code='ecosystem_unsupported')
    root = Path(database).resolve()
    root.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix='download-', dir=root) as temporary:
            archives, sources = {}, {}
            for ecosystem in sorted(set(ecosystems)):
                url = 'https://osv-vulnerabilities.storage.googleapis.com/' + quote(ecosystem, safe='') + '/all.zip'
                path = Path(temporary) / (ecosystem + '.zip')
                count = 0
                with urlopen(url, timeout=timeout_seconds) as source, path.open('wb') as target:
                    while chunk := source.read(1024 * 1024):
                        count += len(chunk)
                        if count > MAX_ARCHIVE_BYTES:
                            raise AdvisoryError('OSV download exceeds byte limit', code='database_invalid')
                        target.write(chunk)
                archives[ecosystem], sources[ecosystem] = path, url
            return provision_advisory_database(root, archives=archives, sources=sources)
    except (OSError, ValueError) as exc:
        raise AdvisoryError(f'Advisory update failed: {exc}', code='database_update_failed') from exc
