"""Transactional profile storage and read-only matching index queries."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import Counter
from pathlib import Path
from urllib.parse import quote

from ..config import FINGERPRINT_ALGORITHM
from ..errors import ProfileError
from ..models import ProfileDatabaseRecord
from ..purl import reference_coordinates
from .schema import initialize, validate


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def connect_write(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(Path(path))
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        initialize(conn)
        validate(conn)
        return conn
    except Exception:
        conn.close()
        raise


def connect_readonly(path: str | Path) -> sqlite3.Connection:
    p = Path(path)
    if not p.is_file():
        raise ProfileError(f"profile database does not exist or is not a file: {p}")
    uri = f"file:{quote(str(p.resolve()).replace(chr(92), '/'))}?mode=ro"
    conn = None
    try:
        conn = sqlite3.connect(uri, uri=True)
        validate(conn)
        return conn
    except (sqlite3.Error, ProfileError) as exc:
        if conn is not None:
            conn.close()
        raise ProfileError(f"cannot use profile database {p}: {exc}") from exc


def database_record(path: str | Path | None) -> ProfileDatabaseRecord:
    if path is None:
        return ProfileDatabaseRecord()
    p = Path(path)
    conn = connect_readonly(p)
    try:
        rows = dict(conn.execute("SELECT key, value FROM db_meta"))
        count = conn.execute("SELECT COUNT(*) FROM library_release").fetchone()[0]
    except sqlite3.Error as exc:
        raise ProfileError(f"cannot read profile database metadata {p}: {exc}") from exc
    finally:
        conn.close()
    try:
        digest = sha256_file(p)
    except OSError as exc:
        raise ProfileError(f"cannot read profile database {p}: {exc}") from exc
    return ProfileDatabaseRecord(
        id=rows.get("database_id"),
        version=rows.get("schema_version"),
        sha256=digest,
        generated_at=rows.get("generated_at"),
        profile_count=int(count),
    )


def family_id_from_purl(purl: str) -> tuple[str, str, str | None, str]:
    ecosystem, package_name, name, version, _ = reference_coordinates(purl)
    family_id = hashlib.sha256(f"{ecosystem}:{package_name or ''}:{name}".encode()).hexdigest()[:16]
    return family_id, name, package_name, version


def release_id(family_id: str, version: str, source_sha256: str) -> str:
    # Kept as an internal call shape; release identity no longer depends on bytes.
    return hashlib.sha256(f"{family_id}:{version}".encode()).hexdigest()[:24]


def upsert_release(
    conn: sqlite3.Connection,
    *,
    purl: str,
    source_sha256: str,
    source_format: str,
    provenance: dict,
    dex_shapes: Counter[str] | None = None,
    dex_classes: Counter[tuple[str, str]] | None = None,
    elf_identity: dict | None = None,
    build_configuration: dict | None = None,
    output_sha256: str | None = None,
    published_metadata: dict | None = None,
) -> tuple[str, str, str]:
    family_id, name, package_name, version = family_id_from_purl(purl)
    rid = release_id(family_id, version, source_sha256)
    ecosystem = "Maven" if purl.startswith("pkg:maven/") else (purl[4:].split("/", 1)[0] if purl.startswith("pkg:") else None)
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO library_family(family_id, name, ecosystem, package_name) VALUES (?, ?, ?, ?)",
            (family_id, name, ecosystem, package_name),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO library_release(
              release_id, family_id, version, purl, fingerprint_algorithm
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                rid,
                family_id,
                version,
                purl,
                FINGERPRINT_ALGORITHM,
            ),
        )
        aid = hashlib.sha256(f'{rid}:{source_sha256}'.encode()).hexdigest()[:24]
        configuration = json.dumps(build_configuration or {'kind': 'original'}, sort_keys=True, separators=(',', ':'))
        output_sha = output_sha256 or source_sha256
        vid = hashlib.sha256(f'{aid}:{output_sha}:{configuration}'.encode()).hexdigest()[:24]
        primary = not conn.execute("SELECT 1 FROM build_variant v JOIN reference_artifact a USING(artifact_id) WHERE a.release_id=? AND v.is_primary=1 AND ((a.format='elf')=?)", (rid, int(source_format == 'elf'))).fetchone()
        conn.execute('INSERT OR IGNORE INTO reference_artifact VALUES (?,?,?,?,?)',
                     (aid, rid, source_sha256, source_format, json.dumps(provenance, sort_keys=True)))
        conn.execute('INSERT OR IGNORE INTO build_variant VALUES (?,?,?,?,?)', (vid, aid, output_sha, configuration, int(primary)))
        occurrences = dex_classes or Counter({(d, ''): n for d, n in (dex_shapes or {}).items()})
        for (digest, descriptor), count in sorted(occurrences.items()):
            fid = hashlib.sha256(f'dex-shape-v2:{digest}'.encode()).hexdigest()
            conn.execute('INSERT OR IGNORE INTO fingerprint VALUES (?,?,?)', (fid, 'dex-shape-v2', digest))
            conn.execute('INSERT OR REPLACE INTO fingerprint_occurrence VALUES (?,?,?,?)', (vid, fid, descriptor, count))
        if published_metadata is not None:
            conn.execute('INSERT OR REPLACE INTO published_metadata VALUES (?,?,?)',
                         (rid, published_metadata['sha256'], json.dumps(published_metadata, sort_keys=True)))
        if elf_identity:
            fid = hashlib.sha256(f"elf-identity-v1:{elf_identity['sha256']}".encode()).hexdigest()
            conn.execute('INSERT OR IGNORE INTO fingerprint VALUES (?,?,?)', (fid, 'elf-identity-v1', elf_identity['sha256']))
            conn.execute('INSERT OR IGNORE INTO fingerprint_occurrence VALUES (?,?,?,1)', (vid, fid, elf_identity['abi']))
            conn.execute(
                """
                INSERT OR REPLACE INTO elf_identity(release_id, abi, sha256, build_id, soname, symbol_digest)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    rid,
                    elf_identity["abi"],
                    elf_identity["sha256"],
                    elf_identity.get("build_id"),
                    elf_identity.get("soname"),
                    elf_identity.get("symbol_digest"),
                ),
            )
        conn.execute(
            "INSERT OR REPLACE INTO db_meta(key, value) VALUES ('generated_at', datetime('now'))"
        )
    return rid, family_id, version


def dex_class_rows(conn: sqlite3.Connection, release_id: str, digests: set[str]) -> dict[str, Counter[str]]:
    if not digests:
        return {}
    placeholders = ",".join("?" for _ in digests)
    rows: dict[str, Counter[str]] = {}
    for digest, descriptor, multiplicity in conn.execute(
        f"""
        SELECT digest, descriptor, multiplicity
        FROM dex_class
        WHERE release_id=? AND digest IN ({placeholders})
        """,
        (release_id, *tuple(sorted(digests))),
    ):
        rows.setdefault(digest, Counter())[descriptor] += int(multiplicity)
    return rows


def release_rows(conn: sqlite3.Connection, release_ids: set[str]) -> dict[str, dict]:
    if not release_ids:
        return {}
    placeholders = ",".join("?" for _ in release_ids)
    rows = {}
    for row in conn.execute(
        f"""
        SELECT r.release_id, r.family_id, r.version, r.purl,
               (SELECT sha256 FROM reference_artifact WHERE release_id=r.release_id ORDER BY artifact_id LIMIT 1),
               (SELECT format FROM reference_artifact WHERE release_id=r.release_id ORDER BY artifact_id LIMIT 1),
               f.name, f.ecosystem, f.package_name
        FROM library_release r JOIN library_family f USING(family_id)
        WHERE r.release_id IN ({placeholders})
        """,
        tuple(sorted(release_ids)),
    ):
        rows[row[0]] = {
            "release_id": row[0],
            "family_id": row[1],
            "version": row[2],
            "purl": row[3],
            "source_sha256": row[4],
            "source_format": row[5],
            "name": row[6],
            "ecosystem": row[7],
            "package_name": row[8],
            "source_hashes": [x[0] for x in conn.execute('SELECT sha256 FROM reference_artifact WHERE release_id=?', (row[0],))],
        }
    return rows
