"""Transactional profile storage and read-only matching index queries."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import Counter
from pathlib import Path
from urllib.parse import quote

from ..config import FINGERPRINT_ALGORITHM
from ..models import ProfileDatabaseRecord
from .schema import initialize, validate


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def connect_write(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(Path(path))
    conn.execute("PRAGMA foreign_keys=ON")
    initialize(conn)
    validate(conn)
    return conn


def connect_readonly(path: str | Path) -> sqlite3.Connection:
    p = Path(path)
    uri = f"file:{quote(str(p.resolve()).replace(chr(92), '/'))}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    validate(conn)
    return conn


def database_record(path: str | Path | None) -> ProfileDatabaseRecord:
    if path is None:
        return ProfileDatabaseRecord()
    p = Path(path)
    conn = connect_readonly(p)
    try:
        rows = dict(conn.execute("SELECT key, value FROM db_meta"))
        count = conn.execute("SELECT COUNT(*) FROM library_release").fetchone()[0]
    finally:
        conn.close()
    return ProfileDatabaseRecord(
        id=rows.get("database_id"),
        version=rows.get("schema_version"),
        sha256=sha256_file(p),
        generated_at=rows.get("generated_at"),
        profile_count=int(count),
    )


def family_id_from_purl(purl: str) -> tuple[str, str, str | None, str]:
    body = purl
    if body.startswith("pkg:"):
        body = body[4:]
    if "@" not in body:
        raise ValueError("purl must include a version")
    before_version, version = body.rsplit("@", 1)
    if "/" in before_version:
        ecosystem, rest = before_version.split("/", 1)
    else:
        ecosystem, rest = "generic", before_version
    parts = rest.split("/")
    name = parts[-1]
    package_name = "/".join(parts[:-1]) or None
    family_id = hashlib.sha256(f"{ecosystem}:{package_name or ''}:{name}".encode()).hexdigest()[:16]
    ecosystem_label = "Maven" if ecosystem.lower() == "maven" else ecosystem
    return family_id, name, package_name, version if version else ""


def release_id(family_id: str, version: str, source_sha256: str) -> str:
    return hashlib.sha256(f"{family_id}:{version}:{source_sha256}".encode()).hexdigest()[:24]


def upsert_release(
    conn: sqlite3.Connection,
    *,
    purl: str,
    source_sha256: str,
    source_format: str,
    provenance: dict,
    dex_shapes: Counter[str] | None = None,
    elf_identity: dict | None = None,
) -> tuple[str, str, str]:
    family_id, name, package_name, version = family_id_from_purl(purl)
    rid = release_id(family_id, version, source_sha256)
    ecosystem = "Maven" if purl.startswith("pkg:maven/") else (purl[4:].split("/", 1)[0] if purl.startswith("pkg:") else None)
    with conn:
        existing = conn.execute(
            "SELECT source_sha256 FROM library_release WHERE purl=? AND version=?", (purl, version)
        ).fetchone()
        if existing and existing[0] != source_sha256:
            raise ValueError("conflicting source hash for same purl/version")
        conn.execute(
            "INSERT OR IGNORE INTO library_family(family_id, name, ecosystem, package_name) VALUES (?, ?, ?, ?)",
            (family_id, name, ecosystem, package_name),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO library_release(
              release_id, family_id, version, purl, source_sha256, source_format, provenance_json, fingerprint_algorithm
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rid,
                family_id,
                version,
                purl,
                source_sha256,
                source_format,
                json.dumps(provenance, sort_keys=True, separators=(",", ":")),
                FINGERPRINT_ALGORITHM,
            ),
        )
        if dex_shapes:
            for digest, count in sorted(dex_shapes.items()):
                conn.execute(
                    "INSERT OR REPLACE INTO dex_shape(release_id, digest, multiplicity) VALUES (?, ?, ?)",
                    (rid, digest, int(count)),
                )
        if elf_identity:
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


def release_rows(conn: sqlite3.Connection, release_ids: set[str]) -> dict[str, dict]:
    if not release_ids:
        return {}
    placeholders = ",".join("?" for _ in release_ids)
    rows = {}
    for row in conn.execute(
        f"""
        SELECT r.release_id, r.family_id, r.version, r.purl, r.source_sha256, r.source_format,
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
        }
    return rows

