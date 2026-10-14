"""SQLite schema and compatibility validation."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from ..config import FINGERPRINT_ALGORITHM, DATABASE_SCHEMA_VERSION
from ..errors import ProfileError
from ..purl import reference_coordinates

DDL = """
CREATE TABLE IF NOT EXISTS db_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS library_family (
  family_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  ecosystem TEXT,
  package_name TEXT
);
CREATE TABLE IF NOT EXISTS library_release (
  release_id TEXT PRIMARY KEY,
  family_id TEXT NOT NULL REFERENCES library_family(family_id),
  version TEXT NOT NULL,
  purl TEXT NOT NULL,
  source_sha256 TEXT NOT NULL,
  source_format TEXT NOT NULL,
  provenance_json TEXT NOT NULL,
  fingerprint_algorithm TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dex_shape (
  release_id TEXT NOT NULL REFERENCES library_release(release_id),
  digest TEXT NOT NULL,
  multiplicity INTEGER NOT NULL CHECK(multiplicity > 0),
  PRIMARY KEY (release_id, digest)
);
CREATE INDEX IF NOT EXISTS idx_dex_shape_digest ON dex_shape(digest);
CREATE TABLE IF NOT EXISTS dex_class (
  release_id TEXT NOT NULL REFERENCES library_release(release_id),
  digest TEXT NOT NULL,
  descriptor TEXT NOT NULL,
  multiplicity INTEGER NOT NULL CHECK(multiplicity > 0),
  PRIMARY KEY (release_id, digest, descriptor)
);
CREATE INDEX IF NOT EXISTS idx_dex_class_digest ON dex_class(digest);
CREATE TABLE IF NOT EXISTS elf_identity (
  release_id TEXT NOT NULL REFERENCES library_release(release_id),
  abi TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  build_id TEXT,
  soname TEXT,
  symbol_digest TEXT,
  PRIMARY KEY (release_id, abi, sha256)
);
CREATE INDEX IF NOT EXISTS idx_elf_sha256 ON elf_identity(sha256);
"""


def initialize(conn: sqlite3.Connection) -> None:
    conn.executescript(DDL)
    meta = {
        "schema_version": str(DATABASE_SCHEMA_VERSION),
        "fingerprint_algorithm": FINGERPRINT_ALGORITHM,
        "database_id": "local",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }
    for key, value in meta.items():
        conn.execute("INSERT OR IGNORE INTO db_meta(key, value) VALUES (?, ?)", (key, value))


def validate(conn: sqlite3.Connection) -> None:
    rows = dict(conn.execute("SELECT key, value FROM db_meta"))
    if rows.get("schema_version") != str(DATABASE_SCHEMA_VERSION):
        raise ProfileError("profile database schema version is incompatible")
    if rows.get("fingerprint_algorithm") != FINGERPRINT_ALGORITHM:
        raise ProfileError("profile database fingerprint algorithm is incompatible")
    required = {
        "db_meta",
        "library_family",
        "library_release",
        "dex_shape",
        "dex_class",
        "elf_identity",
    }
    actual = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing = required - actual
    if missing:
        raise ProfileError(f"profile database is missing tables: {', '.join(sorted(missing))}")
    incompatible = conn.execute(
        "SELECT COUNT(*) FROM library_release WHERE fingerprint_algorithm != ?",
        (FINGERPRINT_ALGORITHM,),
    ).fetchone()[0]
    if incompatible:
        raise ProfileError("profile database contains incompatible release fingerprints; rebuild it")
    for purl, version, name, namespace in conn.execute(
        "SELECT r.purl, r.version, f.name, f.package_name FROM library_release r JOIN library_family f USING(family_id)"
    ):
        try:
            _, expected_namespace, expected_name, expected_version, _ = reference_coordinates(purl)
        except ValueError as exc:
            raise ProfileError(f"profile database has an invalid reference PURL: {exc}") from exc
        if (version, name, namespace) != (expected_version, expected_name, expected_namespace):
            raise ProfileError("profile database identity disagrees with reference PURL; rebuild it")
