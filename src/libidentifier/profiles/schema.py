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
  fingerprint_algorithm TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reference_artifact (
  artifact_id TEXT PRIMARY KEY,
  release_id TEXT NOT NULL REFERENCES library_release(release_id),
  sha256 TEXT NOT NULL,
  format TEXT NOT NULL,
  provenance_json TEXT NOT NULL,
  UNIQUE(release_id,sha256)
);
CREATE TABLE IF NOT EXISTS build_variant (
  variant_id TEXT PRIMARY KEY,
  artifact_id TEXT NOT NULL REFERENCES reference_artifact(artifact_id),
  output_sha256 TEXT NOT NULL,
  configuration_json TEXT NOT NULL,
  is_primary INTEGER NOT NULL CHECK(is_primary IN (0,1))
);
CREATE TABLE IF NOT EXISTS fingerprint (
  fingerprint_id TEXT PRIMARY KEY,
  algorithm TEXT NOT NULL,
  digest TEXT NOT NULL,
  UNIQUE(algorithm,digest)
);
CREATE TABLE IF NOT EXISTS fingerprint_occurrence (
  variant_id TEXT NOT NULL REFERENCES build_variant(variant_id),
  fingerprint_id TEXT NOT NULL REFERENCES fingerprint(fingerprint_id),
  locator TEXT NOT NULL,
  multiplicity INTEGER NOT NULL CHECK(multiplicity>0),
  PRIMARY KEY(variant_id,fingerprint_id,locator)
);
CREATE INDEX IF NOT EXISTS idx_fingerprint_digest ON fingerprint(digest);
CREATE INDEX IF NOT EXISTS idx_occurrence_fingerprint ON fingerprint_occurrence(fingerprint_id);
CREATE INDEX IF NOT EXISTS idx_artifact_release ON reference_artifact(release_id);
CREATE VIEW IF NOT EXISTS dex_class AS
  SELECT a.release_id, f.digest, o.locator AS descriptor, o.multiplicity
  FROM fingerprint_occurrence o JOIN fingerprint f USING(fingerprint_id)
  JOIN build_variant v USING(variant_id) JOIN reference_artifact a USING(artifact_id)
  WHERE f.algorithm='dex-shape-v2' AND v.is_primary=1;
CREATE VIEW IF NOT EXISTS dex_shape AS
  SELECT release_id,digest,SUM(multiplicity) AS multiplicity FROM dex_class
  GROUP BY release_id,digest;
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
CREATE TABLE IF NOT EXISTS published_metadata (
  release_id TEXT NOT NULL REFERENCES library_release(release_id),
  source_sha256 TEXT NOT NULL,
  body_json TEXT NOT NULL,
  PRIMARY KEY(release_id,source_sha256)
);
"""


def initialize(conn: sqlite3.Connection) -> None:
    if conn.execute("SELECT 1 FROM sqlite_master WHERE name='db_meta'").fetchone():
        version = conn.execute("SELECT value FROM db_meta WHERE key='schema_version'").fetchone()
        if not version or version[0] != str(DATABASE_SCHEMA_VERSION):
            raise ProfileError('profile database schema is incompatible; rebuild with profiles rebuild')
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
        raise ProfileError("profile database schema version is incompatible; rebuild with profiles rebuild")
    if rows.get("fingerprint_algorithm") != FINGERPRINT_ALGORITHM:
        raise ProfileError("profile database fingerprint algorithm is incompatible")
    required = {
        "db_meta",
        "library_family",
        "library_release",
        "dex_shape",
        "dex_class",
        "elf_identity",
        "reference_artifact", "build_variant", "fingerprint", "fingerprint_occurrence", "published_metadata",
    }
    actual = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')")}
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
