"""Explicit reference artifact fetching and catalog rebuild support."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import urllib.request
from pathlib import Path

from ..config import FINGERPRINT_ALGORITHM
from ..errors import ProfileError
from .builder import build_profile, validate_database
from .catalog import CatalogReference, ReferenceCatalog, artifact_filename, load_catalog, resolve_reference_url
from .store import sha256_file


def cache_path(cache_dir: str | Path, ref: CatalogReference) -> Path:
    legacy = Path(cache_dir) / artifact_filename(ref)
    # Reuse old verified caches while isolating new artifacts by content hash.
    if legacy.is_file() and sha256_file(legacy) == ref.sha256:
        return legacy
    return Path(cache_dir) / ref.sha256 / artifact_filename(ref)


def fetch_reference(ref: CatalogReference, cache_dir: str | Path, *, offline: bool = False) -> dict:
    cache_root = Path(cache_dir)
    cache_root.mkdir(parents=True, exist_ok=True)
    dest = cache_path(cache_root, ref)
    dest.parent.mkdir(parents=True, exist_ok=True)
    url = resolve_reference_url(ref)
    if dest.exists():
        digest = sha256_file(dest)
        if digest.lower() != ref.sha256:
            raise ProfileError(f"cached reference hash mismatch for {dest}")
        return {"purl": ref.purl, "path": str(dest), "url": url, "sha256": digest, "status": "cached"}
    if offline:
        raise ProfileError(f"reference is not cached for offline rebuild: {ref.purl}")
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    try:
        with urllib.request.urlopen(url) as response, tmp.open("wb") as fh:
            shutil.copyfileobj(response, fh)
        digest = sha256_file(tmp)
        if digest.lower() != ref.sha256:
            tmp.unlink(missing_ok=True)
            raise ProfileError(f"downloaded reference hash mismatch for {ref.purl}")
        os.replace(tmp, dest)
    except OSError as exc:
        tmp.unlink(missing_ok=True)
        raise ProfileError(f"failed to fetch reference {ref.purl}: {exc}") from exc
    return {"purl": ref.purl, "path": str(dest), "url": url, "sha256": ref.sha256, "status": "downloaded"}


def fetch_catalog(catalog: ReferenceCatalog, cache_dir: str | Path, *, offline: bool = False) -> list[dict]:
    results = []
    for ref in catalog.references:
        row = fetch_reference(ref, cache_dir, offline=offline)
        if ref.pom_url:
            from dataclasses import replace
            pom_ref = replace(ref, url=ref.pom_url, sha256=ref.pom_sha256, pom_url=None, pom_sha256=None)
            fetched = fetch_reference(pom_ref, cache_dir, offline=offline)
            target = Path(row['path']).with_suffix('.pom')
            shutil.copyfile(fetched['path'], target)
            row['pom_sha256'] = fetched['sha256']
            row['pom_source'] = ref.pom_url
        results.append(row)
    return results


def rebuild_database(
    catalog_path: str | Path,
    *,
    cache_dir: str | Path,
    database: str | Path,
    d8: str | Path | None = None,
    android_jar: str | Path | None = None,
    offline: bool = False,
) -> list[dict]:
    catalog = load_catalog(catalog_path)
    fetched = fetch_catalog(catalog, cache_dir, offline=offline)
    output = Path(database)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=output.name + ".", suffix=".tmp", dir=output.parent)
    os.close(fd)
    tmp_db = Path(tmp_name)
    tmp_db.unlink(missing_ok=True)
    results: list[dict] = []
    try:
        for ref, fetched_item in zip(catalog.references, fetched):
            artifact = fetched_item['path']
            built = build_profile(
                artifact,
                purl=ref.purl,
                database=tmp_db,
                d8=d8,
                android_jar=android_jar,
                reference_sha256=ref.sha256,
            )
            # Keep reviewed origins inside the distributable database as well.
            from .store import connect_write
            conn = connect_write(tmp_db)
            try:
                with conn:
                    row = conn.execute('SELECT artifact_id,provenance_json FROM reference_artifact WHERE release_id=? AND sha256=?', (built.release_id, ref.sha256)).fetchone()
                    provenance = json.loads(row[1])
                    provenance.update({'url':resolve_reference_url(ref),'license':ref.license})
                    conn.execute('UPDATE reference_artifact SET provenance_json=? WHERE artifact_id=?', (json.dumps(provenance,sort_keys=True),row[0]))
                    if fetched_item.get('pom_source'):
                        for sha, body in conn.execute('SELECT source_sha256,body_json FROM published_metadata WHERE release_id=?', (built.release_id,)).fetchall():
                            metadata = json.loads(body)
                            metadata['source'] = fetched_item['pom_source']
                            conn.execute('UPDATE published_metadata SET body_json=? WHERE release_id=? AND source_sha256=?', (json.dumps(metadata,sort_keys=True),built.release_id,sha))
            finally:
                conn.close()
            results.append(
                {
                    **built.to_dict(),
                    "url": resolve_reference_url(ref),
                    "license": ref.license,
                    "fingerprint_algorithm": FINGERPRINT_ALGORITHM,
                }
            )
        validate_database(tmp_db)
        os.replace(tmp_db, output)
    except Exception:
        tmp_db.unlink(missing_ok=True)
        raise
    manifest = {
        "schema_version": 1,
        "catalog": str(Path(catalog_path)),
        "cache_dir": str(Path(cache_dir)),
        "database": str(output),
        "fingerprint_algorithm": FINGERPRINT_ALGORITHM,
        "references": results,
    }
    output.with_suffix(output.suffix + ".manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return results
