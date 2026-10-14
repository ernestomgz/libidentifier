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
    return Path(cache_dir) / artifact_filename(ref)


def fetch_reference(ref: CatalogReference, cache_dir: str | Path, *, offline: bool = False) -> dict:
    cache_root = Path(cache_dir)
    cache_root.mkdir(parents=True, exist_ok=True)
    dest = cache_path(cache_root, ref)
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
    return [fetch_reference(ref, cache_dir, offline=offline) for ref in catalog.references]


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
        by_purl = {item["purl"]: item for item in fetched}
        for ref in catalog.references:
            artifact = by_purl[ref.purl]["path"]
            built = build_profile(
                artifact,
                purl=ref.purl,
                database=tmp_db,
                d8=d8,
                android_jar=android_jar,
                reference_sha256=ref.sha256,
            )
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
