from __future__ import annotations

import json

from libidentifier.api import identify
from libidentifier.cli import main
from libidentifier.profiles.catalog import load_catalog
from libidentifier.profiles.fetcher import fetch_catalog, rebuild_database

from conftest import lib_classes, make_apk, make_dex


def _catalog(path, ref, sha256):
    data = {
        "schema_version": 1,
        "fingerprint_algorithm": "dex-shape-v1-defs+elf-identity-v1",
        "references": [
            {
                "purl": "pkg:maven/example/libcatalog@1.0.0",
                "url": ref.resolve().as_uri(),
                "sha256": sha256,
                "license": "Apache-2.0",
            }
        ],
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_catalog_fetch_and_offline_rebuild(tmp_path):
    ref = tmp_path / "libcatalog.dex"
    ref.write_bytes(make_dex(lib_classes("lib/catalog", 6)))
    import hashlib

    digest = hashlib.sha256(ref.read_bytes()).hexdigest()
    catalog_path = _catalog(tmp_path / "references.json", ref, digest)
    cache = tmp_path / "cache"
    db = tmp_path / "profiles.sqlite"

    catalog = load_catalog(catalog_path)
    fetched = fetch_catalog(catalog, cache)
    assert fetched[0]["status"] == "downloaded"
    rebuilt = rebuild_database(catalog_path, cache_dir=cache, database=db, offline=True)

    assert rebuilt[0]["purl"] == "pkg:maven/example/libcatalog@1.0.0"
    apk = make_apk(tmp_path / "sample.apk", {"classes.dex": make_dex(lib_classes("lib/catalog", 6))})
    result = identify(apk, profiles=db)
    assert [c.name for c in result.components] == ["libcatalog"]


def test_cli_identify_uses_env_default_profiles(tmp_path, monkeypatch):
    ref = tmp_path / "libcatalog.dex"
    ref.write_bytes(make_dex(lib_classes("lib/catalog", 6)))
    import hashlib

    catalog_path = _catalog(tmp_path / "references.json", ref, hashlib.sha256(ref.read_bytes()).hexdigest())
    db = tmp_path / "profiles.sqlite"
    rebuild_database(catalog_path, cache_dir=tmp_path / "cache", database=db)
    apk = make_apk(tmp_path / "sample.apk", {"classes.dex": make_dex(lib_classes("lib/catalog", 6))})
    out = tmp_path / "out.json"
    monkeypatch.setenv("LIBIDENTIFIER_PROFILES", str(db))

    assert main(["identify", str(apk), "--format", "json", "--output", str(out)]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["components"][0]["name"] == "libcatalog"
