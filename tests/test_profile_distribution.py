"""Portable release assets, explicit acquisition and failed-install rollback."""
import gzip
import hashlib
import io
import json
from pathlib import Path
from urllib.error import URLError

import pytest

from libidentifier import install_profiles, package_profiles, validate_profiles
from libidentifier.cli import main
from libidentifier.errors import ProfileError
from libidentifier.profiles import distribution as release
from libidentifier.profiles.store import sha256_file


@pytest.fixture
def assets(demo_db, tmp_path):
    folder = tmp_path / "release"
    package_profiles(demo_db, output_dir=folder, snapshot_version="test-preview.1",
                     source_revision="a" * 40)
    return folder


def manifest(folder):
    return json.loads((folder / "profiles-manifest.json").read_text())


def rewrite(folder, data):
    (folder / "profiles-manifest.json").write_text(json.dumps(data), encoding="utf-8")


def test_package_is_portable_nonmutating_and_repeatable(demo_db, assets, tmp_path):
    original = sha256_file(demo_db)
    data = manifest(assets)
    again = tmp_path / "again"
    package_profiles(demo_db, output_dir=again, snapshot_version="test-preview.1",
                     source_revision="a" * 40)
    assert sha256_file(demo_db) == original
    assert {p.name for p in assets.iterdir()} == {"profiles.sqlite.gz", "profiles-manifest.json", "SHA256SUMS"}
    for path in assets.iterdir():
        assert path.read_bytes() == (again / path.name).read_bytes()
    assert data["database_schema_version"] == 2
    assert data["schema_version"] == 1
    assert data["coverage"]["library_release"] == 2
    body = gzip.decompress((assets / "profiles.sqlite.gz").read_bytes())
    assert str(tmp_path).encode() not in body
    assert b'"path"' not in body
    assert hashlib.sha256(body).hexdigest() == data["database"]["sha256"]
    for line in (assets / "SHA256SUMS").read_text().splitlines():
        digest, filename = line.split("  ")
        assert sha256_file(assets / filename) == digest


def test_local_offline_install_no_network_and_explicit_replace(assets, tmp_path, monkeypatch):
    monkeypatch.setattr(release, "_https_open", lambda *a, **k: pytest.fail("unexpected network"))
    target = tmp_path / "installed.sqlite"
    source = assets / "profiles-manifest.json"
    data = install_profiles(source, database=target, offline=True,
                            manifest_sha256=sha256_file(source))
    assert sha256_file(target) == data["database"]["sha256"]
    validation = validate_profiles(target)
    assert validation["status"] == "valid"
    assert validation["counts"] == data["coverage"]
    assert validation["database_id"] == data["snapshot_version"]
    with pytest.raises(ProfileError, match="already exists"):
        install_profiles(source, database=target, offline=True)
    install_profiles(source, database=target, offline=True, replace=True)
    assert not list(tmp_path.glob(".profile-install-*"))


def test_https_streamed_acquisition_and_manifest_pin(assets, tmp_path, monkeypatch):
    requests = []

    class Response(io.BytesIO):
        def geturl(self):
            return "https://release.example/asset"

    def open_url(url, *, timeout):
        requests.append((url, timeout))
        return Response((assets / url.rsplit("/", 1)[-1]).read_bytes())

    monkeypatch.setattr(release, "_https_open", open_url)
    target = tmp_path / "installed.sqlite"
    data = install_profiles("https://release.example/profiles-manifest.json", database=target,
                            manifest_sha256=sha256_file(assets / "profiles-manifest.json"))
    assert [u for u, _ in requests] == ["https://release.example/profiles-manifest.json",
                                      "https://release.example/profiles.sqlite.gz"]
    assert sha256_file(target) == data["database"]["sha256"]


@pytest.mark.parametrize("changes", [
    {"requires_engine": ">=999"}, {"requires_engine": "invalid spec"},
    {"database_schema_version": 1}, {"schema_version": True},
    {"fingerprint_algorithm": "dex-shape-v1"}, {"snapshot_version": "../escape"},
    {"asset": {"filename": "../escape"}}, {"coverage": []},
    {"asset": {"filename": "profiles.sqlite.gz", "size_bytes": True, "sha256": "0" * 64}},
])
def test_invalid_incompatible_manifest_never_replaces(assets, tmp_path, changes):
    data = manifest(assets)
    data.update(changes)
    rewrite(assets, data)
    target = tmp_path / "existing.sqlite"
    target.write_bytes(b"preserve existing installation")
    with pytest.raises(ProfileError):
        install_profiles(assets / "profiles-manifest.json", database=target, offline=True, replace=True)
    assert target.read_bytes() == b"preserve existing installation"


def test_checksums_limits_and_corrupt_sqlite_preserve_target(assets, tmp_path):
    target = tmp_path / "installed.sqlite"
    target.write_bytes(b"old")
    source = assets / "profiles-manifest.json"
    with pytest.raises(ProfileError, match="manifest SHA"):
        install_profiles(source, database=target, replace=True, manifest_sha256="0" * 64)
    with pytest.raises(ProfileError, match="size limit"):
        install_profiles(source, database=target, replace=True, max_download_bytes=1)
    data = manifest(assets)
    archive = assets / "profiles.sqlite.gz"
    archive.write_bytes(archive.read_bytes()[:-1])
    with pytest.raises(ProfileError, match="mismatch"):
        install_profiles(source, database=target, replace=True)
    # Both hashes can be consistent with invalid content: SQLite validation is independent.
    invalid = b"not a database"
    archive.write_bytes(gzip.compress(invalid))
    data["asset"].update(size_bytes=archive.stat().st_size, sha256=sha256_file(archive))
    data["database"].update(size_bytes=len(invalid), sha256=hashlib.sha256(invalid).hexdigest())
    rewrite(assets, data)
    with pytest.raises(ProfileError, match="profile database"):
        install_profiles(source, database=target, replace=True)
    assert target.read_bytes() == b"old"
    assert not list(tmp_path.glob(".profile-install-*"))


def test_decompression_limit_and_inventory_mismatch(assets, tmp_path):
    data = manifest(assets)
    data["database"]["size_bytes"] = 16
    rewrite(assets, data)
    target = tmp_path / "installed.sqlite"
    with pytest.raises(ProfileError, match="size limit"):
        install_profiles(assets / "profiles-manifest.json", database=target)
    data = manifest(assets)
    data["database"]["size_bytes"] = len(gzip.decompress((assets / "profiles.sqlite.gz").read_bytes()))
    data["coverage"]["library_family"] += 1
    rewrite(assets, data)
    with pytest.raises(ProfileError, match="inventory"):
        install_profiles(assets / "profiles-manifest.json", database=target)
    assert not target.exists()


def test_offline_https_redirect_download_failure_and_manifest_limit(tmp_path, monkeypatch):
    target = tmp_path / "installed.sqlite"
    monkeypatch.setattr(release, "_https_open", lambda *a, **k: pytest.fail("offline download"))
    with pytest.raises(ProfileError, match="offline"):
        install_profiles(database=target, offline=True)
    with pytest.raises(ProfileError, match="HTTPS"):
        install_profiles("http://example/profiles-manifest.json", database=target)

    class Response(io.BytesIO):
        def geturl(self):
            return "http://downgrade.example/manifest"

    monkeypatch.setattr(release, "_https_open", lambda *a, **k: Response(b"{}"))
    with pytest.raises(ProfileError, match="redirected"):
        install_profiles(database=target)
    def failure(*a, **k):
        raise URLError("unavailable")
    monkeypatch.setattr(release, "_https_open", failure)
    with pytest.raises(ProfileError, match="download failed"):
        install_profiles(database=target)
    local = tmp_path / "manifest.json"
    local.write_bytes(b" " * (release.MAX_MANIFEST_BYTES + 1))
    with pytest.raises(ProfileError, match="size limit"):
        install_profiles(local, database=target, offline=True)


def test_concurrent_destination_is_not_overwritten(assets, tmp_path, monkeypatch):
    target = tmp_path / "installed.sqlite"
    operation = "rename" if release.os.name == "nt" else "link"
    publish = getattr(release.os, operation)
    def concurrent(source, destination):
        target.write_bytes(b"created concurrently")
        return publish(source, destination)
    monkeypatch.setattr(release.os, operation, concurrent)
    with pytest.raises(ProfileError):
        install_profiles(assets / "profiles-manifest.json", database=target)
    assert target.read_bytes() == b"created concurrently"


def test_release_cli_package_install_and_errors(demo_db, tmp_path, capsys):
    folder = tmp_path / "cli-release"
    assert main(["profiles", "package", "--database", str(demo_db), "--output-dir", str(folder),
                 "--snapshot-version", "cli-preview", "--source-revision", "b" * 40]) == 0
    assert json.loads(capsys.readouterr().out)["snapshot_version"] == "cli-preview"
    target = tmp_path / "cli.sqlite"
    assert main(["profiles", "install", "--manifest", str(folder / "profiles-manifest.json"),
                 "--database", str(target), "--offline"]) == 0
    capsys.readouterr()
    assert main(["profiles", "install", "--database", str(target)]) == 3
    assert "explicit" in capsys.readouterr().err
    with pytest.raises(ProfileError, match="already exists"):
        package_profiles(demo_db, output_dir=folder, snapshot_version="same", source_revision="b" * 40)
