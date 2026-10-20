"""Explicit profile release packaging and acquisition; never called by analysis."""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import zlib
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, build_opener

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import Version

from ..config import DATABASE_SCHEMA_VERSION, FINGERPRINT_ALGORITHM
from ..errors import ProfileError
from ..version import __version__
from .store import connect_readonly, sha256_file

DEFAULT_PROFILE_MANIFEST = (
    "https://github.com/ernestomgz/libidentifier/releases/download/"
    "profiles-2026.10.20-preview.1/profiles-manifest.json"
)
DEFAULT_ENGINE_REQUIREMENT = ">=0.2.0rc1,<0.3.0"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
MAX_DATABASE_BYTES = 2 * 1024 * 1024 * 1024
COUNTS = ("library_family", "library_release", "reference_artifact", "build_variant",
          "fingerprint", "fingerprint_occurrence", "published_metadata", "elf_identity")


def _compatible(requirement: str) -> None:
    if not isinstance(requirement, str) or not requirement.strip():
        raise ProfileError("requires_engine must be a nonempty PEP 440 specifier")
    try:
        supported = Version(__version__) in SpecifierSet(requirement, prereleases=True)
    except InvalidSpecifier as error:
        raise ProfileError("invalid engine compatibility specifier") from error
    if not supported:
        raise ProfileError(f"profile release requires engine {requirement}; installed {__version__}")


def _positive(value, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ProfileError(f"{label} must be a positive integer")
    return value


def _digest(value) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ProfileError("release SHA-256 must contain 64 lowercase hexadecimal characters")
    return value


def _inspect(database: Path) -> dict:
    connection = connect_readonly(database)
    try:
        if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ProfileError("profile database integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone():
            raise ProfileError("profile database has broken foreign keys")
        counts = {name: connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
                  for name in COUNTS}
        references = []
        for purl, digest, fmt, provenance in connection.execute(
            "SELECT r.purl,a.sha256,a.format,a.provenance_json FROM reference_artifact a "
            "JOIN library_release r USING(release_id) ORDER BY r.purl,a.sha256"
        ):
            source = json.loads(provenance)
            references.append({"purl": purl, "sha256": digest, "format": fmt,
                               **{key: source[key] for key in ("url", "license") if key in source}})
        return {"counts": counts, "references": references,
                "database_id": dict(connection.execute("SELECT key,value FROM db_meta"))["database_id"]}
    except (sqlite3.Error, ValueError, KeyError, TypeError) as error:
        raise ProfileError(f"cannot inspect profile release: {error}") from error
    finally:
        connection.close()


def validate_profiles(database) -> dict:
    """Validate a local database without downloads and return compatibility/inventory."""
    path = Path(database)
    inventory = _inspect(path)
    return {"status": "valid", "database_schema_version": DATABASE_SCHEMA_VERSION,
            "fingerprint_algorithm": FINGERPRINT_ALGORITHM,
            "sha256": sha256_file(path), "size_bytes": path.stat().st_size, **inventory}


def package_profiles(database, *, output_dir, snapshot_version: str, source_revision: str,
                     requires_engine: str = DEFAULT_ENGINE_REQUIREMENT) -> dict:
    """Create three portable assets in a new directory; source database is unchanged."""
    if not isinstance(snapshot_version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", snapshot_version):
        raise ProfileError("snapshot version must be a portable identifier of at most 100 characters")
    if not isinstance(source_revision, str) or not re.fullmatch(r"[0-9a-f]{40}", source_revision):
        raise ProfileError("source revision must be a full lowercase Git commit SHA")
    _compatible(requires_engine)
    target = Path(output_dir).absolute()
    if target.exists():
        raise ProfileError("release output directory already exists; use a new directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    source = connect_readonly(database)
    try:
        with tempfile.TemporaryDirectory(prefix=".profile-release-", dir=target.parent) as temporary:
            stage = Path(temporary)
            portable = stage / "profiles.sqlite"
            destination = sqlite3.connect(portable)
            try:
                source.backup(destination)
                # Local filesystem provenance is not a distribution contract.
                for artifact_id, body in destination.execute(
                    "SELECT artifact_id,provenance_json FROM reference_artifact"
                ).fetchall():
                    record = json.loads(body)
                    record = {key: record[key] for key in ("source_sha256", "url", "license") if key in record}
                    if "url" in record and urlsplit(record["url"]).scheme not in {"https", "http"}:
                        record.pop("url")
                    destination.execute("UPDATE reference_artifact SET provenance_json=? WHERE artifact_id=?",
                                        (json.dumps(record, sort_keys=True), artifact_id))
                for variant_id, body in destination.execute(
                    "SELECT variant_id,configuration_json FROM build_variant"
                ).fetchall():
                    record = json.loads(body)
                    record = {key: record[key] for key in (
                        "kind", "executable_sha256", "compiler_version", "compiler_version_status",
                        "android_jar_sha256", "arguments") if key in record}
                    if "arguments" in record:
                        record["arguments"] = ["<local-path>" if ("\\" in value or value.startswith("/"))
                                               else value for value in record["arguments"]]
                    destination.execute("UPDATE build_variant SET configuration_json=? WHERE variant_id=?",
                                        (json.dumps(record, sort_keys=True), variant_id))
                destination.execute("DELETE FROM db_meta WHERE key NOT IN ('schema_version','fingerprint_algorithm','generated_at')")
                destination.execute("INSERT INTO db_meta VALUES ('database_id',?)", (snapshot_version,))
                destination.commit()
                # Rebuild pages so removed path strings do not persist in free space.
                destination.execute("VACUUM")
            finally:
                destination.close()
            inventory = _inspect(portable)
            if not inventory["counts"]["library_release"]:
                raise ProfileError("cannot publish an empty reference catalog")
            compressed = stage / "profiles.sqlite.gz"
            with portable.open("rb") as reader, compressed.open("wb") as writer:
                with gzip.GzipFile(filename="", mode="wb", fileobj=writer, mtime=0) as archive:
                    shutil.copyfileobj(reader, archive)
            manifest = {
                "schema_version": 1, "kind": "libidentifier-profiles",
                "snapshot_version": snapshot_version, "requires_engine": requires_engine,
                "database_schema_version": DATABASE_SCHEMA_VERSION,
                "fingerprint_algorithm": FINGERPRINT_ALGORITHM,
                "producer": {"name": "libidentifier", "version": __version__, "source_revision": source_revision},
                "asset": {"filename": compressed.name, "size_bytes": compressed.stat().st_size,
                          "sha256": sha256_file(compressed)},
                "database": {"size_bytes": portable.stat().st_size, "sha256": sha256_file(portable)},
                "coverage": inventory["counts"], "references": inventory["references"],
                "limitations": ["Preview catalog; absence of a match does not establish absence of libraries.",
                                "Structural matches do not establish exact installed versions.",
                                "Catalog coverage and metadata are limited to the listed references."],
            }
            manifest_path = stage / "profiles-manifest.json"
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            (stage / "SHA256SUMS").write_text(
                f"{sha256_file(compressed)}  {compressed.name}\n"
                f"{sha256_file(manifest_path)}  {manifest_path.name}\n", encoding="ascii")
            portable.unlink()
            stage.rename(target)
            return manifest
    except (sqlite3.Error, ValueError, TypeError) as error:
        raise ProfileError(f"cannot package profiles: {error}") from error
    finally:
        source.close()


def _manifest(raw: bytes, max_download_bytes: int, max_database_bytes: int) -> dict:
    try:
        data = json.loads(raw)
        if (type(data["schema_version"]) is not int or data["schema_version"] != 1
                or data["kind"] != "libidentifier-profiles"):
            raise ProfileError("unsupported profile release manifest")
        if (type(data["database_schema_version"]) is not int or data["database_schema_version"] != DATABASE_SCHEMA_VERSION
                or data["fingerprint_algorithm"] != FINGERPRINT_ALGORITHM):
            raise ProfileError("profile release database/fingerprint version is incompatible")
        _compatible(data["requires_engine"])
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", data["snapshot_version"]):
            raise ProfileError("invalid snapshot version")
        if data["asset"]["filename"] != "profiles.sqlite.gz":
            raise ProfileError("profile asset filename must be profiles.sqlite.gz")
        for key, limit in (("asset", max_download_bytes), ("database", max_database_bytes)):
            _digest(data[key]["sha256"])
            if _positive(data[key]["size_bytes"], key + " size") > limit:
                raise ProfileError(f"profile {key} exceeds configured size limit")
        if not isinstance(data["coverage"], dict) or not isinstance(data["references"], list):
            raise ProfileError("invalid profile coverage/references")
        return data
    except (KeyError, TypeError, ValueError) as error:
        raise ProfileError(f"invalid profile release manifest: {error}") from error


class _HTTPSRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        if urlsplit(newurl).scheme != "https":
            raise ProfileError("profile download redirected outside HTTPS")
        return super().redirect_request(request, response, code, message, headers, newurl)


def _https_open(url, *, timeout):
    return build_opener(_HTTPSRedirect()).open(url, timeout=timeout)


def _read_url(url: str, output, *, limit: int, timeout: float) -> None:
    if urlsplit(url).scheme != "https":
        raise ProfileError("profile downloads require HTTPS")
    try:
        with _https_open(url, timeout=timeout) as response:
            if urlsplit(response.geturl()).scheme != "https":
                raise ProfileError("profile download redirected outside HTTPS")
            _copy_bounded(response, output, limit)
    except OSError as error:
        raise ProfileError(f"profile download failed: {error}") from error


def _copy_bounded(reader, writer, limit: int) -> int:
    count = 0
    while chunk := reader.read(min(1024 * 1024, limit - count + 1)):
        count += len(chunk)
        if count > limit:
            raise ProfileError("profile content exceeds declared/configured size limit")
        writer.write(chunk)
    return count


def install_profiles(manifest=DEFAULT_PROFILE_MANIFEST, *, database, offline: bool = False,
                     replace: bool = False, manifest_sha256: str | None = None,
                     timeout_seconds: float = 60, max_download_bytes: int = MAX_DOWNLOAD_BYTES,
                     max_database_bytes: int = MAX_DATABASE_BYTES) -> dict:
    """Explicit local import or HTTPS acquisition, with atomic validated replacement.

    Checksums establish integrity relative to the manifest. Authenticate its source
    via HTTPS or pin manifest_sha256 from a separately trusted release record.
    """
    import io
    import math

    _positive(max_download_bytes, "download limit")
    _positive(max_database_bytes, "database limit")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ProfileError("timeout must be finite and positive")
    if manifest_sha256 is not None:
        _digest(manifest_sha256)
    target = Path(database).absolute()
    if target.exists() and not replace:
        raise ProfileError("profile database already exists; explicit replace=True/--replace is required")
    # A Path always means local input, including paths containing a colon on Windows.
    remote = not isinstance(manifest, Path) and str(manifest).startswith(("https:", "http:"))
    if remote and offline:
        raise ProfileError("offline mode prohibits downloading a profile manifest")
    buffer = io.BytesIO()
    if remote:
        _read_url(str(manifest), buffer, limit=MAX_MANIFEST_BYTES, timeout=timeout_seconds)
    else:
        with Path(manifest).open("rb") as reader:
            _copy_bounded(reader, buffer, MAX_MANIFEST_BYTES)
    raw = buffer.getvalue()
    if manifest_sha256 and hashlib.sha256(raw).hexdigest() != manifest_sha256:
        raise ProfileError("profile manifest SHA-256 mismatch")
    data = _manifest(raw, max_download_bytes, max_database_bytes)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix=".profile-install-", dir=target.parent) as temporary:
            stage = Path(temporary)
            compressed = stage / "profiles.sqlite.gz"
            with compressed.open("wb") as writer:
                if remote:
                    _read_url(urljoin(str(manifest), data["asset"]["filename"]), writer,
                              limit=data["asset"]["size_bytes"], timeout=timeout_seconds)
                else:
                    with (Path(manifest).parent / data["asset"]["filename"]).open("rb") as reader:
                        _copy_bounded(reader, writer, data["asset"]["size_bytes"])
            if compressed.stat().st_size != data["asset"]["size_bytes"] or sha256_file(compressed) != data["asset"]["sha256"]:
                raise ProfileError("profile asset size/SHA-256 mismatch")
            portable = stage / "profiles.sqlite"
            with gzip.open(compressed, "rb") as reader, portable.open("wb") as writer:
                _copy_bounded(reader, writer, data["database"]["size_bytes"])
            if portable.stat().st_size != data["database"]["size_bytes"] or sha256_file(portable) != data["database"]["sha256"]:
                raise ProfileError("profile database size/SHA-256 mismatch")
            inventory = _inspect(portable)
            if inventory != {"counts": data["coverage"], "references": data["references"], "database_id": data["snapshot_version"]}:
                raise ProfileError("profile database does not match manifest inventory/snapshot")
            if replace:
                os.replace(portable, target)
            else:
                # Exclusive publication also refuses a destination created during download.
                    if os.name == "nt":
                        os.rename(portable, target)  # Windows rename refuses existing targets.
                    else:
                        os.link(portable, target)
            return data
    except (OSError, EOFError, zlib.error) as error:
        raise ProfileError(f"cannot install profile release: {error}") from error
