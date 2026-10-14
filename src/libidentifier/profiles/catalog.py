"""Reference catalog parsing and validation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from ..config import FINGERPRINT_ALGORITHM
from ..errors import ProfileError
from .store import family_id_from_purl


@dataclass(frozen=True)
class CatalogReference:
    purl: str
    sha256: str
    repository: str | None = None
    url: str | None = None
    path: str | None = None
    license: str | None = None
    notes: str | None = None

    @property
    def version(self) -> str:
        return family_id_from_purl(self.purl)[3]


@dataclass(frozen=True)
class ReferenceCatalog:
    path: Path
    schema_version: int
    fingerprint_algorithm: str
    references: list[CatalogReference]


def _maven_path(purl: str) -> str:
    body = purl[4:] if purl.startswith("pkg:") else purl
    if "@" not in body:
        raise ProfileError("catalog purl must include a version")
    before_version, version = body.rsplit("@", 1)
    if not before_version.startswith("maven/"):
        raise ProfileError(f"cannot derive Maven URL for non-Maven purl: {purl}")
    coordinate = before_version[len("maven/") :]
    parts = coordinate.split("/")
    if len(parts) < 2:
        raise ProfileError(f"Maven purl must include group and artifact: {purl}")
    artifact = parts[-1]
    group_path = "/".join(quote(part, safe="") for part in parts[:-1])
    artifact_q = quote(artifact, safe="")
    version_q = quote(version, safe="")
    return f"{group_path}/{artifact_q}/{version_q}/{artifact_q}-{version_q}"


def resolve_reference_url(ref: CatalogReference) -> str:
    if ref.url:
        return ref.url
    if ref.path:
        return Path(ref.path).resolve().as_uri()
    if ref.repository in {"maven-central", "mavenCentral"}:
        return "https://repo.maven.apache.org/maven2/" + _maven_path(ref.purl) + _artifact_extension(ref)
    if ref.repository in {"google-maven", "googleMaven"}:
        return "https://dl.google.com/dl/android/maven2/" + _maven_path(ref.purl) + _artifact_extension(ref)
    raise ProfileError(f"catalog reference needs url/path or known repository: {ref.purl}")


def _artifact_extension(ref: CatalogReference) -> str:
    if ref.url:
        suffix = Path(ref.url.split("?", 1)[0]).suffix
        if suffix:
            return suffix
    return ".jar"


def artifact_filename(ref: CatalogReference) -> str:
    url = resolve_reference_url(ref)
    name = Path(url.split("?", 1)[0]).name
    if not name:
        raise ProfileError(f"cannot determine artifact filename for {ref.purl}")
    return name


def load_catalog(path: str | Path) -> ReferenceCatalog:
    catalog_path = Path(path)
    try:
        data = json.loads(catalog_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ProfileError(f"cannot read catalog: {catalog_path}") from exc
    except json.JSONDecodeError as exc:
        raise ProfileError(f"catalog is not valid JSON: {exc}") from exc
    if data.get("schema_version") != 1:
        raise ProfileError("catalog schema version is incompatible")
    algorithm = data.get("fingerprint_algorithm", FINGERPRINT_ALGORITHM)
    if algorithm != FINGERPRINT_ALGORITHM:
        raise ProfileError("catalog fingerprint algorithm is incompatible")
    refs = []
    seen: set[str] = set()
    for item in data.get("references", []):
        purl = item.get("purl")
        sha256 = item.get("sha256")
        if not isinstance(purl, str) or "@" not in purl:
            raise ProfileError("catalog reference purl must be a versioned string")
        if not isinstance(sha256, str) or len(sha256) != 64:
            raise ProfileError(f"catalog reference has invalid sha256: {purl}")
        if purl in seen:
            raise ProfileError(f"duplicate catalog purl: {purl}")
        seen.add(purl)
        family_id_from_purl(purl)
        ref = CatalogReference(
            purl=purl,
            sha256=sha256.lower(),
            repository=item.get("repository"),
            url=item.get("url"),
            path=item.get("path"),
            license=item.get("license"),
            notes=item.get("notes"),
        )
        resolve_reference_url(ref)
        refs.append(ref)
    if not refs:
        raise ProfileError("catalog contains no references")
    return ReferenceCatalog(
        path=catalog_path,
        schema_version=1,
        fingerprint_algorithm=algorithm,
        references=refs,
    )
