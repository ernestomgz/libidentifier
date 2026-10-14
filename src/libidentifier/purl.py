"""Small PURL coordinate reader for trusted reference identities.

This does not resolve packages or validate ecosystem-specific release names.
"""

from __future__ import annotations

import re
from urllib.parse import unquote


def reference_coordinates(purl: str) -> tuple[str, str | None, str, str, str]:
    """Return type, namespace, name, decoded version and versionless PURL."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        raise ValueError("reference PURL must start with pkg:")
    if re.search(r"\s|%(?![0-9a-fA-F]{2})", purl):
        raise ValueError("reference PURL has invalid escaping or whitespace")
    coordinate = re.split(r"[?#]", purl, maxsplit=1)[0]
    suffix = purl[len(coordinate):]
    if coordinate.count("@") != 1:
        raise ValueError("reference PURL must include one explicit version")
    base, encoded_version = coordinate.rsplit("@", 1)
    parts = base[4:].split("/")
    if len(parts) < 2 or not re.fullmatch(r"[a-z][a-z0-9.+-]*", parts[0]):
        raise ValueError("reference PURL has invalid package type")
    decoded = [unquote(part, errors="strict") for part in parts[1:]]
    version = unquote(encoded_version, errors="strict")
    if not version or any(not part or part in {".", ".."} or "/" in part for part in decoded):
        raise ValueError("reference PURL needs a package name and non-empty version")
    if parts[0] == "maven" and len(decoded) != 2:
        raise ValueError("Maven PURL must include group and artifact")
    return parts[0], "/".join(decoded[:-1]) or None, decoded[-1], version, base + suffix


def family_purl(purl: str) -> str:
    return reference_coordinates(purl)[4]
