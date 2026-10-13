"""LIEF ELF identity extraction."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class ElfFeature:
    sha256: str
    abi: str
    soname: str | None
    build_id: str | None
    imported_symbols: tuple[str, ...]
    exported_symbols: tuple[str, ...]
    symbol_digest: str | None


def _name(value) -> str | None:
    if value is None:
        return None
    n = getattr(value, "name", None)
    return str(n) if n else None


def parse_elf(data: bytes) -> ElfFeature:
    import lief

    parsed = lief.ELF.parse(list(data))
    if parsed is None:
        raise ValueError("LIEF returned no ELF object")
    header = getattr(parsed, "header", None)
    machine = str(getattr(header, "machine_type", "unknown")).split(".")[-1].lower()
    cls = str(getattr(header, "identity_class", "")).split(".")[-1].lower()
    abi = ":".join(x for x in (machine, cls) if x)
    soname = None
    try:
        soname = parsed.soname
    except Exception:
        soname = None
    build_id = None
    for note in getattr(parsed, "notes", []) or []:
        desc = getattr(note, "description", None)
        if desc and "build" in str(getattr(note, "type", "")).lower():
            try:
                build_id = bytes(desc).hex()
            except Exception:
                build_id = str(desc)
            break
    imported = tuple(sorted(n for n in (_name(s) for s in getattr(parsed, "imported_symbols", []) or []) if n))
    exported = tuple(sorted(n for n in (_name(s) for s in getattr(parsed, "exported_symbols", []) or []) if n))
    symbol_digest = None
    if imported or exported:
        payload = "\n".join(["I:" + x for x in imported] + ["E:" + x for x in exported]).encode()
        symbol_digest = hashlib.sha256(b"elf-identity-v1\0" + payload).hexdigest()
    return ElfFeature(
        sha256=hashlib.sha256(data).hexdigest(),
        abi=abi or "unknown",
        soname=soname,
        build_id=build_id,
        imported_symbols=imported,
        exported_symbols=exported,
        symbol_digest=symbol_digest,
    )

