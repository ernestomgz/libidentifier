"""Magic-byte format detection."""

from __future__ import annotations

from pathlib import Path


def detect_bytes(data: bytes, *, name: str | None = None) -> str:
    if data.startswith(b"dex\n") and len(data) >= 8:
        return "dex"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08"):
        lowered = (name or "").lower()
        if lowered.endswith(".apk"):
            return "apk"
        if lowered.endswith(".aar"):
            return "aar"
        if lowered.endswith(".jar"):
            return "jar"
        return "zip"
    return "unknown"


def detect_file(path: str | Path, read_size: int = 8) -> str:
    p = Path(path)
    with p.open("rb") as fh:
        head = fh.read(read_size)
    return detect_bytes(head, name=p.name)

