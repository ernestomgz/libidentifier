"""Bounded ZIP/APK traversal for untrusted archives."""

from __future__ import annotations

import hashlib
import posixpath
import stat
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath

from .config import IdentifyOptions
from .detect import detect_bytes
from .models import AnalysisError


@dataclass(frozen=True)
class ArchiveMember:
    name: str
    format: str
    data: bytes
    sha256: str


def _safe_member_name(name: str) -> bool:
    if "\x00" in name or "\\" in name:
        return False
    if name.startswith("/") or name.startswith("//"):
        return False
    if len(name) >= 2 and name[1] == ":":
        return False
    normalized = posixpath.normpath(name)
    if normalized == "." or normalized.startswith("../") or normalized == "..":
        return False
    parts = PurePosixPath(normalized).parts
    return ".." not in parts


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0o170000
    return mode == stat.S_IFLNK


def _interesting_by_path(name: str) -> bool:
    lowered = name.lower()
    base = PurePosixPath(lowered).name
    return (
        (base.startswith("classes") and base.endswith(".dex"))
        or (lowered.startswith("lib/") and lowered.endswith(".so"))
        or lowered.endswith("/pom.properties")
        or lowered == "androidmanifest.xml"
        or base in {"libflutter.so", "libapp.so"}
    )


def read_selected_members(path, options: IdentifyOptions) -> tuple[list[ArchiveMember], list[AnalysisError]]:
    errors: list[AnalysisError] = []
    members: list[ArchiveMember] = []
    total = 0
    with zipfile.ZipFile(path) as zf:
        infos = sorted(zf.infolist(), key=lambda i: i.filename)
        if len(infos) > options.max_archive_members:
            raise ValueError("archive has too many members")
        for info in infos:
            name = info.filename
            if info.is_dir():
                continue
            if not _safe_member_name(name):
                errors.append(AnalysisError("unsafe_member_path", name, "ZIP member path is unsafe", "warning"))
                continue
            if _is_symlink(info):
                errors.append(AnalysisError("unsupported_member", name, "ZIP symlink member skipped", "warning"))
                continue
            if info.flag_bits & 0x1:
                errors.append(AnalysisError("encrypted_member", name, "Encrypted ZIP member skipped", "warning"))
                continue
            if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                errors.append(AnalysisError("unsupported_compression", name, "Unsupported ZIP compression skipped", "warning"))
                continue
            if info.file_size > options.max_member_uncompressed_bytes:
                errors.append(AnalysisError("member_too_large", name, "ZIP member exceeds size limit", "warning"))
                continue
            if info.compress_size and info.file_size / max(info.compress_size, 1) > options.max_compression_ratio:
                errors.append(AnalysisError("compression_ratio", name, "ZIP member compression ratio exceeds limit", "warning"))
                continue

            selected = _interesting_by_path(name)
            with zf.open(info) as fh:
                head = fh.read(8)
                fmt = detect_bytes(head, name=name)
                selected = selected or fmt in {"dex", "elf"}
                if not selected:
                    continue
                rest = fh.read(options.max_member_uncompressed_bytes + 1)
            data = head + rest
            if len(data) > options.max_member_uncompressed_bytes:
                errors.append(AnalysisError("member_too_large", name, "ZIP member exceeds size limit", "warning"))
                continue
            total += len(data)
            if total > options.max_total_selected_uncompressed_bytes:
                errors.append(AnalysisError("archive_budget", name, "Selected archive members exceed total byte limit", "warning"))
                break
            fmt = detect_bytes(data, name=name)
            if fmt in {"unknown", "zip"} and name.lower().endswith("/pom.properties"):
                fmt = "metadata"
            members.append(ArchiveMember(name=name, format=fmt, data=data, sha256=hashlib.sha256(data).hexdigest()))
    return members, errors

