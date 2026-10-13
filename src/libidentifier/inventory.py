"""Input inspection and feature aggregation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from .archive import read_selected_members
from .config import FINGERPRINT_ALGORITHM, SCHEMA_VERSION, IdentifyOptions
from .detect import detect_bytes, detect_file
from .errors import InputError
from .extractors.dex import ClassFeature, parse_dex
from .extractors.elf import ElfFeature, parse_elf
from .extractors.metadata import framework_hints_from_names
from .models import (
    AnalysisError,
    ArtifactRecord,
    CoverageRecord,
    FrameworkHint,
    InputRecord,
    ProfileDatabaseRecord,
    ScanResult,
)


@dataclass
class Inventory:
    input: InputRecord
    analyzed_files: list[ArtifactRecord] = field(default_factory=list)
    dex_classes: list[ClassFeature] = field(default_factory=list)
    elf_features: list[tuple[ElfFeature, ArtifactRecord]] = field(default_factory=list)
    frameworks_detected: list[FrameworkHint] = field(default_factory=list)
    errors: list[AnalysisError] = field(default_factory=list)
    coverage: CoverageRecord = field(default_factory=CoverageRecord)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _coverage(inv: Inventory) -> None:
    dex_seen = any(a.format == "dex" for a in inv.analyzed_files)
    elf_seen = any(a.format == "elf" for a in inv.analyzed_files)
    dex_errors = any(e.code.startswith("dex_") or e.code == "parse_error" for e in inv.errors)
    elf_errors = any(e.code.startswith("elf_") for e in inv.errors)
    analyzed_count = {
        "dex": sum(1 for a in inv.analyzed_files if a.format == "dex" and a.status == "analyzed"),
        "elf": sum(1 for a in inv.analyzed_files if a.format == "elf" and a.status == "analyzed"),
        "classes": len(inv.dex_classes),
        "native_binaries": sum(1 for a in inv.analyzed_files if a.format == "elf" and a.status == "analyzed"),
    }
    skipped = dict(inv.coverage.skipped_count)
    for e in inv.errors:
        if e.code in {"member_too_large", "archive_budget"}:
            skipped["size_limit"] += 1
        elif e.code == "encrypted_member":
            skipped["encrypted"] += 1
        elif "unsupported" in e.code:
            skipped["unsupported"] += 1
        elif "parse" in e.code:
            skipped["parse_error"] += 1
    inv.coverage = CoverageRecord(
        dex="partial" if dex_seen and dex_errors else ("analyzed" if dex_seen else "absent"),
        elf="partial" if elf_seen and elf_errors else ("analyzed" if elf_seen else "absent"),
        metadata="partial" if inv.frameworks_detected else "absent",
        analyzed_count=analyzed_count,
        skipped_count=skipped,
        limitations=[],
    )


def _analyze_blob(inv: Inventory, data: bytes, *, fmt: str, container: str, member: str | None, path: str | None) -> None:
    digest = sha256_bytes(data)
    record = ArtifactRecord(member=member, format=fmt, sha256=digest, status="analyzed", path=path)
    if fmt == "dex":
        try:
            classes = parse_dex(data, container=container, member=member, sha256=digest)
            inv.dex_classes.extend(classes)
            inv.analyzed_files.append(record)
        except Exception as exc:
            inv.analyzed_files.append(ArtifactRecord(member=member, format=fmt, sha256=digest, status="failed", path=path))
            inv.errors.append(AnalysisError("dex_parse_error", member, str(exc), "error"))
    elif fmt == "elf":
        try:
            elf = parse_elf(data)
            inv.elf_features.append((elf, record))
            inv.analyzed_files.append(record)
        except Exception as exc:
            inv.analyzed_files.append(ArtifactRecord(member=member, format=fmt, sha256=digest, status="failed", path=path))
            inv.errors.append(AnalysisError("elf_parse_error", member, str(exc), "error"))


def _scan_file(path: Path, options: IdentifyOptions, *, top_input: Path | None = None, member_prefix: str | None = None) -> Inventory:
    fmt = detect_file(path)
    if fmt == "unknown":
        raise InputError(f"unsupported input format: {path}")
    input_path = top_input or path
    inv = Inventory(InputRecord(path=str(input_path), format=fmt, sha256=sha256_file(input_path), size=input_path.stat().st_size))
    if fmt in {"dex", "elf"}:
        _analyze_blob(inv, path.read_bytes(), fmt=fmt, container=str(input_path), member=member_prefix, path=str(path))
    elif fmt in {"apk", "zip", "jar", "aar"}:
        try:
            members, errors = read_selected_members(path, options)
            inv.errors.extend(errors)
        except Exception as exc:
            raise InputError(f"cannot inspect ZIP/APK: {exc}") from exc
        names = [m.name for m in members]
        for member in members:
            if member.format in {"dex", "elf"}:
                _analyze_blob(inv, member.data, fmt=member.format, container=str(input_path), member=member.name, path=None)
        inv.frameworks_detected = framework_hints_from_names(names, inv.dex_classes)
    _coverage(inv)
    return inv


def _merge(base: Inventory, child: Inventory) -> None:
    base.analyzed_files.extend(child.analyzed_files)
    base.dex_classes.extend(child.dex_classes)
    base.elf_features.extend(child.elf_features)
    base.frameworks_detected.extend(child.frameworks_detected)
    base.errors.extend(child.errors)


def inspect_path(path, options: IdentifyOptions) -> Inventory:
    p = Path(path)
    if not p.exists():
        raise InputError(f"input does not exist: {p}")
    if p.is_symlink():
        raise InputError("top-level symlink inputs are not supported")
    if p.is_file():
        return _scan_file(p, options)
    if not p.is_dir():
        raise InputError("input must be a file or directory")

    files = []
    root_depth = len(p.resolve().parts)
    total = 0
    for child in sorted(p.rglob("*")):
        if child.is_symlink() or not child.is_file():
            continue
        if len(child.resolve().parts) - root_depth > options.max_directory_depth:
            continue
        files.append(child)
        total += child.stat().st_size
        if len(files) > options.max_directory_files:
            raise InputError("directory contains too many files")
        if total > options.max_total_selected_uncompressed_bytes:
            raise InputError("directory exceeds scan byte budget")

    root_hash = hashlib.sha256()
    for child in files:
        root_hash.update(str(child.relative_to(p)).replace("\\", "/").encode())
        root_hash.update(sha256_file(child).encode())
    inv = Inventory(InputRecord(path=str(p), format="directory", sha256=root_hash.hexdigest(), size=total))
    for child in files:
        try:
            fmt = detect_file(child)
        except OSError as exc:
            inv.errors.append(AnalysisError("file_read_error", str(child.relative_to(p)), str(exc), "warning"))
            continue
        if fmt in {"unknown", "zip", "jar", "aar"}:
            continue
        try:
            child_inv = _scan_file(child, options, top_input=p, member_prefix=str(child.relative_to(p)).replace("\\", "/"))
            _merge(inv, child_inv)
        except InputError as exc:
            inv.errors.append(AnalysisError("unsupported_file", str(child.relative_to(p)), str(exc), "warning"))
    inv.frameworks_detected = sorted(inv.frameworks_detected, key=lambda h: (h.name, h.evidence))
    _coverage(inv)
    return inv


def empty_scan_result(inv: Inventory, tool_version: str) -> ScanResult:
    return ScanResult(
        schema_version=SCHEMA_VERSION,
        tool_name="libidentifier",
        tool_version=tool_version,
        fingerprint_algorithm=FINGERPRINT_ALGORITHM,
        profile_database=ProfileDatabaseRecord(),
        input=inv.input,
        analyzed_files=sorted(inv.analyzed_files, key=lambda a: (a.member or "", a.sha256)),
        frameworks_detected=inv.frameworks_detected,
        components=[],
        class_ownership_hints=[],
        unknown_classes=sorted((c.locator for c in inv.dex_classes), key=lambda x: (x.member or "", x.class_descriptor or "")),
        coverage=inv.coverage,
        errors=inv.errors,
    )

