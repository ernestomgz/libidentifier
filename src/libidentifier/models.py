"""Dataclasses and deterministic JSON serialization."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


def _drop_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _drop_none(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_drop_none(v) for v in value]
    return value


@dataclass(frozen=True)
class InputRecord:
    path: str
    format: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "InputRecord":
        return cls(**data)


@dataclass(frozen=True)
class AnalysisError:
    code: str
    member: str | None
    message: str
    severity: str = "warning"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AnalysisError":
        return cls(**data)


@dataclass(frozen=True)
class CodeLocator:
    container: str
    member: str | None
    class_descriptor: str | None = None
    method_descriptor: str | None = None
    sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CodeLocator":
        return cls(**data)


@dataclass(frozen=True)
class CodeOwnerHint:
    subject: str
    origin: str
    component_id: str
    confidence: str
    method: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CodeOwnerHint":
        return cls(**data)


@dataclass(frozen=True)
class ArtifactRecord:
    member: str | None
    format: str
    sha256: str
    status: str
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ArtifactRecord":
        return cls(**data)


@dataclass(frozen=True)
class FrameworkHint:
    name: str
    evidence: str
    member: str | None
    confidence: str = "low"
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FrameworkHint":
        return cls(**data)


@dataclass(frozen=True)
class CoverageRecord:
    dex: str = "absent"
    elf: str = "absent"
    javascript: str = "not_supported"
    hermes: str = "not_supported"
    dart_aot: str = "not_supported"
    metadata: str = "absent"
    analyzed_count: dict[str, int] = field(
        default_factory=lambda: {"dex": 0, "elf": 0, "classes": 0, "native_binaries": 0}
    )
    skipped_count: dict[str, int] = field(
        default_factory=lambda: {"size_limit": 0, "encrypted": 0, "unsupported": 0, "parse_error": 0}
    )
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CoverageRecord":
        return cls(**data)


@dataclass(frozen=True)
class ComponentMatch:
    component_id: str
    name: str
    ecosystem: str | None
    purl: str | None
    version: str | None
    version_candidates: list[str]
    identity_confidence: str
    version_confidence: str
    identification_methods: list[str]
    score: float | None
    score_details: dict[str, Any]
    matched_code: list[CodeLocator]
    source_artifacts: list[str]
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["matched_code"] = [c.to_dict() for c in self.matched_code]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ComponentMatch":
        copied = dict(data)
        copied["matched_code"] = [CodeLocator.from_dict(x) for x in copied.get("matched_code", [])]
        return cls(**copied)


@dataclass(frozen=True)
class ProfileDatabaseRecord:
    id: str | None = None
    version: str | None = None
    sha256: str | None = None
    generated_at: str | None = None
    profile_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProfileDatabaseRecord":
        return cls(**data)


@dataclass(frozen=True)
class ScanResult:
    schema_version: int
    tool_name: str
    tool_version: str
    fingerprint_algorithm: str
    profile_database: ProfileDatabaseRecord
    input: InputRecord
    analyzed_files: list[ArtifactRecord]
    frameworks_detected: list[FrameworkHint]
    components: list[ComponentMatch]
    class_ownership_hints: list[CodeOwnerHint]
    unknown_classes: list[CodeLocator]
    coverage: CoverageRecord
    errors: list[AnalysisError]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "fingerprint_algorithm": self.fingerprint_algorithm,
            "profile_database": self.profile_database.to_dict(),
            "input": self.input.to_dict(),
            "analyzed_files": [x.to_dict() for x in self.analyzed_files],
            "frameworks_detected": [x.to_dict() for x in self.frameworks_detected],
            "components": [x.to_dict() for x in self.components],
            "class_ownership_hints": [x.to_dict() for x in self.class_ownership_hints],
            "unknown_classes": [x.to_dict() for x in self.unknown_classes],
            "coverage": self.coverage.to_dict(),
            "errors": [x.to_dict() for x in self.errors],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanResult":
        return cls(
            schema_version=data["schema_version"],
            tool_name=data["tool_name"],
            tool_version=data["tool_version"],
            fingerprint_algorithm=data["fingerprint_algorithm"],
            profile_database=ProfileDatabaseRecord.from_dict(data.get("profile_database", {})),
            input=InputRecord.from_dict(data["input"]),
            analyzed_files=[ArtifactRecord.from_dict(x) for x in data.get("analyzed_files", [])],
            frameworks_detected=[FrameworkHint.from_dict(x) for x in data.get("frameworks_detected", [])],
            components=[ComponentMatch.from_dict(x) for x in data.get("components", [])],
            class_ownership_hints=[CodeOwnerHint.from_dict(x) for x in data.get("class_ownership_hints", [])],
            unknown_classes=[CodeLocator.from_dict(x) for x in data.get("unknown_classes", [])],
            coverage=CoverageRecord.from_dict(data["coverage"]),
            errors=[AnalysisError.from_dict(x) for x in data.get("errors", [])],
        )

    def to_json(self) -> str:
        return json.dumps(_drop_none(self.to_dict()), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def write_json(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json() + "\n", encoding="utf-8")


@dataclass(frozen=True)
class ProfileBuildResult:
    database: str
    release_id: str
    family_id: str
    purl: str
    version: str
    source_format: str
    source_sha256: str
    dex_shapes: int = 0
    elf_identities: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

