"""Dataclasses and deterministic JSON serialization."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any


def _known(cls, data):
    """Ignore additive fields when reading a supported schema."""
    names = {f.name for f in fields(cls)}
    return {k: v for k, v in data.items() if k in names}


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
        return cls(**_known(cls, data))


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
        return cls(**_known(cls, data))


@dataclass(frozen=True)
class CodeLocator:
    container: str
    member: str | None
    class_descriptor: str | None = None
    method_descriptor: str | None = None
    sha256: str | None = None
    byte_offset: int | None = None  # Absolute byte offset in the DEX member.

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CodeLocator":
        return cls(**_known(cls, data))


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
        return cls(**_known(cls, data))


@dataclass(frozen=True)
class ArtifactRecord:
    member: str | None
    format: str
    sha256: str
    status: str
    path: str | None = None
    container: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ArtifactRecord":
        return cls(**_known(cls, data))


@dataclass(frozen=True)
class FrameworkEvidence:
    indicator: str
    location: CodeLocator

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FrameworkEvidence":
        return cls(data["indicator"], CodeLocator.from_dict(data["location"]))


@dataclass(frozen=True)
class FrameworkHint:
    name: str
    evidence: str
    member: str | None
    confidence: str = "low"
    limitations: list[str] = field(default_factory=list)
    framework_id: str | None = None
    evidence_records: list[FrameworkEvidence] = field(default_factory=list)
    application_logic: str = "not_supported"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FrameworkHint":
        copied = _known(cls, data)
        copied["evidence_records"] = [FrameworkEvidence.from_dict(x) for x in data.get("evidence_records", [])]
        return cls(**copied)


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
    library_identification: str = "unknown"
    unknown_classes_total: int | None = None
    unknown_classes_emitted: int | None = None
    unknown_classes_truncated: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CoverageRecord":
        return cls(**_known(cls, data))


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
    family_purl: str | None = None
    version_candidates_total: int | None = None
    version_candidates_truncated: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["matched_code"] = [c.to_dict() for c in self.matched_code]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ComponentMatch":
        copied = _known(cls, data)
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
        return cls(**_known(cls, data))


class Record:
    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**_known(cls, data))


@dataclass(frozen=True)
class Producer(Record):
    name: str
    version: str


@dataclass(frozen=True)
class AnalysisRun(Record):
    capability: str
    status: str
    producer: Producer
    counts: dict[str, int] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    errors: list[AnalysisError] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data):
        d = _known(cls, data)
        d['producer'] = Producer.from_dict(data['producer'])
        d['errors'] = [AnalysisError.from_dict(x) for x in data.get('errors', [])]
        return cls(**d)


@dataclass(frozen=True)
class EvidenceRecord(Record):
    id: str
    kind: str
    producer: Producer
    location: CodeLocator | None = None
    details: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data):
        d = _known(cls, data)
        d['producer'] = Producer.from_dict(data['producer'])
        d['location'] = CodeLocator.from_dict(data['location']) if data.get('location') else None
        return cls(**d)


@dataclass(frozen=True)
class EntityRef(Record):
    kind: str
    id: str
    location: CodeLocator | None = None
    purl: str | None = None

    @classmethod
    def from_dict(cls, data):
        d = _known(cls, data)
        d['location'] = CodeLocator.from_dict(data['location']) if data.get('location') else None
        return cls(**d)


@dataclass(frozen=True)
class OwnershipAssertion(Record):
    location: CodeLocator
    status: str
    component_ids: list[str]
    evidence_ids: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data):
        d = _known(cls, data)
        d['location'] = CodeLocator.from_dict(data['location'])
        return cls(**d)


@dataclass(frozen=True)
class Relationship(Record):
    id: str
    type: str
    source: EntityRef
    target: EntityRef
    evidence_ids: list[str]
    producer: Producer
    strength: str = 'observed'
    qualifiers: dict[str, Any] = field(default_factory=dict)
    supporting_relationship_ids: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data):
        d = _known(cls, data)
        for name in ('source', 'target'):
            d[name] = EntityRef.from_dict(data[name])
        d['producer'] = Producer.from_dict(data['producer'])
        return cls(**d)


@dataclass(frozen=True)
class UnattributedCluster(Record):
    id: str
    class_count: int
    members: list[CodeLocator]
    namespace_hint: str | None
    grouping_methods: list[str]
    origin: str = 'unknown'
    quality: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    supporting_relationship_ids: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data):
        d = _known(cls, data)
        d['members'] = [CodeLocator.from_dict(x) for x in data['members']]
        return cls(**d)


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
    analysis_runs: list[AnalysisRun] = field(default_factory=list)
    evidence_records: list[EvidenceRecord] = field(default_factory=list)
    ownership_assertions: list[OwnershipAssertion] = field(default_factory=list)
    unattributed_clusters: list[UnattributedCluster] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)

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
            **{name: [x.to_dict() for x in getattr(self, name)] for name in (
                'analysis_runs', 'evidence_records', 'ownership_assertions', 'unattributed_clusters', 'relationships')},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanResult":
        from .config import SCHEMA_VERSION
        if data["schema_version"] != SCHEMA_VERSION:
            raise ValueError(f"unsupported scan schema version: {data['schema_version']}")
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
            analysis_runs=[AnalysisRun.from_dict(x) for x in data.get('analysis_runs', [])],
            evidence_records=[EvidenceRecord.from_dict(x) for x in data.get('evidence_records', [])],
            ownership_assertions=[OwnershipAssertion.from_dict(x) for x in data.get('ownership_assertions', [])],
            unattributed_clusters=[UnattributedCluster.from_dict(x) for x in data.get('unattributed_clusters', [])],
            relationships=[Relationship.from_dict(x) for x in data.get('relationships', [])],
        )

    def to_json(self) -> str:
        from .serialization import iter_json
        return "".join(iter_json(self))

    def write_json(self, path: str | Path) -> None:
        from .serialization import write_json
        write_json(self, path)


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
