"""Versioned assessment models, independent of identification internals."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from pathlib import Path
from ..models import AnalysisError, CodeLocator, CoverageRecord, InputRecord, ProfileDatabaseRecord, ScanResult, _known
from ..serialization import iter_json, write_json

ASSESSMENT_SCHEMA_VERSION = 1

class JsonModel:
    def to_dict(self):
        return asdict(self)
    def to_json(self):
        return ''.join(iter_json(self))
    def write_json(self, path):
        write_json(self, path)
    @classmethod
    def from_dict(cls, data):
        return cls(**_known(cls, data))

@dataclass(frozen=True)
class VulnerabilityOptions:
    scanner: str | Path
    database: str | Path
    timeout_seconds: float = 60
    max_database_age_days: float = 30
    discover_unknown_versions: bool = True
    max_potential_advisories_per_component: int = 100
    max_output_bytes: int = 64 * 1024 * 1024
    def __post_init__(self):
        import math
        if not isinstance(self.discover_unknown_versions, bool):
            raise ValueError('discover_unknown_versions must be a boolean')
        for name in ('timeout_seconds', 'max_database_age_days'):
            value = getattr(self, name)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
                raise ValueError(f'{name} must be finite and positive')
        for name in ('max_potential_advisories_per_component', 'max_output_bytes'):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < (1 if name == 'max_output_bytes' else 0):
                raise ValueError(f'{name} has an invalid limit')

@dataclass(frozen=True)
class ScannerRecord(JsonModel):
    path: str
    version: str
    sha256: str

@dataclass(frozen=True)
class AdvisoryDatabaseRecord(JsonModel):
    generation: str
    fetched_at: str
    age_days: float
    ecosystems: list[str]
    hashes: dict[str, str]
    sources: dict[str, str]
    schema_version: int = 1

@dataclass(frozen=True)
class AdvisoryRecord(JsonModel):
    id: str
    aliases: list[str]
    summary: str
    severity: list[dict]
    affected: list[dict]
    references: list[dict]
    modified: str | None
    withdrawn: str | None
    raw: dict

@dataclass(frozen=True)
class AdvisoryFinding(JsonModel):
    component_id: str
    advisory_id: str
    applicability: str
    match_basis: str
    evaluated_version: str | None
    identity_confidence: str
    version_confidence: str
    reachability: str = 'not_analyzed'
    related_advisory_ids: list[str] = field(default_factory=list)

@dataclass(frozen=True)
class ComponentAssessment(JsonModel):
    component_id: str
    family_purl: str | None
    status: str
    reason: str
    evaluated_version: str | None
    identity_confidence: str
    version_confidence: str
    evidence: list[CodeLocator]
    advisory_ids: list[str] = field(default_factory=list)
    advisories_total: int = 0
    advisories_truncated: bool = False
    @classmethod
    def from_dict(cls, data):
        d = _known(cls, data)
        d['evidence'] = [CodeLocator.from_dict(x) for x in data.get('evidence', [])]
        return cls(**d)

@dataclass(frozen=True)
class VulnerabilityReport(JsonModel):
    status: str
    input: InputRecord
    tool_version: str
    profile_database: ProfileDatabaseRecord
    components: list[ComponentAssessment] = field(default_factory=list)
    findings: list[AdvisoryFinding] = field(default_factory=list)
    advisories: list[AdvisoryRecord] = field(default_factory=list)
    scanner: ScannerRecord | None = None
    database: AdvisoryDatabaseRecord | None = None
    errors: list[AnalysisError] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    schema_version: int = ASSESSMENT_SCHEMA_VERSION
    result_kind: str = 'vulnerability_report'
    identification_coverage: CoverageRecord | None = None
    identification_errors: list[AnalysisError] = field(default_factory=list)
    @classmethod
    def from_dict(cls, data):
        _check(data, 'vulnerability_report')
        d = _known(cls, data)
        for name, model in [('input', InputRecord), ('profile_database', ProfileDatabaseRecord)]:
            d[name] = model.from_dict(data[name])
        for name, model in [('scanner', ScannerRecord), ('database', AdvisoryDatabaseRecord)]:
            d[name] = model.from_dict(data[name]) if data.get(name) else None
        for name, model in [('components', ComponentAssessment), ('findings', AdvisoryFinding), ('advisories', AdvisoryRecord), ('errors', AnalysisError)]:
            d[name] = [model.from_dict(x) for x in data.get(name, [])]
        d['identification_errors'] = [AnalysisError.from_dict(x) for x in data.get('identification_errors', [])]
        d['identification_coverage'] = CoverageRecord.from_dict(data['identification_coverage']) if data.get('identification_coverage') else None
        return cls(**d)

@dataclass(frozen=True)
class AssessmentResult(JsonModel):
    identification: ScanResult
    vulnerabilities: VulnerabilityReport
    schema_version: int = ASSESSMENT_SCHEMA_VERSION
    result_kind: str = 'assessment'
    @classmethod
    def from_dict(cls, data):
        _check(data, 'assessment')
        return cls(ScanResult.from_dict(data['identification']), VulnerabilityReport.from_dict(data['vulnerabilities']))

def _check(data, kind):
    if data.get('schema_version') != ASSESSMENT_SCHEMA_VERSION or data.get('result_kind') != kind:
        raise ValueError('unsupported assessment schema or result kind')
