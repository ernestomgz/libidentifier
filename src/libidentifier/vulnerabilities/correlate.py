"""Evidence-linked correlation; only OSV evaluates exact-version ranges."""
from __future__ import annotations
from dataclasses import replace
import sqlite3
import math
from ..errors import AdvisoryError
from ..models import AnalysisError
from ..purl import reference_coordinates
from .database import discover, open_snapshot
from .models import AdvisoryFinding, AdvisoryRecord, ComponentAssessment, VulnerabilityReport
from .runner import match_versions, verify_scanner

LIMITATIONS = [
    'Advisory matching does not establish vulnerable code reachability or exploitability',
    'Coverage is limited to identified components, supported ecosystems and the provisioned advisory snapshot',
    'Package-only potential advisories do not establish applicability; candidate versions are never installed-version claims',
]


def _coordinate(component):
    # Legacy schema-1 results may not yet have family_purl.
    purl = component.purl or component.family_purl
    if not purl:
        return None
    try:
        if component.version and component.purl:
            kind, namespace, name, version, _ = reference_coordinates(purl)
            if version != component.version or name != component.name:
                return None
        else:
            if '@' in purl.split('?', 1)[0].split('#', 1)[0]:
                return None
            base, separator, suffix = purl.partition('?')
            base, fragment, tail = base.partition('#')
            value = base + '@__unknown__' + (separator + suffix if separator else fragment + tail)
            kind, namespace, name, _, _ = reference_coordinates(value)
        if kind != 'maven' or not namespace:
            return None
        return 'Maven', namespace + ':' + name
    except ValueError:
        return None


def _advisory(raw):
    return AdvisoryRecord(raw['id'], raw.get('aliases', []), raw.get('summary', ''), raw.get('severity', []),
                          raw.get('affected', []), raw.get('references', []), raw.get('modified'), raw.get('withdrawn'), raw)


def _group_findings(advisories, findings, assessments):
    """One finding per alias-connected advisory group, retaining original records."""
    parent = {key: key for key in advisories}
    owners = {}
    def root(key):
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key
    for key, record in sorted(advisories.items()):
        for alias in [key, *record.aliases]:
            if alias in owners:
                a, b = root(key), root(owners[alias])
                parent[max(a, b)] = min(a, b)
            else:
                owners[alias] = key
    groups = {}
    for key in advisories:
        groups.setdefault(root(key), []).append(key)
    grouped = {}
    for finding in findings:
        canonical = root(finding.advisory_id)
        key = (finding.component_id, canonical, finding.match_basis, finding.evaluated_version)
        grouped[key] = replace(finding, advisory_id=canonical, related_advisory_ids=sorted(groups[canonical]))
    normalized = [replace(a, advisory_ids=sorted({root(key) for key in a.advisory_ids})) for a in assessments]
    return sorted(grouped.values(), key=lambda f: (f.component_id, f.advisory_id)), normalized


def unavailable_report(result, exc, *, scanner=None):
    """Keep inventory and attribution intact when CLI preparation cannot complete."""
    code = getattr(exc, 'code', 'assessment_unavailable')
    return VulnerabilityReport('blocked', result.input, result.tool_version, result.profile_database,
        components=[ComponentAssessment(c.component_id, c.family_purl, 'not_assessed', code,
            None, c.identity_confidence, c.version_confidence, c.matched_code) for c in result.components],
        scanner=scanner, database=getattr(exc, 'database', None), limitations=LIMITATIONS,
        errors=[AnalysisError(code, None, str(exc), 'error')],
        identification_coverage=result.coverage, identification_errors=result.errors)


def correlate(result, *, options):
    assessments = [ComponentAssessment(c.component_id, c.family_purl, 'not_assessed', 'Assessment unavailable',
        None, c.identity_confidence, c.version_confidence, c.matched_code) for c in result.components]
    report = VulnerabilityReport('blocked', result.input, result.tool_version, result.profile_database,
                                  components=assessments, limitations=[*LIMITATIONS,
                                      f'Advisory identity score threshold: {options.min_identity_score:g}; scores are not calibrated probabilities'],
                                  identification_coverage=result.coverage, identification_errors=result.errors)
    scanner = database = None
    try:
        scanner = verify_scanner(options)
        database, stage = open_snapshot(options.database, max_age_days=options.max_database_age_days)
    except (AdvisoryError, OSError) as exc:
        return unavailable_report(result, exc, scanner=scanner)
    advisories, findings, queries, eligible = {}, [], {}, {}
    try:
        for i, component in enumerate(result.components):
            coordinate = _coordinate(component)
            score = component.score
            if (not isinstance(score, (int, float)) or isinstance(score, bool) or not math.isfinite(score)
                    or not 0 <= score <= 1):
                assessments[i] = replace(assessments[i], reason='Identity score unavailable or invalid')
                continue
            if score < options.min_identity_score:
                assessments[i] = replace(assessments[i], reason=f'Identity score below {options.min_identity_score:g}')
                continue
            if not coordinate or coordinate[0] not in database.ecosystems:
                assessments[i] = replace(assessments[i], reason='Unsupported or unavailable package ecosystem/coordinate')
                continue
            ecosystem, name = coordinate
            if component.version and component.version_confidence == 'high' and component.purl:
                key = (ecosystem, name, component.version)
                queries[key] = {'ecosystem': ecosystem, 'name': name, 'version': component.version}
                eligible[i] = key
            elif options.discover_unknown_versions:
                records, total = discover(stage, ecosystem, name, options.max_potential_advisories_per_component)
                ids = []
                for raw in records:
                    aid = raw['id']
                    advisories[aid] = _advisory(raw)
                    ids.append(aid)
                    findings.append(AdvisoryFinding(component.component_id, aid, 'potential', 'package_identity', None,
                        component.identity_confidence, component.version_confidence))
                assessments[i] = replace(assessments[i], status='potential' if total else 'not_assessed',
                    reason='Package advisories found; installed version applicability is unknown' if total else 'Version unknown; no package advisories in this snapshot',
                    advisory_ids=ids, advisories_total=total, advisories_truncated=total > len(ids))
            else:
                assessments[i] = replace(assessments[i], reason='Version is unknown; package-only discovery is disabled')
        errors = []
        if queries:
            try:
                matches = match_versions(scanner, stage, [queries[k] for k in sorted(queries)], options)
                for i, key in eligible.items():
                    component = result.components[i]
                    ids = []
                    for raw in matches[key]:
                        aid = raw['id']
                        if aid not in ids:
                            ids.append(aid)
                            advisories[aid] = _advisory(raw)
                            findings.append(AdvisoryFinding(component.component_id, aid, 'affected', 'exact_version',
                                component.version, component.identity_confidence, component.version_confidence))
                    assessments[i] = replace(assessments[i], status='affected' if ids else 'not_affected',
                        reason='OSV matched this reliable version' if ids else 'No evaluated advisories affect this reliable version in this snapshot',
                        evaluated_version=component.version, advisory_ids=sorted(ids), advisories_total=len(ids))
            except (AdvisoryError, OSError) as exc:
                for i in eligible:
                    assessments[i] = replace(assessments[i], reason='Exact-version scanner evaluation failed')
                errors.append(AnalysisError(getattr(exc, 'code', 'scanner_failed'), None, str(exc), 'error'))
        incomplete = bool(errors or result.errors) or result.coverage.dex == 'partial' or result.coverage.elf == 'partial' or any(a.status == 'not_assessed' or a.advisories_truncated for a in assessments)
        findings, assessments = _group_findings(advisories, findings, assessments)
        return replace(report, status='partial' if incomplete else ('not_applicable' if not assessments else 'complete'),
                       scanner=scanner, database=database, components=assessments,
                       findings=findings,
                       advisories=[advisories[k] for k in sorted(advisories)], errors=errors)
    except (AdvisoryError, OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        return replace(report, status='failed', scanner=scanner, database=database,
            errors=[AnalysisError(getattr(exc, 'code', 'assessment_failed'), None, str(exc), 'error')])
