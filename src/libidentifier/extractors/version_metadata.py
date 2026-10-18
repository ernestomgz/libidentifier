"""A deliberately small pom.properties subset, never a global version-string search."""
from __future__ import annotations

import re
from dataclasses import replace
from ..models import CodeLocator, EvidenceRecord, Producer, AnalysisRun
from ..grouping import stable_id
from ..purl import reference_coordinates


def read_properties(data, member):
    match = re.fullmatch(r'META-INF/maven/([^/]+)/([^/]+)/pom\.properties', member)
    if not match or len(data) > 65536:
        return None
    values = {}
    try:
        for line in data.decode('utf-8-sig').splitlines():
            line = line.strip()
            if not line or line.startswith(('#','!')):
                continue
            key, value = re.split(r'\s*[=:]\s*', line, maxsplit=1)
            if key in values or '\\' in line:
                return None  # Unsupported Java-properties escapes/continuations.
            values[key] = value.strip()
    except (ValueError, UnicodeError):
        return None
    if (values.get('groupId'), values.get('artifactId')) != match.groups() or not values.get('version'):
        return None
    return values


def apply_version_metadata(result, inv):
    components, evidence = [], list(result.evidence_records)
    conflicts = 0
    for component in result.components:
        records = []
        containers = {loc.container for loc in component.matched_code}
        if component.family_purl:
            try:
                base = re.split(r'[?#]', component.family_purl, maxsplit=1)[0]
                ecosystem, group, name, _, _ = reference_coordinates(base + '@__unknown__')
            except ValueError:
                ecosystem, group, name = None, None, None
            for loc, props in inv.version_metadata:
                if loc.container in containers and ecosystem == 'maven' and (group, name) == (props['groupId'], props['artifactId']):
                    eid = stable_id('evidence', ['pom.properties', loc.to_dict(), props])
                    evidence.append(EvidenceRecord(eid, 'version_metadata', Producer('maven-properties','1'), loc,
                        {'component_id':component.component_id, 'declared':props},
                        limitations=['Embedded metadata is a declaration and can be modified; structural corroboration is required']))
                    records.append(props)
        versions = {r['version'] for r in records}
        if len(versions) > 1 or (component.version and versions and versions != {component.version}):
            conflicts += 1
            component = replace(component, version=None, purl=None, version_confidence='unknown',
                limitations=component.limitations + ['Conflicting embedded version metadata'])
        elif (len(versions) == 1 and not component.version and len(containers) == 1 and len(component.matched_code) >= 3
              and component.score_details.get('exact_descriptor_matches',0) >= 3):
            version = next(iter(versions))
            # Full supported candidates remain conservative; never use mere best release.
            supported = {v for v,details in component.score_details.get('version_candidate_scores',{}).items() if details.get('supported')}
            if version in supported or version in component.version_candidates:
                from urllib.parse import quote
                base = re.split(r'[?#]', component.family_purl, maxsplit=1)[0]
                suffix = component.family_purl[len(base):]
                component = replace(component, version=version, purl=base+'@'+quote(version,safe='')+suffix,
                    version_confidence='high', identification_methods=component.identification_methods+['maven_properties'],
                    limitations=component.limitations+['Version uses attributable embedded Maven declaration plus matching code; not cryptographic provenance'])
        components.append(component)
    return replace(result, components=components, evidence_records=evidence,
        analysis_runs=result.analysis_runs+[AnalysisRun('version_metadata', 'partial' if conflicts or inv.metadata_issues or inv.coverage.dex=='partial' else 'complete',
            Producer('maven-properties','1'), {'records':len(inv.version_metadata), 'conflicting_components':conflicts},
            ['Only simple canonical pom.properties associated with identified code is supported'], inv.metadata_issues)])
