"""Known embedded version declarations, corroborated against identified code."""
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


ANDROIDX_VERSION_PATH = re.compile(
    r'META-INF/(androidx(?:\.[a-z0-9][a-z0-9.-]*)?)_([a-zA-Z0-9][a-zA-Z0-9.-]*)\.version'
)


def is_androidx_version_member(member):
    return ANDROIDX_VERSION_PATH.fullmatch(member) is not None


def read_androidx_version(data, member):
    match = ANDROIDX_VERSION_PATH.fullmatch(member)
    if not match or len(data) > 4096:
        return None
    try:
        version = data.decode('utf-8-sig').strip(' \t\r\n')
    except UnicodeError:
        return None
    # One literal version token, not arbitrary text, ranges or property files.
    if not re.fullmatch(r'[0-9][A-Za-z0-9.+_-]{0,255}', version):
        return None
    return dict(zip(('groupId', 'artifactId', 'version'), (*match.groups(), version)))


def read_version_metadata(data, member):
    if is_androidx_version_member(member):
        return read_androidx_version(data, member)
    return read_properties(data, member)


def _coordinates(component):
    if component.family_purl:
        try:
            base = re.split(r'[?#]', component.family_purl, maxsplit=1)[0]
            ecosystem, group, name, _, _ = reference_coordinates(base + '@__unknown__')
            if ecosystem == 'maven':
                return group, name
        except ValueError:
            pass
    return None


def apply_version_metadata(result, inv):
    evidence = list(result.evidence_records)
    by_component = {}
    # Preserve declarations even without matching profiles/code (including inspect).
    # They are evidence, never metadata-only library matches or OSV coordinates.
    for loc, props in inv.version_metadata:
        convention = 'androidx.version' if is_androidx_version_member(loc.member or '') else 'pom.properties'
        producer = Producer('androidx-version-file' if convention == 'androidx.version' else 'maven-properties', '1')
        matches = [c for c in result.components
                   if _coordinates(c) == (props['groupId'], props['artifactId'])
                   and loc.container in {code.container for code in c.matched_code}]
        details = {'declared': props, 'convention': convention,
                   'component_ids': [c.component_id for c in matches]}
        if len(matches) == 1:
            details['component_id'] = matches[0].component_id
            by_component.setdefault(matches[0].component_id, []).append((props, convention))
        evidence.append(EvidenceRecord(
            stable_id('evidence', [convention, loc.to_dict(), props]),
            'version_metadata', producer, loc, details,
            limitations=['Embedded metadata is a declaration and can be modified; structural corroboration is required']))

    components, conflicts = [], 0
    for component in result.components:
        records = by_component.get(component.component_id, [])
        containers = {loc.container for loc in component.matched_code}
        versions = {props['version'] for props, _ in records}
        if len(versions) > 1 or (component.version and versions and versions != {component.version}):
            conflicts += 1
            component = replace(component, version=None, purl=None, version_confidence='unknown',
                limitations=component.limitations + ['Conflicting embedded version metadata'])
        elif (len(versions) == 1 and not component.version and len(containers) == 1 and len(component.matched_code) >= 3
              and component.score_details.get('exact_descriptor_matches', 0) >= 3):
            version = next(iter(versions))
            supported = {v for v, details in component.score_details.get('version_candidate_scores', {}).items()
                         if details.get('supported')}
            if version in supported or version in component.version_candidates:
                from urllib.parse import quote
                base = re.split(r'[?#]', component.family_purl, maxsplit=1)[0]
                suffix = component.family_purl[len(base):]
                methods = sorted({'androidx_version_file' if convention == 'androidx.version' else 'maven_properties'
                                  for _, convention in records})
                component = replace(component, version=version, purl=base+'@'+quote(version, safe='')+suffix,
                    version_confidence='high', identification_methods=component.identification_methods+methods,
                    limitations=component.limitations+['Version uses attributable embedded declaration plus matching code; not cryptographic provenance'])
        components.append(component)
    return replace(result, components=components, evidence_records=evidence,
        analysis_runs=result.analysis_runs+[AnalysisRun('version_metadata',
            'partial' if conflicts or inv.metadata_issues or inv.coverage.dex == 'partial' else 'complete',
            Producer('embedded-version-metadata', '1'),
            {'records': len(inv.version_metadata), 'conflicting_components': conflicts},
            ['Only canonical Maven pom.properties and AndroidX version-file conventions are supported; declarations alone do not identify code'],
            inv.metadata_issues)])
