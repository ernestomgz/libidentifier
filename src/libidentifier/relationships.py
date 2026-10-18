"""Evidence-backed structural/call relationships and component aggregation."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
import json
from urllib.parse import quote

from .extractors.instructions import decode_invocations
from .grouping import locator_key, stable_id, group_unknown
from .models import (AnalysisRun, Producer, EvidenceRecord, EntityRef, Relationship,
                     OwnershipAssertion, AnalysisError)
from .purl import family_purl

PRODUCER = Producer('dex-relationships', '1')


def enrich(result, inv, options, conn=None):
    """Run once against the complete internal inventory, before output capping."""
    evidence, edges, runs = list(result.evidence_records), [], list(result.analysis_runs)
    definitions = defaultdict(list)
    methods = defaultdict(list)
    for cls in inv.dex_classes:
        definitions[cls.descriptor].append(cls.locator)
        for method in cls.methods:
            if method.descriptor:
                methods[method.descriptor].append(replace(cls.locator, method_descriptor=method.descriptor))
    assertions = inv.ownership_assertions or [OwnershipAssertion(cls.locator,
        'ambiguous' if len(definitions[cls.descriptor]) > 1 else 'unattributed', []) for cls in inv.dex_classes]
    resolved_assertions = []
    for assertion in assertions:
        ids = []
        if assertion.component_ids:
            eid = stable_id('evidence', ['ownership', assertion.to_dict()])
            evidence.append(EvidenceRecord(eid, 'component_match', Producer('component-matcher', '2'),
                assertion.location, details={'component_ids': assertion.component_ids, 'status': assertion.status},
                provenance={'profile_database_sha256': result.profile_database.sha256}, limitations=assertion.limitations))
            ids.append(eid)
        resolved_assertions.append(replace(assertion, evidence_ids=ids))
    incomplete = inv.coverage.dex == 'partial'
    runs.append(AnalysisRun('ownership', 'not_requested' if conn is None else ('partial' if incomplete or any(a.status == 'ambiguous' for a in assertions) else 'complete'),
        Producer('component-matcher', '2'), {'definitions': len(assertions), 'ambiguous': sum(a.status == 'ambiguous' for a in assertions)},
        ['Ownership is a supported attribution, not proof of original authorship']))

    def entity(kind, descriptor, locations):
        location = locations[0] if len(locations) == 1 else None
        identity = [kind, locator_key(location), descriptor] if location else [kind, descriptor, 'ambiguous' if locations else 'external']
        return EntityRef(kind, stable_id(kind, identity), location)

    def emit(kind, source, target, location, details, qualifiers=None):
        eid = stable_id('evidence', [kind, location.to_dict(), details])
        evidence.append(EvidenceRecord(eid, kind, PRODUCER, location, details))
        rid = stable_id('relationship', [kind, source.id, target.id, eid])
        edges.append(Relationship(rid, kind, source, target, [eid], PRODUCER,
            qualifiers=qualifiers or {}, limitations=['Static reference does not establish runtime execution']))

    structural_count = 0
    calls_examined = calls_skipped = 0
    call_errors = []
    if options.extract_relationships:
        for cls in inv.dex_classes:
            source = entity('class', cls.descriptor, [cls.locator])
            refs = [('inheritance', cls.superclass, cls.locator, {'role': 'superclass'})]
            refs += [('interface_implementation', desc, cls.locator, {'role': 'interface'}) for desc in cls.interfaces]
            refs += [('class_reference', f.type_descriptor, cls.locator, {'role': 'field_type', 'field': f.name}) for f in cls.fields]
            for method in cls.methods:
                loc = replace(cls.locator, method_descriptor=method.descriptor)
                refs.append(('class_reference', method.return_type, loc, {'role': 'return_type'}))
                refs += [('class_reference', desc, loc, {'role': 'parameter_type', 'parameter_index': i}) for i,desc in enumerate(method.parameter_types)]
            for kind, desc, loc, details in refs:
                if not desc or not desc.lstrip('[').startswith('L'):
                    continue
                target_desc = desc.lstrip('[')
                target = entity('class', target_desc, definitions.get(target_desc, []))
                emit(kind, source, target, loc, {**details, 'target_descriptor': target_desc},
                     {'target_resolution': 'unique' if target.location else ('ambiguous' if definitions.get(target_desc) else 'external')})
                structural_count += 1
    runs.append(AnalysisRun('relationships.structural', ('partial' if incomplete else 'complete') if options.extract_relationships else 'not_requested',
        PRODUCER, {'relationships': structural_count}, ['Only declaration/signature type references are extracted']))

    if options.extract_calls:
        for cls in inv.dex_classes:
            tables = inv.dex_tables.get((cls.locator.container, cls.locator.member))
            for method in cls.methods:
                if method.code_offset is None:
                    continue
                calls_examined += 1
                loc = replace(cls.locator, method_descriptor=method.descriptor)
                if tables is None:
                    calls_skipped += 1
                    call_errors.append(AnalysisError('call_tables_missing', loc.member, 'Method reference tables unavailable'))
                    continue
                calls, issues = decode_invocations(method.bytecode, method_count=len(tables.methods), dex_version=int(tables.data[4:7]))
                if issues:
                    calls_skipped += 1
                    call_errors.extend(AnalysisError('call_extraction_partial', loc.member,
                        f'{method.descriptor}: {issue}') for issue in issues)
                source = entity('method', method.descriptor, [loc])
                for offset, kind, index in calls:
                    target_desc = tables.method_descriptor(index)
                    target = entity('method', target_desc, methods.get(target_desc, []))
                    emit('static_call_reference', source, target,
                        replace(loc, byte_offset=method.code_offset + offset),
                        {'declared_target': target_desc, 'instruction_byte_offset': offset, 'method_index': index},
                        {'invocation_kind': kind, 'target_resolution': 'unique' if target.location else ('ambiguous' if methods.get(target_desc) else 'external')})
    runs.append(AnalysisRun('relationships.calls', ('partial' if incomplete or call_errors else 'complete') if options.extract_calls else 'not_requested',
        PRODUCER, {'methods_examined': calls_examined, 'methods_partial': calls_skipped},
        ['Declared ordinary invocation targets only; no runtime dispatch or reachability'], call_errors))

    ownership = {locator_key(a.location): a.component_ids[0] for a in resolved_assertions if a.status == 'attributed' and len(a.component_ids) == 1}
    aggregates = defaultdict(list)
    for edge in edges:
        if edge.source.location and edge.target.location:
            src, dst = ownership.get(locator_key(edge.source.location)), ownership.get(locator_key(edge.target.location))
            if src and dst and src != dst:
                aggregates[(edge.type, src, dst)].append(edge)
    for (kind, src, dst), supporting in sorted(aggregates.items()):
        edges.append(Relationship(stable_id('relationship', [kind, src, dst]), kind,
            EntityRef('component', src), EntityRef('component', dst),
            sorted({eid for edge in supporting for eid in edge.evidence_ids}), PRODUCER,
            strength='attributed', supporting_relationship_ids=sorted(e.id for e in supporting),
            limitations=['Component edge depends on code ownership; does not prove build introduction or runtime execution']))
    runs.append(AnalysisRun('relationships.components', 'not_requested' if conn is None or not (options.extract_relationships or options.extract_calls) else ('partial' if incomplete or any(a.status == 'ambiguous' for a in assertions) or call_errors else 'complete'),
        PRODUCER, {'relationships': len(aggregates)}, ['Only uniquely attributed embedded endpoints are aggregated']))

    published_count, missing_metadata = 0, 0
    if conn is not None and options.extract_relationships:
        metadata_rows = list(conn.execute('SELECT r.purl,m.body_json FROM published_metadata m JOIN library_release r USING(release_id) ORDER BY r.purl,m.source_sha256'))
        for component in result.components:
            supported = {v for v,details in component.score_details.get('version_candidate_scores',{}).items() if details.get('supported')}
            versions = {component.version} if component.version else supported | set(component.version_candidates)
            selected = [(purl, json.loads(body)) for purl,body in metadata_rows
                        if family_purl(purl) == component.family_purl and purl_version(purl) in versions]
            if not selected:
                missing_metadata += 1
            for purl, metadata in selected:
                if metadata['status'] != 'complete':
                    missing_metadata += 1
                for index, declaration in enumerate(metadata['declarations']):
                    values = declaration['interpreted']
                    target_purl = ('pkg:maven/' + quote(values['groupId'], safe='.') + '/' + quote(values['artifactId'], safe='')
                                   if values['groupId'] and values['artifactId'] else None)
                    eid = stable_id('evidence', [purl, metadata['sha256'], index])
                    evidence.append(EvidenceRecord(eid, 'pom_declaration', Producer('pom-direct', '1'),
                        details=declaration, provenance={'source':metadata['source'], 'sha256':metadata['sha256'], 'release_purl':purl}, limitations=metadata['limitations']))
                    edges.append(Relationship(stable_id('relationship', [component.component_id, eid]), 'published_dependency',
                        EntityRef('reference_release', purl, purl=purl), EntityRef('package', target_purl or stable_id('unresolved', declaration), purl=target_purl),
                        [eid], Producer('pom-direct','1'), strength='declared',
                        qualifiers={'component_id':component.component_id, 'release_association':'exact' if component.version else 'candidate', **declaration},
                        limitations=['Published reference declaration does not prove APK dependency inclusion or selected version']))
                    published_count += 1
    runs.append(AnalysisRun('relationships.published', 'not_requested' if conn is None or not options.extract_relationships else ('partial' if missing_metadata else 'complete'),
        Producer('pom-direct','1'), {'declarations':published_count, 'incomplete_components':missing_metadata},
        ['Only supplied reference metadata is evaluated; candidate release declarations are conditional']))

    assigned = {locator_key(a.location) for a in resolved_assertions if a.status == 'attributed'}
    unknown = [c.locator for c in inv.dex_classes if locator_key(c.locator) not in assigned]
    clusters = group_unknown(inv.dex_classes, unknown, edges) if options.group_unknown_classes else []
    runs.append(AnalysisRun('grouping', ('partial' if incomplete else 'complete') if options.group_unknown_classes else 'not_requested',
        Producer('namespace-structural','1'), {'classes_total':len(unknown), 'classes_emitted':sum(c.class_count for c in clusters), 'clusters':len(clusters)},
        ['Grouping covers successfully extracted unmatched definitions only']))
    return replace(result, ownership_assertions=resolved_assertions, evidence_records=sorted({e.id:e for e in evidence}.values(),key=lambda e:e.id),
        relationships=sorted(edges,key=lambda e:e.id), analysis_runs=runs, unattributed_clusters=clusters)


def purl_version(purl):
    from .purl import reference_coordinates
    return reference_coordinates(purl)[3]
