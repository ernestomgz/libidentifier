from dataclasses import replace
import json

from conftest import make_dex, lib_classes
from libidentifier.extractors.dex import parse_dex
from libidentifier.models import ScanResult, AnalysisRun, Producer, OwnershipAssertion, CodeLocator
from libidentifier.inventory import empty_scan_result, Inventory
from libidentifier.models import InputRecord
import sqlite3
import struct
import pytest
from libidentifier import identify, inspect, build_profile, IdentifyOptions
from libidentifier.extractors.instructions import decode_invocations, INVOKES
from libidentifier.profiles.store import connect_write, upsert_release
from libidentifier.profiles.pom import parse_pom
from libidentifier.errors import ProfileError
from conftest import make_apk


def test_canonical_interfaces_and_descriptors():
    classes = [{'descriptor': 'Ltest/C;', 'interfaces': ['Ltest/I;'],
                'fields': [{'name': 'items', 'type': '[[Ltest/Item;'}],
                'methods': [{'name': 'read', 'return': '[I', 'params': ['Z', 'Ltest/Item;']}]}]
    result = parse_dex(make_dex(classes), container='memory', member='classes.dex', sha256='a')
    cls = result[0]
    assert cls.interfaces == ('Ltest/I;',)
    assert cls.fields[0].type_descriptor == '[[Ltest/Item;'
    assert cls.methods[0].parameter_types == ('Z', 'Ltest/Item;')
    assert cls.methods[0].return_type == '[I'
    assert cls.methods[0].descriptor == 'Ltest/C;->read(ZLtest/Item;)[I'


def test_additive_records_and_legacy_json():
    base = empty_scan_result(Inventory(InputRecord('a', 'dex', 'a', 0)), 'test')
    result = replace(base, analysis_runs=[AnalysisRun('ownership', 'partial', Producer('test', '1'))],
                     ownership_assertions=[OwnershipAssertion(CodeLocator('a', 'classes.dex'), 'ambiguous', ['c1', 'c2'])])
    data = json.loads(result.to_json())
    data['analysis_runs'][0]['producer']['future'] = 1
    assert ScanResult.from_dict(data) == result
    for key in ('analysis_runs', 'evidence_records', 'ownership_assertions', 'unattributed_clusters', 'relationships'):
        data.pop(key)
    assert ScanResult.from_dict(data) == base


@pytest.mark.parametrize('opcode', sorted(INVOKES))
def test_ordinary_invocation_forms(opcode):
    code = struct.pack('<HHHH', opcode, 1, 0, 0x0e)
    calls, issues = decode_invocations(code, method_count=2)
    assert calls == [(0, INVOKES[opcode], 1)] and not issues


def test_instruction_payloads_special_and_malformed():
    # Array bytes include an invoke opcode but are data, never instructions.
    code = struct.pack('<HHHHHHH', 0x0300, 2, 2, 0, 0x006e, 0x0000, 0x000e)
    assert decode_invocations(code, method_count=1) == ([], [])
    for code in (b'\x6e\0', b'\xe3\0', struct.pack('<HHH',0x6e,5,0), b'\0'):
        assert decode_invocations(code,method_count=1)[1]
    for opcode, width in [(0xfa,4),(0xfb,4),(0xfc,3),(0xfd,3)]:
        code = struct.pack('<'+'H'*width,opcode,*([0]*(width-1)))
        calls, issues = decode_invocations(code,method_count=1,dex_version=39)
        assert not calls and 'Special invocation' in issues[0]
        assert decode_invocations(code,method_count=1,dex_version=35)[1]
    # Switch payload widths consume all data, including embedded invoke bytes.
    assert not decode_invocations(struct.pack('<8H',0x0100,2,0,0,0x6e,0,0,0),method_count=1)[0]
    assert not decode_invocations(struct.pack('<6H',0x0200,1,0x6e,0,0,0),method_count=1)[0]


def test_end_to_end_calls_locations_grouping_and_partial(tmp_path):
    key = ('Lother/api/B;', 'V', (), 'target')
    classes = [{'descriptor':'Lsample/code/A;', 'interfaces':['Lsample/code/I;'],
                'methods':[{'name':'caller','flags':1,'code':lambda ids:[0x0071,ids[key],0,0x000e]}]},
               {'descriptor':key[0], 'methods':[{'name':'target','flags':0x109}]},
               {'descriptor':'Lsample/code/I;', 'flags':0x601},
               {'descriptor':'Lsample/code/C;'}]
    path=tmp_path/'calls.dex'; path.write_bytes(make_dex(classes))
    result=inspect(path)
    calls=[e for e in result.relationships if e.type=='static_call_reference']
    assert len(calls)==1
    call=calls[0]
    assert call.qualifiers['invocation_kind']=='static'
    evidence={e.id:e for e in result.evidence_records}[call.evidence_ids[0]]
    assert evidence.details['declared_target']=='Lother/api/B;->target()V'
    assert evidence.location.byte_offset is not None
    assert path.read_bytes()[evidence.location.byte_offset] == 0x71
    assert call.target.location.class_descriptor==key[0]
    assert sum(c.class_count for c in result.unattributed_clusters)==4
    assert all(c.origin=='unknown' for c in result.unattributed_clusters)
    assert any(c.class_count==1 for c in result.unattributed_clusters)
    assert result==inspect(path)
    assert next(r for r in result.analysis_runs if r.capability=='ownership').status=='not_requested'
    assert next(r for r in result.analysis_runs if r.capability=='relationships.components').status=='not_requested'
    assert ScanResult.from_dict(json.loads(result.to_json()))==result
    capped=inspect(path,options=IdentifyOptions(max_emitted_unknown_classes=0))
    assert not capped.unknown_classes and capped.unattributed_clusters==result.unattributed_clusters
    disabled=inspect(path,options=IdentifyOptions(extract_calls=False,group_unknown_classes=False))
    assert next(r for r in disabled.analysis_runs if r.capability=='relationships.calls').status=='not_requested'
    classes[0]['methods'][0]['code']=[0x0071]
    path.write_bytes(make_dex(classes))
    partial=inspect(path)
    assert next(r for r in partial.analysis_runs if r.capability=='relationships.calls').status=='partial'
    assert not any(e.type=='static_call_reference' for e in partial.relationships)


def test_duplicate_definitions_have_ambiguous_ownership(tmp_path, demo_db):
    path=make_apk(tmp_path/'duplicate.apk',{'classes.dex':make_dex(lib_classes('lib/alpha')),
                                          'classes2.dex':make_dex(lib_classes('lib/alpha'))})
    result=identify(path,profiles=demo_db)
    assert result.ownership_assertions
    assert all(a.status=='ambiguous' for a in result.ownership_assertions)
    assert len(result.unknown_classes)==12
    assert not result.class_ownership_hints
    assert not any(e.source.kind=='component' for e in result.relationships)


def test_variants_release_identity_and_no_inflation(tmp_path):
    from collections import Counter
    from libidentifier.fingerprint.dex_v1 import digest_class
    dex=make_dex(lib_classes('lib/alpha')); ref=tmp_path/'ref.dex';ref.write_bytes(dex)
    db=tmp_path/'profiles.sqlite'; built=build_profile(ref,purl='pkg:maven/example/demo@1.0',database=db)
    before=identify(ref,profiles=db)
    features=parse_dex(dex,container='reference',member=None,sha256='a')
    conn=connect_write(db)
    rid,_,_=upsert_release(conn,purl=built.purl,source_sha256='b'*64,source_format='dex',provenance={},
        dex_classes=Counter((digest_class(c),c.descriptor) for c in features),build_configuration={'kind':'test-variant'})
    assert rid==built.release_id
    assert conn.execute('SELECT COUNT(*) FROM library_release').fetchone()[0]==1
    assert conn.execute('SELECT COUNT(*) FROM reference_artifact').fetchone()[0]==2
    assert conn.execute('SELECT COUNT(*) FROM build_variant').fetchone()[0]==2
    assert conn.execute('SELECT COUNT(*) FROM fingerprint_occurrence').fetchone()[0]==2*len(features)
    conn.close()
    after=identify(ref,profiles=db)
    assert after.components==before.components
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE db_meta SET value='1' WHERE key='schema_version'")
    with pytest.raises(ProfileError,match='rebuild'):
        identify(ref,profiles=db)


POM=b'''<project><groupId>example</groupId><artifactId>demo</artifactId><version>1.0</version>
<properties><dep.version>2.0</dep.version></properties><parent><artifactId>parent</artifactId></parent>
<dependencyManagement><dependencies><dependency><groupId>x</groupId><artifactId>managed</artifactId><version>9</version></dependency></dependencies></dependencyManagement>
<dependencies><dependency><groupId>x</groupId><artifactId>api</artifactId><version>${dep.version}</version><scope>runtime</scope><optional>true</optional>
<exclusions><exclusion><groupId>z</groupId><artifactId>excluded</artifactId></exclusion></exclusions></dependency>
<dependency><groupId>y</groupId><artifactId>unresolved</artifactId><version>${missing}</version></dependency></dependencies></project>'''


def test_direct_pom_unresolved_and_published_edges(tmp_path):
    parsed=parse_pom(POM,source='local',expected=('example','demo','1.0'))
    assert len(parsed['declarations'])==2
    assert parsed['declarations'][0]['interpreted']['version']=='2.0'
    assert parsed['declarations'][1]['interpreted']['version'] is None
    assert parsed['status']=='partial'
    ref=tmp_path/'ref.dex';ref.write_bytes(make_dex(lib_classes('lib/alpha')))
    ref.with_suffix('.pom').write_bytes(POM)
    db=tmp_path/'profiles.sqlite';build_profile(ref,purl='pkg:maven/example/demo@1.0',database=db)
    apk=make_apk(tmp_path/'app.apk',{'classes.dex':ref.read_bytes()})
    result=identify(apk,profiles=db)
    deps=[e for e in result.relationships if e.type=='published_dependency']
    assert len(deps)==2 and all(e.source.kind=='reference_release' for e in deps)
    assert all(e.qualifiers['release_association']=='candidate' for e in deps)
    assert any(e.qualifiers['status']=='unresolved' for e in deps)
    assert not result.components[0].version
    for bad in (b'<bad', b'<!DOCTYPE x><project/>'):
        with pytest.raises(ValueError):parse_pom(bad,source='bad')
    with pytest.raises(ValueError):parse_pom(POM,source='wrong',expected=('wrong','demo','1.0'))


def test_attributable_version_metadata_and_conflict(tmp_path):
    ref=tmp_path/'ref.dex';ref.write_bytes(make_dex(lib_classes('lib/alpha')))
    db=tmp_path/'profiles.sqlite';build_profile(ref,purl='pkg:maven/example/demo@1.0',database=db)
    props=b'groupId=example\nartifactId=demo\nversion=1.0\n'
    members={'classes.dex':ref.read_bytes(),'META-INF/maven/example/demo/pom.properties':props}
    apk=make_apk(tmp_path/'app.apk',members)
    result=identify(apk,profiles=db)
    assert result.components[0].version=='1.0'
    assert result.components[0].version_confidence=='high'
    assert identify(apk,profiles=db,options=IdentifyOptions(max_version_candidates=0)).components[0].version=='1.0'
    assert any(e.kind=='version_metadata' for e in result.evidence_records)
    members['META-INF/maven/example/demo/pom.properties']=props.replace(b'1.0',b'99.0')
    assert identify(make_apk(apk,members),profiles=db).components[0].version is None
    members['META-INF/maven/example/demo/pom.properties']=props.replace(b'example',b'imposter')
    assert identify(make_apk(apk,members),profiles=db).components[0].version is None


def test_component_relationships_are_backed_by_unique_code(tmp_path):
    alpha=lib_classes('alpha/code')
    beta=lib_classes('beta/code',extra_return='Ljava/lang/Object;')
    alpha[0]['fields'].append({'name':'api','type':beta[0]['descriptor']})
    db=tmp_path/'profiles.sqlite'
    for name,classes in [('alpha',alpha),('beta',beta)]:
        ref=tmp_path/(name+'.dex');ref.write_bytes(make_dex(classes))
        build_profile(ref,purl=f'pkg:maven/example/{name}@1',database=db)
    apk=make_apk(tmp_path/'both.apk',{'classes.dex':make_dex(alpha+beta)})
    result=identify(apk,profiles=db)
    assert {c.name for c in result.components}=={'alpha','beta'}
    disabled=identify(apk,profiles=db,options=IdentifyOptions(extract_relationships=False,extract_calls=False,group_unknown_classes=False))
    assert disabled.components==result.components and disabled.unknown_classes==result.unknown_classes
    edges=[r for r in result.relationships if r.source.kind=='component']
    assert any(r.type=='class_reference' for r in edges)
    by_id={r.id:r for r in result.relationships}
    assert all(r.supporting_relationship_ids and all(k in by_id for k in r.supporting_relationship_ids) for r in edges)
    assert all(a.evidence_ids for a in result.ownership_assertions if a.status=='attributed')
    assert ScanResult.from_dict(result.to_dict())==result


def test_legacy_fixture_and_public_consumer(tmp_path):
    from pathlib import Path
    from libidentifier import ScanResult, Relationship, AnalysisRun, UnattributedCluster
    legacy=ScanResult.from_dict(json.loads((Path(__file__).parent/'fixtures/scan-v1-legacy.json').read_text()))
    assert legacy.unknown_classes[0].class_descriptor=='Lsample/C;'
    assert legacy.analysis_runs==[]  # Legacy availability is unknown, not complete.
    assert ScanResult.from_dict(legacy.to_dict())==legacy
    path=tmp_path/'app.dex';path.write_bytes(make_dex(lib_classes('unknown/code')))
    result=inspect(path)
    # A consumer uses public records and never the fingerprint/store internals.
    assert isinstance(result.analysis_runs[0],AnalysisRun)
    assert all(isinstance(c,UnattributedCluster) for c in result.unattributed_clusters)
    ids={e.id for e in result.evidence_records}
    assert all(isinstance(r,Relationship) and set(r.evidence_ids)<=ids for r in result.relationships)
    data=result.to_dict()
    for name in ('relationships','unattributed_clusters','ownership_assertions','evidence_records','analysis_runs'):
        for item in data[name]:item['future_optional']=True
    assert ScanResult.from_dict(data)==result


def test_pinned_catalog_pom_and_canonical_rebuild(tmp_path):
    import hashlib
    from libidentifier.profiles.fetcher import rebuild_database
    ref=tmp_path/'ref.dex';ref.write_bytes(make_dex(lib_classes('known/code')))
    pom=tmp_path/'source.pom';pom.write_bytes(POM)
    catalog=tmp_path/'catalog.json'
    catalog.write_text(json.dumps({'schema_version':1,'references':[{
        'purl':'pkg:maven/example/demo@1.0','url':ref.as_uri(),'sha256':hashlib.sha256(ref.read_bytes()).hexdigest(),
        'pom_url':pom.as_uri(),'pom_sha256':hashlib.sha256(POM).hexdigest()}]}))
    snapshots=[]
    for i in range(2):
        db=tmp_path/f'profiles{i}.sqlite'
        rebuild_database(catalog,cache_dir=tmp_path/'cache',database=db,offline=False)
        with sqlite3.connect(db) as conn:
            snapshots.append({table:conn.execute(f'SELECT * FROM {table} ORDER BY 1,2').fetchall()
                for table in ('library_family','library_release','reference_artifact','build_variant','fingerprint','fingerprint_occurrence','published_metadata')})
            stored=json.loads(conn.execute('SELECT body_json FROM published_metadata').fetchone()[0])
            assert stored['source']==pom.as_uri()
    assert snapshots[0]==snapshots[1]
    # Every input is cached; the same workflow is functional without downloads.
    rebuild_database(catalog,cache_dir=tmp_path/'cache',database=tmp_path/'offline.sqlite',offline=True)


def test_cli_enrichment_controls_preserve_inventory(tmp_path,capsys):
    from libidentifier.cli import main
    path=tmp_path/'sample.dex';path.write_bytes(make_dex(lib_classes('unknown/code')))
    assert main(['inspect',str(path),'--no-relationships','--no-calls','--no-grouping'])==0
    result=ScanResult.from_dict(json.loads(capsys.readouterr().out))
    assert len(result.unknown_classes)==6 and not result.relationships and not result.unattributed_clusters
    assert all(r.status=='not_requested' for r in result.analysis_runs if r.capability.startswith('relationships.') or r.capability=='grouping')


def test_d8_build_provenance_and_version_probe_fallback(tmp_path,monkeypatch):
    import subprocess
    import zipfile
    from libidentifier.profiles import builder
    from pathlib import Path
    jar=tmp_path/'reference.jar'
    with zipfile.ZipFile(jar,'w') as archive:archive.writestr('Example.class',b'fixture')
    compiler=tmp_path/'compiler.cmd';compiler.write_bytes(b'trusted test compiler')
    dex=make_dex(lib_classes('known/code'))
    monkeypatch.setattr(builder,'_run_d8',lambda *args:dex)
    def version(args,**kwargs):
        assert args==[str(Path(compiler)), '--version']
        return subprocess.CompletedProcess(args,0,b'D8 fixture-version',b'')
    monkeypatch.setattr(builder.subprocess,'run',version)
    db=tmp_path/'profiles.sqlite'
    build_profile(jar,purl='pkg:maven/example/demo@1',database=db,d8=str(compiler))
    with sqlite3.connect(db) as conn:
        config=json.loads(conn.execute('SELECT configuration_json FROM build_variant').fetchone()[0])
        assert config['compiler_version']=='D8 fixture-version'
        assert config['compiler_version_status']=='reported'
    monkeypatch.setattr(builder.subprocess,'run',lambda *a,**k:subprocess.CompletedProcess(a,1,b'',b'unsupported'))
    build_profile(jar,purl='pkg:maven/example/demo@1',database=db,d8=str(compiler))
    with sqlite3.connect(db) as conn:
        assert conn.execute('SELECT COUNT(*) FROM build_variant').fetchone()[0]==2


def test_metadata_in_another_apk_does_not_set_version(tmp_path):
    ref=tmp_path/'reference.dex';ref.write_bytes(make_dex(lib_classes('known/code')))
    db=tmp_path/'profiles.sqlite';build_profile(ref,purl='pkg:maven/example/demo@1',database=db)
    folder=tmp_path/'inputs';folder.mkdir()
    make_apk(folder/'known.apk',{'classes.dex':ref.read_bytes()})
    make_apk(folder/'unrelated.apk',{'classes.dex':make_dex([{'descriptor':'Lunrelated/Empty;'}]),
        'META-INF/maven/example/demo/pom.properties':b'groupId=example\nartifactId=demo\nversion=1\n'})
    result=identify(folder,profiles=db)
    assert len(result.components)==1 and result.components[0].version is None


def test_identical_dex_bytes_across_families_never_prove_version(tmp_path):
    ref=tmp_path/'reference.dex';ref.write_bytes(make_dex(lib_classes('shared/code')))
    db=tmp_path/'profiles.sqlite'
    for name,version in [('alpha','1'),('beta','2')]:
        build_profile(ref,purl=f'pkg:maven/example/{name}@{version}',database=db)
    result=identify(ref,profiles=db)
    assert {c.name for c in result.components}=={'alpha','beta'}
    assert all(c.version is None and c.purl is None and c.version_confidence=='unknown' for c in result.components)
    assert all(a.status=='ambiguous' for a in result.ownership_assertions)
