"""Complete output and qualified offline OSV assessment tests."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import os
import sqlite3
import tracemalloc
import zipfile
import pytest
from libidentifier import (IdentifyOptions, ScanResult, VulnerabilityOptions, AssessmentResult, VulnerabilityReport,
    identify, inspect, scan, correlate, build_profile, provision_advisory_database, validate_advisory_database, update_advisory_database)
from libidentifier.cli import main
from libidentifier.errors import AdvisoryError
from libidentifier.models import CodeLocator
from libidentifier.vulnerabilities import database, runner
from conftest import make_dex, make_apk, lib_classes

ROOT = Path(__file__).resolve().parents[1]
EXE = Path(os.environ.get('LIBIDENTIFIER_TEST_OSV', ROOT / 'test-results/tmp/osv/osv-scanner_windows_amd64.exe'))


@pytest.fixture(autouse=True)
def isolated_temp_root(tmp_path, monkeypatch):
    import tempfile
    monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))


def record(aid='OSV-TEST-0001', withdrawn=None):
    r = {'schema_version':'1.7.0','id':aid,'modified':'2026-10-01T00:00:00Z',
         'aliases':['CVE-2099-0001'], 'summary':'Synthetic advisory (not a real CVE)',
         'severity':[{'type':'CVSS_V3','score':'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}],
         'affected':[{'package':{'ecosystem':'Maven','name':'example:demo'},
                      'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'0'},{'fixed':'2.0'}]}]}]}
    if withdrawn: r['withdrawn'] = withdrawn
    return r


def archive(path, records=None):
    with zipfile.ZipFile(path, 'w') as z:
        for r in records or [record()]: z.writestr(r['id']+'.json', json.dumps(r))
    return path


@pytest.fixture
def local_db(tmp_path):
    src = archive(tmp_path/'Maven.zip')
    root = tmp_path/'database'
    provision_advisory_database(root, archives={'Maven':src})
    return root


@pytest.fixture
def qualified_options(local_db):
    if not EXE.is_file(): pytest.skip('qualified OSV executable not installed for integration tests')
    return VulnerabilityOptions(EXE, local_db)


@pytest.fixture
def versioned(tmp_path):
    ref = tmp_path/'reference.dex'; ref.write_bytes(make_dex(lib_classes('known/demo')))
    db = tmp_path/'profiles.sqlite'
    build_profile(ref,purl='pkg:maven/example/demo@1.0',database=db)
    return identify(ref,profiles=db)


def test_full_unknown_output_and_caps_do_not_change_matching(tmp_path, demo_db):
    classes = [{'descriptor':f'Lunknown/Empty{i};','flags':0} for i in range(6001)] + lib_classes('lib/alpha')
    apk = make_apk(tmp_path/'large.apk',{'classes.dex':make_dex(classes)})
    full = identify(apk,profiles=demo_db)
    assert len(full.unknown_classes) == full.coverage.unknown_classes_total == 6001
    assert not full.coverage.unknown_classes_truncated
    for cap in (0,7,7000):
        capped=identify(apk,profiles=demo_db,options=IdentifyOptions(max_emitted_unknown_classes=cap))
        assert capped.components == full.components
        assert capped.coverage.analyzed_count == full.coverage.analyzed_count
        assert len(capped.unknown_classes) == min(cap,6001)
        assert capped.coverage.unknown_classes_total == 6001
        assert capped.coverage.unknown_classes_truncated == (cap<6001)
    inspected=inspect(apk)
    assert len(inspected.unknown_classes) == 6007
    output=tmp_path/'full.json'; full.write_json(output)
    assert ScanResult.from_dict(json.loads(output.read_text(encoding='utf-8'))) == full
    assert output.read_text(encoding='utf-8').rstrip('\n') == full.to_json()


def test_streaming_memory_and_atomic_write(tmp_path, versioned, monkeypatch):
    r=replace(versioned,unknown_classes=[CodeLocator('a.apk','classes.dex',f'Ltest/C{i};',sha256='a'*64) for i in range(10000)])
    tracemalloc.start(); r.write_json(tmp_path/'stream.json'); _, stream_peak=tracemalloc.get_traced_memory(); tracemalloc.stop()
    tracemalloc.start(); legacy=json.dumps(r.to_dict()); _, copy_peak=tracemalloc.get_traced_memory(); tracemalloc.stop()
    assert stream_peak < copy_peak / 3
    assert json.loads(legacy) == json.loads((tmp_path/'stream.json').read_text())
    from libidentifier import serialization
    dest=tmp_path/'saved.json'; dest.write_text('previous')
    monkeypatch.setattr(serialization,'write_stream',lambda *a: (_ for _ in ()).throw(OSError('interrupted')))
    with pytest.raises(OSError): r.write_json(dest)
    assert dest.read_text() == 'previous'
    assert not list(tmp_path.glob('saved.json.*.tmp'))


def test_real_osv_affected_unaffected_and_semantics(versioned, qualified_options):
    affected=correlate(versioned,options=qualified_options)
    assert affected.status == 'complete', affected.errors
    assert affected.components[0].status == 'affected'
    assert affected.findings[0].applicability == 'affected'
    assert affected.findings[0].evaluated_version == '1.0'
    assert affected.findings[0].reachability == 'not_analyzed'
    assert affected.components[0].evidence == versioned.components[0].matched_code
    assert affected.advisories[0].aliases == ['CVE-2099-0001']
    assert affected.advisories[0].affected and affected.advisories[0].severity
    assert affected.scanner.version == '2.7.0'
    c=replace(versioned.components[0],version='3.0',purl='pkg:maven/example/demo@3.0')
    unaffected=correlate(replace(versioned,components=[c]),options=qualified_options)
    assert unaffected.components[0].status == 'not_affected', unaffected.errors
    assert unaffected.components[0].evaluated_version == '3.0'
    assert not unaffected.findings
    assert VulnerabilityReport.from_dict(json.loads(affected.to_json())) == affected
    data=affected.to_dict(); data['future']=1; data['components'][0]['future']=2; data['advisories'][0]['future']=3
    assert VulnerabilityReport.from_dict(data) == affected
    data['schema_version']=2
    with pytest.raises(ValueError): VulnerabilityReport.from_dict(data)


def test_unknown_candidates_never_promoted_and_bounded_discovery(tmp_path, local_db, versioned, qualified_options):
    src=archive(tmp_path/'other.zip',[record('OSV-TEST-0001'),record('OSV-TEST-0002'),record('OSV-WITHDRAWN','2026-10-02T00:00:00Z')])
    provision_advisory_database(local_db,archives={'Maven':src})
    c=replace(versioned.components[0],version=None,purl=None,version_confidence='unknown',version_candidates=['1.0'])
    result=replace(versioned,components=[c,c])
    report=correlate(result,options=replace(qualified_options,max_potential_advisories_per_component=1))
    assert report.status == 'partial'
    assert len(report.advisories) == 1
    assert all(a.status == 'potential' and a.evaluated_version is None for a in report.components)
    assert all(a.advisories_total==2 and a.advisories_truncated for a in report.components)
    assert all(f.match_basis=='package_identity' and f.evaluated_version is None for f in report.findings)
    assert c.version is None
    disabled=correlate(replace(versioned,components=[c]),options=replace(qualified_options,discover_unknown_versions=False))
    assert disabled.components[0].status=='not_assessed' and not disabled.findings


def test_missing_corrupt_stale_database(versioned,qualified_options,tmp_path):
    missing=correlate(versioned,options=replace(qualified_options,database=tmp_path/'absent'))
    assert missing.status=='blocked' and missing.components[0].status=='not_assessed'
    pointer=json.loads((Path(qualified_options.database)/'CURRENT.json').read_text())
    index=Path(qualified_options.database)/'generations'/pointer['generation']/'index.sqlite'
    with index.open('ab') as f: f.write(b'corruption')
    corrupted=correlate(versioned,options=qualified_options)
    assert corrupted.errors[0].code=='database_corrupt'
    src=archive(tmp_path/'old.zip')
    old=(datetime.now(timezone.utc)-timedelta(days=100)).isoformat()
    provision_advisory_database(qualified_options.database,archives={'Maven':src},fetched_at=old)
    stale=correlate(versioned,options=qualified_options)
    assert stale.errors[0].code=='database_stale' and stale.database.age_days > 99
    assert stale.components[0].status=='not_assessed'


def test_missing_executable_timeout_and_bad_output(versioned, qualified_options, tmp_path, monkeypatch):
    missing=correlate(versioned,options=replace(qualified_options,scanner=tmp_path/'missing.exe'))
    assert missing.errors[0].code=='scanner_missing'
    fake=tmp_path/'fake.exe'; fake.write_bytes(b'not approved')
    assert correlate(versioned,options=replace(qualified_options,scanner=fake)).errors[0].code=='scanner_unapproved'
    timeout=correlate(versioned,options=replace(qualified_options,timeout_seconds=0.00001))
    assert timeout.errors[0].code=='scanner_timeout'
    original=runner._execute
    def bad(cmd,**kwargs):
        if '--version' in cmd: return original(cmd,**kwargs)
        assert '--offline' in cmd and '--download-offline-databases' not in cmd
        return 0, '{"results":[]}', ''
    monkeypatch.setattr(runner,'_execute',bad)
    report=correlate(versioned,options=qualified_options)
    assert report.status=='partial' and report.components[0].status=='not_assessed'
    assert report.errors[0].code=='scanner_invalid_output'


def test_no_components_is_not_clean_and_no_osv_required_for_identify(tmp_path,demo_db, qualified_options, monkeypatch):
    apk=make_apk(tmp_path/'app.apk',{'classes.dex':make_dex(lib_classes('unknown',5,'V'))})
    with monkeypatch.context() as context:
        context.setattr(runner, 'verify_scanner', lambda *a: pytest.fail('identification tried to load OSV'))
        r=scan(apk,profiles=demo_db)
    assert r.vulnerabilities.status=='not_requested'
    assert AssessmentResult.from_dict(json.loads(r.to_json()))==r
    report=correlate(r.identification,options=qualified_options)
    assert report.status=='not_applicable' and not report.components
    assert report.database and report.scanner


def test_update_and_import_failures_preserve_current(local_db,tmp_path,monkeypatch):
    before=(local_db/'CURRENT.json').read_bytes()
    bad=tmp_path/'bad.zip'; bad.write_bytes(b'bad')
    with pytest.raises(AdvisoryError): provision_advisory_database(local_db,archives={'Maven':bad})
    assert (local_db/'CURRENT.json').read_bytes()==before
    import urllib.request
    monkeypatch.setattr(urllib.request,'urlopen',lambda *a,**k: (_ for _ in ()).throw(OSError('download interrupted')))
    with pytest.raises(AdvisoryError): update_advisory_database(local_db)
    assert (local_db/'CURRENT.json').read_bytes()==before
    validate_advisory_database(local_db)
    original=os.replace
    def interrupted(src,dest):
        if str(dest).endswith('CURRENT.json'): raise OSError('publication interrupted')
        return original(src,dest)
    monkeypatch.setattr(os,'replace',interrupted)
    with pytest.raises(AdvisoryError): provision_advisory_database(local_db,archives={'Maven':archive(tmp_path/'new.zip')})
    assert (local_db/'CURRENT.json').read_bytes()==before
    validate_advisory_database(local_db)


def test_offline_python_network_gate_and_generated_input_only(versioned, qualified_options, monkeypatch):
    import urllib.request
    monkeypatch.setattr(urllib.request,'urlopen',lambda *a,**k: pytest.fail('network call during scan'))
    original=runner._execute
    def inspect_call(cmd,**kwargs):
        assert kwargs['work'].name.startswith('libidentifier-osv-')
        if '--version' not in cmd:
            assert '--offline' in cmd and '--no-resolve' in cmd
            assert '--offline-vulnerabilities' not in cmd and '--download-offline-databases' not in cmd
            path=Path(cmd[-1].removeprefix('osv-scanner:'))
            data=json.loads(path.read_text())
            assert data['results'][0]['packages'][0]['package']=={'ecosystem':'Maven','name':'example:demo','version':'1.0'}
            assert not any('.apk' in a or 'reference.dex' in a for a in cmd)
        return original(cmd,**kwargs)
    monkeypatch.setattr(runner,'_execute',inspect_call)
    assert correlate(versioned,options=qualified_options).components[0].status=='affected'
    assert correlate(versioned,options=replace(qualified_options,database='missing')).status=='blocked'


def test_cli_scan_correlate_and_maintenance(tmp_path, demo_db, qualified_options, capsys):
    apk=make_apk(tmp_path/'app.apk',{'classes.dex':make_dex(lib_classes('lib/alpha'))})
    out=tmp_path/'assessment.json'
    assert main(['scan',str(apk),'--profiles',str(demo_db),'--vulnerabilities','--osv-scanner',str(EXE),'--osv-db',str(qualified_options.database),'--output',str(out)])==0
    r=AssessmentResult.from_dict(json.loads(out.read_text()))
    assert r.identification.components and r.vulnerabilities.components[0].status=='not_assessed'
    inventory=tmp_path/'inventory.json'; r.identification.write_json(inventory)
    assert main(['correlate',str(inventory),'--osv-scanner',str(EXE),'--osv-db',str(qualified_options.database),'--format','table'])==0
    assert 'Advisory assessment: partial' in capsys.readouterr().out
    assert main(['vulnerabilities','validate','--database',str(qualified_options.database)])==0

def test_alias_groups_are_one_finding_with_original_records(tmp_path, versioned, qualified_options):
    src=archive(tmp_path/'aliases.zip',[record('GHSA-TEST-0001'),record('CVE-2099-0001')])
    provision_advisory_database(qualified_options.database,archives={'Maven':src})
    report=correlate(versioned,options=qualified_options)
    assert report.components[0].status=='affected', report.errors
    assert len(report.findings)==1
    assert report.findings[0].related_advisory_ids==['CVE-2099-0001','GHSA-TEST-0001']
    assert len(report.advisories)==2  # distinct source IDs are preserved once each


def test_real_osv_missing_cache_and_empty_input_exit_codes(tmp_path, qualified_options):
    scanner=runner.verify_scanner(qualified_options)
    with pytest.raises(AdvisoryError,match='exit 127'):
        runner.match_versions(scanner,tmp_path/'no-cache',[{'ecosystem':'Maven','name':'example:demo','version':'1.0'}],qualified_options)
    _,stage=database.open_snapshot(qualified_options.database)
    with pytest.raises(AdvisoryError,match='exit 128'):
        runner.match_versions(scanner,stage,[],qualified_options)

def test_correlate_retains_partial_identification(versioned,qualified_options):
    from libidentifier.models import AnalysisError
    inventory=replace(versioned,coverage=replace(versioned.coverage,dex='partial'),
        errors=[AnalysisError('dex_parse_error','classes2.dex','malformed','error')])
    report=correlate(inventory,options=qualified_options)
    assert report.components[0].status=='affected'
    assert report.status=='partial'
    assert report.identification_errors==inventory.errors
    assert report.identification_coverage.dex=='partial'
    assert VulnerabilityReport.from_dict(json.loads(report.to_json()))==report

def test_published_maven_advisory_version_matching(qualified_options):
    live=ROOT/'test-results/tmp/osv/live-db'
    if not (live/'CURRENT.json').is_file(): pytest.skip('explicitly provisioned published Maven snapshot required')
    options=replace(qualified_options,database=live)
    scanner=runner.verify_scanner(options)
    _,stage=database.open_snapshot(live,max_age_days=None)
    packages=[{'ecosystem':'Maven','name':'com.squareup.okhttp3:okhttp','version':v} for v in ('4.9.0','4.9.3')]
    results=runner.match_versions(scanner,stage,packages,options)
    affected=results[('Maven','com.squareup.okhttp3:okhttp','4.9.0')]
    assert any(a['id']=='GHSA-3cqm-mf7h-prrj' and 'CVE-2021-0341' in a['aliases'] for a in affected)
    assert results[('Maven','com.squareup.okhttp3:okhttp','4.9.3')]==[]
