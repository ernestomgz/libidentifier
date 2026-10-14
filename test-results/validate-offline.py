from pathlib import Path
import hashlib,json,tempfile,os
from libidentifier import scan, VulnerabilityOptions
root=Path.cwd()
tempfile.tempdir=str(root/'test-results/tmp')
options=VulnerabilityOptions(Path(os.environ.get('LIBIDENTIFIER_TEST_OSV',root/'test-results/tmp/osv/osv-scanner_windows_amd64.exe')),root/'test-results/tmp/osv/live-db')
platform=os.environ.get('LIBIDENTIFIER_VALIDATION_SUFFIX','windows')
previous=json.loads((root/'test-results/sca-readiness-validation.json').read_text())
old={s['sample']:s for s in previous['samples']}
output=root/('test-results/tmp/offline' if platform=='windows' else 'test-results/tmp/offline-'+platform);output.mkdir(exist_ok=True)
rows=[]
for apk in sorted((root/'samples').glob('*.apk')):
    before=hashlib.sha256(apk.read_bytes()).hexdigest()
    r=scan(apk,profiles=root/'test-results/sca-reference-profiles.sqlite',vulnerabilities=options)
    expected=old[apk.name]['scans']['targeted']
    assert [c.name for c in r.identification.components]==[c['name'] for c in expected['components']]
    assert [(f.name,f.confidence,f.framework_id,[(e.indicator,e.location.member,e.location.class_descriptor,e.location.sha256) for e in f.evidence_records]) for f in r.identification.frameworks_detected]==[(f['name'],f['confidence'],f['framework_id'],[(e['indicator'],e['location']['member'],e['location']['class_descriptor'],e['location']['sha256']) for e in f['evidence_records']]) for f in expected['frameworks']]
    assert all(c.version is None and c.version_confidence=='unknown' for c in r.identification.components)
    assert len(r.identification.unknown_classes)==r.identification.coverage.unknown_classes_total
    assert not r.identification.coverage.unknown_classes_truncated
    assert not r.identification.errors and not r.vulnerabilities.errors, r.vulnerabilities.errors
    assert all(f.applicability=='potential' and f.evaluated_version is None for f in r.vulnerabilities.findings)
    assert before==hashlib.sha256(apk.read_bytes()).hexdigest()
    r.write_json(output/(apk.name+'.json'))
    rows.append({'sample':apk.name,'input_sha256':before,'libraries':[c.name for c in r.identification.components],
        'unknown_classes':len(r.identification.unknown_classes),'frameworks':[f.name for f in r.identification.frameworks_detected],
        'assessment_status':r.vulnerabilities.status,'components':[a.to_dict()|{'evidence_count':len(a.evidence)} for a in r.vulnerabilities.components],
        'advisories':[a.id for a in r.vulnerabilities.advisories], 'confirmed_findings':0,
        'potential_findings':len(r.vulnerabilities.findings),'scanner':r.vulnerabilities.scanner.to_dict(),
        'database':r.vulnerabilities.database.to_dict()})
    for c in rows[-1]['components']:c.pop('evidence')
    print(apk.name,rows[-1]['unknown_classes'],r.vulnerabilities.status,rows[-1]['potential_findings'],'potential; 0 confirmed',flush=True)
(root/('test-results/offline-assessment-validation.json' if platform=='windows' else 'test-results/offline-assessment-validation-'+platform+'.json')).write_text(json.dumps(rows,indent=2)+'\n',encoding='utf-8')
