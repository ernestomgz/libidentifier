"""Exercise CLI discovery/default database against all preserved sample APKs."""
from pathlib import Path
import hashlib
import json
import os
import sys
import tempfile

from libidentifier.cli import main
from libidentifier import AssessmentResult, provision_advisory_database
from libidentifier.vulnerabilities.database import open_snapshot

root = Path(__file__).resolve().parents[1]
platform = 'windows' if os.name == 'nt' else 'linux'
work = root / 'test-results/tmp' / ('convenience-' + platform)
work.mkdir(exist_ok=True)
tempfile.tempdir = str(work)
tools = work / 'tools'; tools.mkdir(exist_ok=True)
scanner = Path(os.environ.get('LIBIDENTIFIER_TEST_OSV', root / 'test-results/tmp/osv/osv-scanner_windows_amd64.exe'))
installed = tools / ('osv-scanner.exe' if os.name == 'nt' else 'osv-scanner')
if not installed.exists():
    os.link(scanner, installed)
os.environ['PATH'] = str(tools)
os.chdir(work)
bootstrap = '--bootstrap' in sys.argv
if not bootstrap:
    record, stage = open_snapshot(root / 'test-results/tmp/osv/live-db')
    provision_advisory_database(work / 'advisory-db',
        archives={'Maven': stage / 'cache/osv-scalibr/Maven/all.zip'}, fetched_at=record.fetched_at)
else:
    assert not (work / 'downloaded-db').exists()
old = {row['sample']: row for row in json.loads((root / 'test-results/offline-assessment-validation.json').read_text())}
rows = []
for i, apk in enumerate(sorted((root / 'samples').glob('*.apk'))):
    before = hashlib.sha256(apk.read_bytes()).hexdigest()
    output = work / (apk.name + '.json')
    argv = ['identify', str(apk), '--profiles', str(root / 'test-results/sca-reference-profiles.sqlite'),
            '--vulnerabilities', '--output', str(output)]
    if bootstrap:
        argv += ['--osv-db', str(work / 'downloaded-db'), '--osv-timeout', '120']
    if not bootstrap or i:
        argv += ['--offline']
    assert main(argv) == 0
    result = AssessmentResult.from_dict(json.loads(output.read_text(encoding='utf-8')))
    identity, report = result.identification, result.vulnerabilities
    assert not report.errors and not identity.errors
    assert [c.name for c in identity.components] == old[apk.name]['libraries']
    assert [f.name for f in identity.frameworks_detected] == old[apk.name]['frameworks']
    assert len(identity.unknown_classes) == old[apk.name]['unknown_classes']
    assert all(c.version is None and c.version_confidence == 'unknown' for c in identity.components)
    assert all(f.applicability == 'potential' and f.evaluated_version is None for f in report.findings)
    assert before == hashlib.sha256(apk.read_bytes()).hexdigest()
    rows.append({'sample': apk.name, 'input_sha256': before,
        'libraries': [c.name for c in identity.components],
        'frameworks': [f.name for f in identity.frameworks_detected],
        'unknown_classes': len(identity.unknown_classes), 'status': report.status,
        'potential_findings': len(report.findings), 'confirmed_findings': 0,
        'scanner': report.scanner.to_dict(), 'database': report.database.to_dict()})
    print(apk.name, report.status, len(report.findings), 'potential; zero confirmed', flush=True)
(root / 'test-results' / ('osv-convenience-validation-' + platform + '.json')).write_text(
    json.dumps(rows, indent=2) + '\n', encoding='utf-8')
