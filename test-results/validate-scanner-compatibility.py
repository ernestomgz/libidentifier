"""Reassess six real APK inventories with installed official scanner releases."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import tempfile

from libidentifier import AssessmentResult, VulnerabilityOptions, correlate
from libidentifier.vulnerabilities.runner import verify_scanner
from libidentifier.vulnerabilities.setup import discover_scanner

root = Path(__file__).resolve().parents[1]
platform = 'windows' if os.name == 'nt' else 'linux'
tempfile.tempdir = str(root / 'test-results/tmp')
github = root / 'test-results/tmp/osv' / ('osv-scanner_windows_amd64.exe' if os.name == 'nt' else 'osv-scanner_linux_amd64')
alternate = (shutil.which('osv-scanner') if os.name == 'nt' else
             os.environ.get('LIBIDENTIFIER_TEST_OSV_ALTERNATE', str(root / 'test-results/tmp/osv/v2.6.0-osv-scanner_linux_amd64')))
paths = list(dict.fromkeys(str(Path(p).resolve()) for p in (github, alternate) if p))
rows = []
for path in paths:
    options = VulnerabilityOptions(path, root / 'test-results/tmp/osv/live-db')
    scanner = verify_scanner(options)
    samples = []
    for inventory in sorted((root / 'test-results/tmp' / ('table-' + platform)).glob('*.apk.json')):
        baseline = AssessmentResult.from_dict(json.loads(inventory.read_text(encoding='utf-8')))
        apk = Path(baseline.identification.input.path)
        with apk.open('rb') as source:
            assert hashlib.file_digest(source, 'sha256').hexdigest() == baseline.identification.input.sha256
        report = correlate(baseline.identification, options=options)
        assert not report.errors
        signature = lambda r: [(a.component_id, a.status, a.evaluated_version, a.advisory_ids) for a in r.components]
        assert signature(report) == signature(baseline.vulnerabilities)
        assert report.findings == baseline.vulnerabilities.findings
        assert report.advisories == baseline.vulnerabilities.advisories
        assert all(f.applicability == 'potential' and f.evaluated_version is None for f in report.findings)
        samples.append({'sample': apk.name, 'status': report.status, 'potential_findings': len(report.findings)})
    assert len(samples) == 6
    rows.append({'scanner': scanner.to_dict(), 'samples': samples})
    print(platform, scanner.version, len(samples), 'cached APK inventories; results unchanged', flush=True)
if os.name == 'nt':
    print('Default discovery:', discover_scanner(), flush=True)
(root / 'test-results' / ('scanner-compatibility-' + platform + '.json')).write_text(
    json.dumps(rows, indent=2) + '\n', encoding='utf-8', newline='\n')
