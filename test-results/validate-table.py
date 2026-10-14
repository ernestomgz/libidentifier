"""Real-APK CLI regression for score-based assessment and terminal rendering."""
from pathlib import Path
import contextlib
import hashlib
import io
import json
import os
import tempfile

from libidentifier import AssessmentResult, VulnerabilityOptions, correlate
from libidentifier.cli import main
from libidentifier.table import write_table, cells

root = Path(__file__).resolve().parents[1]
platform = 'windows' if os.name == 'nt' else 'linux'
tempfile.tempdir = str(root / 'test-results/tmp')
out = root / 'test-results/tmp' / ('table-' + platform); out.mkdir(exist_ok=True)
scanner = Path(os.environ.get('LIBIDENTIFIER_TEST_OSV', root / 'test-results/tmp/osv/osv-scanner_windows_amd64.exe'))
database = root / 'test-results/tmp/osv/live-db'
rows = []
for apk in sorted((root / 'samples').glob('*.apk')):
    before = hashlib.sha256(apk.read_bytes()).hexdigest()
    baseline_path = root / 'test-results/tmp' / ('convenience-' + platform) / (apk.name + '.json')
    baseline = AssessmentResult.from_dict(json.loads(baseline_path.read_text(encoding='utf-8')))
    path = out / (apk.name + '.json')
    args = ['identify', str(apk), '--profiles', str(root / 'test-results/sca-reference-profiles.sqlite'),
            '--vulnerabilities', '--offline', '--osv-scanner', str(scanner), '--osv-db', str(database)]
    assert main([*args, '--output', str(path)]) == 0
    result = AssessmentResult.from_dict(json.loads(path.read_text(encoding='utf-8')))
    assert result.identification == baseline.identification
    assert not result.vulnerabilities.errors
    assert all(f.applicability == 'potential' and f.evaluated_version is None for f in result.vulnerabilities.findings)
    for width in (100, 64, 40):
        stream = io.StringIO()
        if width == 100:
            os.environ['COLUMNS'] = '100'
            with contextlib.redirect_stdout(stream):
                assert main([*args, '--format', 'table']) == 0
        else:
            write_table(result.identification, result.vulnerabilities, stream=stream, width=width)
        text = stream.getvalue()
        assert 'VULNERABILITIES' in text
        assert all(cells(line) <= width for line in text.splitlines())
        assert 'CONFIRMED' not in text
        (out / (apk.name + f'.{width}.txt')).write_text(text, encoding='utf-8', newline='\n')
    if apk.name.startswith('ovaa'):
        c = next(c for c in result.identification.components if c.name == 'retrofit')
        a = next(a for a in result.vulnerabilities.components if a.component_id == c.component_id)
        assert c.score >= 0.75 and c.identity_confidence == 'medium' and a.status == 'potential'
        stricter = correlate(result.identification, options=VulnerabilityOptions(scanner, database, min_identity_score=0.85))
        assert next(a for a in stricter.components if a.component_id == c.component_id).reason == 'Identity score below 0.85'
    assert before == hashlib.sha256(apk.read_bytes()).hexdigest()
    rows.append({'sample': apk.name, 'input_sha256': before, 'status': result.vulnerabilities.status,
        'min_identity_score': 0.75, 'components': [{'name': c.name, 'score': c.score,
            'identity_confidence': c.identity_confidence, 'version': c.version,
            'version_candidates': c.version_candidates, 'status': a.status, 'reason': a.reason,
            'advisories': a.advisory_ids} for c, a in zip(result.identification.components, result.vulnerabilities.components)],
        'potential_findings': len(result.vulnerabilities.findings), 'confirmed_findings': 0,
        'scanner': result.vulnerabilities.scanner.to_dict(), 'database': result.vulnerabilities.database.to_dict()})
    print(apk.name, [(c['name'], c['score'], c['status']) for c in rows[-1]['components']], flush=True)
(root / 'test-results' / ('table-validation-' + platform + '.json')).write_text(json.dumps(rows, indent=2) + '\n', encoding='utf-8', newline='\n')
