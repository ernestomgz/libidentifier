"""Presentation preserves OSV boundaries and attribution; score gate is inclusive."""
from dataclasses import replace
from io import StringIO
import math

import pytest

from libidentifier import correlate, VulnerabilityOptions
from libidentifier.cli import main
from libidentifier.table import write_table, affected_text, cells, clean
from libidentifier.vulnerabilities.models import AdvisoryRecord
from test_offline_assessment import isolated_temp_root, local_db, qualified_options, versioned


@pytest.mark.parametrize('score,expected', [(0.7499, 'not_assessed'), (0.75, 'affected'), (0.837, 'affected')])
def test_score_gate_overrides_categorical_label(versioned, qualified_options, score, expected):
    c = replace(versioned.components[0], identity_confidence='medium', score=score)
    report = correlate(replace(versioned, components=[c]), options=qualified_options)
    assert report.components[0].status == expected
    assert report.components[0].identity_confidence == 'medium'
    if expected == 'affected':
        assert report.findings[0].evaluated_version == c.version
        assert report.findings[0].identity_confidence == 'medium'
    else:
        assert report.components[0].reason == 'Identity score below 0.75'
        assert not report.findings


def test_configurable_threshold_and_candidates_remain_potential(versioned, qualified_options):
    c = replace(versioned.components[0], identity_confidence='medium', score=0.837, version=None,
                purl=None, version_confidence='unknown', version_candidates=['1.0'])
    inventory = replace(versioned, components=[c])
    report = correlate(inventory, options=qualified_options)
    assert report.components[0].status == 'potential'
    assert report.findings[0].evaluated_version is None
    report = correlate(inventory, options=replace(qualified_options, min_identity_score=0.84))
    assert report.components[0].status == 'not_assessed'
    assert report.components[0].reason == 'Identity score below 0.84'


@pytest.mark.parametrize('value', [-1, 1.01, math.inf, math.nan, True, '0.75'])
def test_invalid_threshold(value):
    with pytest.raises(ValueError, match='min_identity_score'):
        VulnerabilityOptions('scanner', 'db', min_identity_score=value)


@pytest.mark.parametrize('score', [None, math.nan, math.inf, -0.1, 1.1, True])
def test_missing_or_invalid_component_score_is_not_assessed(versioned, qualified_options, score):
    report = correlate(replace(versioned, components=[replace(versioned.components[0], score=score)]),
                       options=qualified_options)
    assert report.components[0].status == 'not_assessed'
    assert report.components[0].reason == 'Identity score unavailable or invalid'


def advisory(ranges=None, versions=None, name='example:demo'):
    return AdvisoryRecord('OSV-TEST', [], '', [], [{'package': {'ecosystem': 'Maven', 'name': name},
        'ranges': ranges or [], 'versions': versions or []}], [], None, None, {})


def r(*events, kind='ECOSYSTEM'):
    return {'type': kind, 'events': list(events)}


@pytest.mark.parametrize('ranges,expected', [
    ([r({'introduced': '0'}, {'fixed': '4.9.2'})], 'before 4.9.2'),
    ([r({'introduced': '0'}, {'last_affected': '3.1.1'})], 'up to 3.1.1 inclusive'),
    ([r({'fixed': '2.0-rc1'}, {'introduced': '1.0.Final'})], '1.0.Final inclusive to 2.0-rc1 exclusive'),
    ([r({'introduced': '1.0'}, {'fixed': '1.2'}), r({'introduced': '3.0'}, {'fixed': '3.2'})],
     '1.0 inclusive to 1.2 exclusive OR 3.0 inclusive to 3.2 exclusive'),
    ([r({'introduced': '1.0'})], 'from 1.0 onward'),
    ([r({'introduced': '0'})], 'all versions'),
    ([r({'introduced': '0'}, {'limit': '2'})], 'ECOSYSTEM events: introduced 0; limit 2'),
    ([r({'introduced': '3'}, {'fixed': '3.2'}, {'introduced': '1'}, {'fixed': '1.2'})],
     'ECOSYSTEM events: introduced 3; fixed 3.2; introduced 1; fixed 1.2'),
    ([r({'introduced': '0'}, {'fixed': '2'}, kind='SEMVER')], 'SemVer: before 2'),
])
def test_affected_ranges_preserve_boundaries(ranges, expected):
    assert affected_text([advisory(ranges)], ('Maven', 'example:demo')) == expected


def test_missing_ranges_versions_and_package_attribution():
    assert affected_text([advisory()], ('Maven', 'example:demo')) is None
    nullable = advisory(); nullable.affected[0]['ranges'] = None
    assert affected_text([nullable], ('Maven', 'example:demo')) is None
    assert affected_text([advisory([r({'introduced': '0'}, {'fixed': '2'})], name='other:package')],
                         ('Maven', 'example:demo')) is None
    git = r({'introduced': 'abcdef'}, kind='GIT')
    assert affected_text([advisory([git])], ('Maven', 'example:demo')) is None
    assert affected_text([advisory(versions=['1.0', '1.0.Final'])], ('Maven', 'example:demo')) == 'listed versions: 1.0, 1.0.Final'
    text = affected_text([advisory([r({'introduced': '0'}, {'fixed': '2'}), git])], ('Maven', 'example:demo'))
    assert text == 'before 2 (additional ranges in JSON)'
    for malformed in (None, {}, r({'fixed': '2'}), r({'introduced': '0', 'fixed': '2'})):
        assert affected_text([advisory([malformed])], ('Maven', 'example:demo')) is None
    many = affected_text([advisory(versions=[str(n) for n in range(100)])], ('Maven', 'example:demo'))
    assert many == '100 explicitly listed versions (see JSON)'


@pytest.mark.parametrize('width', [100, 64, 40, 20, 8])
def test_table_wraps_long_unicode_and_ansi_without_escape_leaks(versioned, qualified_options, width):
    name = '\x1b[31mVeryLongLibrary名稱\x1b[0m' + 'x' * 100
    c = replace(versioned.components[0], name=name, version=None, purl=None,
                version_confidence='unknown', version_candidates=['1.' + '0' * 60, '2.0'])
    inventory = replace(versioned, components=[c])
    report = correlate(inventory, options=qualified_options)
    output = StringIO()
    write_table(inventory, report, stream=output, width=width)
    text = output.getvalue()
    assert '\x1b' not in text
    assert all(cells(line) <= width for line in text.splitlines())
    assert 'POTENTIAL' in ''.join(text.split())
    assert 'VeryLongLibrary' in ''.join(text.split())
    # Plain identify/scan without assessment never emits a vulnerability section.
    output = StringIO(); write_table(inventory, stream=output, width=width)
    assert 'VULNERABILITIES' not in output.getvalue()


def test_table_confirms_only_real_version_and_shows_failures(versioned, qualified_options, monkeypatch):
    report = correlate(versioned, options=qualified_options)
    output = StringIO(); write_table(versioned, report, stream=output)
    assert 'CONFIRMED' in output.getvalue() and 'Affected: before 2.0' in output.getvalue()
    assert 'Aliases: OSV-TEST-0001' in output.getvalue()
    qualified = replace(report, components=[replace(a, family_purl=a.family_purl + '?type=jar') for a in report.components])
    output = StringIO(); write_table(report=qualified, stream=output)
    assert 'Affected: before 2.0' in output.getvalue()
    no_ranges = replace(report, advisories=[replace(a, affected=[]) for a in report.advisories])
    output = StringIO(); write_table(versioned, no_ranges, stream=output)
    assert 'Affected:' not in output.getvalue()
    import importlib
    module = importlib.import_module('libidentifier.vulnerabilities.correlate')
    from libidentifier.errors import AdvisoryError
    monkeypatch.setattr(module, 'match_versions', lambda *a: (_ for _ in ()).throw(AdvisoryError('timeout', code='scanner_timeout')))
    failed = correlate(versioned, options=qualified_options)
    output = StringIO(); write_table(versioned, failed, stream=output)
    assert 'Failed' in output.getvalue() and 'CONFIRMED' not in output.getvalue()
    assert 'scanner_timeout' in output.getvalue()


def test_cli_threshold_and_no_ranges_message_when_unavailable(tmp_path, versioned, qualified_options, capsys):
    c = replace(versioned.components[0], score=0.837, identity_confidence='medium')
    inventory = replace(versioned, components=[c]); path = tmp_path / 'inventory.json'; inventory.write_json(path)
    common = ['correlate', str(path), '--osv-scanner', str(qualified_options.scanner), '--osv-db',
              str(qualified_options.database), '--offline', '--format', 'table']
    assert main(common) == 0
    assert 'CONFIRMED' in capsys.readouterr().out
    assert main([*common, '--min-identity-score', '0.84']) == 0
    output = capsys.readouterr().out
    assert 'identity score below 0.84' in output and 'Affected:' not in output
