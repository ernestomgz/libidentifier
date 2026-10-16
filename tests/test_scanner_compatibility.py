"""Distribution-neutral compatibility, optional pinning, and offline cache views."""
from dataclasses import replace
import os
from pathlib import Path
import shutil

import pytest

from libidentifier import VulnerabilityOptions, correlate
from libidentifier.cli import main
from libidentifier.errors import AdvisoryError
from libidentifier.vulnerabilities import runner
from libidentifier.vulnerabilities.database import digest, open_snapshot
from test_offline_assessment import EXE, isolated_temp_root, local_db, versioned


def native(tmp_path):
    path = tmp_path / ('scanner.exe' if os.name == 'nt' else 'scanner')
    path.write_bytes((b'MZ\x00\x00' if os.name == 'nt' else b'\x7fELF') + b'test-only')
    path.chmod(0o755)
    return path


def stub(monkeypatch, version='2.6.0', flags=runner.REQUIRED_FLAGS, help_code=0):
    calls = []
    def execute(cmd, **kwargs):
        calls.append(cmd)
        if '--version' in cmd:
            return 0, f'osv-scanner version: {version}\nosv-scalibr version: 0.5.2\n', ''
        assert cmd[1:] == ['scan', 'source', '--offline', '--help']
        return help_code, '\n'.join('--' + flag for flag in flags), ''
    monkeypatch.setattr(runner, '_execute', execute)
    return calls


@pytest.mark.parametrize('version', ['2.0.0', '2.6.0', '2.7.0', '2.99.0', '2.8.0-rc.1', '2.7.0+packaged.1'])
def test_v2_versions_and_rebuilt_binaries_are_not_hash_whitelisted(tmp_path, monkeypatch, version):
    path = native(tmp_path); calls = stub(monkeypatch, version)
    record = runner.verify_scanner(VulnerabilityOptions(path, tmp_path))
    assert record.version == version and record.sha256 == digest(path)
    assert record.path == str(path) and len(calls) == 2


@pytest.mark.parametrize('version', ['1.9.2', '3.0.0', 'dev', '2.7.0\nosv-scanner version: 2.6.0'])
def test_unknown_or_other_major_is_explicitly_incompatible(tmp_path, monkeypatch, version):
    path = native(tmp_path); stub(monkeypatch, version)
    with pytest.raises(AdvisoryError) as caught:
        runner.verify_scanner(VulnerabilityOptions(path, tmp_path))
    assert caught.value.code == 'scanner_incompatible' and str(path) in str(caught.value)


@pytest.mark.parametrize('flag', runner.REQUIRED_FLAGS)
def test_each_required_offline_capability_is_checked(tmp_path, monkeypatch, flag):
    path = native(tmp_path)
    flags = [f for f in runner.REQUIRED_FLAGS if f != flag] + ['offline-vulnerabilities', 'download-offline-databases']
    stub(monkeypatch, flags=flags)
    with pytest.raises(AdvisoryError) as caught:
        runner.verify_scanner(VulnerabilityOptions(path, tmp_path))
    assert caught.value.code == 'scanner_incompatible' and '--' + flag in str(caught.value)


def test_older_help_exit_and_bad_help_exit(tmp_path, monkeypatch):
    path = native(tmp_path); stub(monkeypatch, help_code=128)
    assert runner.verify_scanner(VulnerabilityOptions(path, tmp_path)).version == '2.6.0'
    stub(monkeypatch, help_code=127)
    with pytest.raises(AdvisoryError, match='help exit 127'):
        runner.verify_scanner(VulnerabilityOptions(path, tmp_path))


def test_optional_sha_pin_is_case_insensitive_and_checked_before_execution(tmp_path, monkeypatch):
    path = native(tmp_path); calls = stub(monkeypatch)
    options = VulnerabilityOptions(path, tmp_path, scanner_sha256='0' * 64)
    with pytest.raises(AdvisoryError) as caught:
        runner.verify_scanner(options)
    assert caught.value.code == 'scanner_unapproved' and not calls
    result = runner.verify_scanner(replace(options, scanner_sha256=digest(path).upper()))
    assert result.sha256 == digest(path)


@pytest.mark.parametrize('value', ['', 'abc', 'z' * 64, 123])
def test_invalid_pin_rejected(value):
    with pytest.raises(ValueError, match='scanner_sha256'):
        VulnerabilityOptions('scanner', 'database', scanner_sha256=value)


def test_two_cache_layouts_and_cross_volume_copy(local_db, tmp_path, monkeypatch):
    _, stage = open_snapshot(local_db)
    sha = digest(stage / 'cache/osv-scalibr/Maven/all.zip')
    for directory in ('linked', 'copied'):
        if directory == 'copied':
            monkeypatch.setattr(os, 'link', lambda *a: (_ for _ in ()).throw(OSError('cross volume')))
        cache = runner._cache_view(stage, tmp_path / directory)
        assert digest(cache / 'osv-scanner/Maven/all.zip') == sha
        assert digest(cache / 'osv-scalibr/Maven/all.zip') == sha
    assert digest(stage / 'cache/osv-scalibr/Maven/all.zip') == sha


def _installed():
    paths = [EXE]
    if value := os.environ.get('LIBIDENTIFIER_TEST_OSV_ALTERNATE'):
        paths.append(Path(value))
    elif os.name == 'nt' and (value := shutil.which('osv-scanner')):
        paths.append(Path(value))
    return list(dict.fromkeys(str(p.resolve()) for p in paths))


@pytest.mark.parametrize('path', _installed())
def test_real_release_and_package_manager_affected_unaffected_and_cli(path, local_db, versioned, tmp_path, monkeypatch):
    if not Path(path).is_file():
        pytest.skip('optional installed scanner unavailable')
    import urllib.request
    monkeypatch.setattr(urllib.request, 'urlopen', lambda *a, **k: pytest.fail('network access during assessment'))
    options = VulnerabilityOptions(path, local_db)
    report = correlate(versioned, options=options)
    assert report.components[0].status == 'affected', report.errors
    assert report.scanner.version.startswith('2.') and report.scanner.sha256 == digest(path)
    c = replace(versioned.components[0], version='3.0', purl='pkg:maven/example/demo@3.0')
    report = correlate(replace(versioned, components=[c]), options=options)
    assert report.components[0].status == 'not_affected' and not report.findings
    inventory = tmp_path / 'inventory.json'; versioned.write_json(inventory)
    assert main(['correlate', str(inventory), '--osv-scanner', path, '--osv-scanner-sha256', digest(path),
                 '--osv-db', str(local_db), '--offline', '--format', 'table']) == 0
