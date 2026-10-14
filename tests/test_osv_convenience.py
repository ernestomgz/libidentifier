"""CLI preparation is separate from strictly offline correlation."""
import json
import os
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from libidentifier.cli import main, build_parser
from libidentifier.errors import AdvisoryError
from libidentifier.vulnerabilities import setup
from libidentifier import AssessmentResult, provision_advisory_database
from test_offline_assessment import (EXE, archive, isolated_temp_root, local_db,
                                     qualified_options, versioned)


@pytest.fixture
def installed(tmp_path, monkeypatch, qualified_options, scanner_installation):
    exe = scanner_installation
    monkeypatch.setenv('PATH', str(exe.parent))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(setup, 'user_database', lambda: qualified_options.database)
    return exe


@pytest.fixture(scope='session')
def scanner_installation(tmp_path_factory):
    if not EXE.is_file():
        pytest.skip('qualified OSV executable not installed')
    tools = tmp_path_factory.mktemp('installed-osv')
    exe = tools / ('osv-scanner_windows_amd64.exe' if os.name == 'nt' else 'osv-scanner_linux_amd64')
    shutil.copyfile(EXE, exe)  # One copy per session, including restricted Windows hosts.
    exe.chmod(0o755)
    return exe


def args(*values):
    return build_parser().parse_args(['correlate', 'inventory.json', *values])


@pytest.mark.parametrize('system', ['nt', 'posix'])
@pytest.mark.parametrize('machine', ['AMD64', 'ARM64', 'aarch64'])
def test_release_names_and_native_architecture_priority(system, machine):
    names = setup._scanner_names(system, machine)
    arch = 'arm64' if machine.lower() in {'arm64', 'aarch64'} else 'amd64'
    suffix = '.exe' if system == 'nt' else ''
    target = 'windows' if system == 'nt' else 'linux'
    assert names[2] == f'osv-scanner_{target}_{arch}{suffix}'
    assert set(names) == {'osv-scanner', 'osv-scanner.exe',
        f'osv-scanner_{target}_amd64{suffix}', f'osv-scanner_{target}_arm64{suffix}'}


@pytest.mark.parametrize('index', range(4))
def test_each_executable_name_discovered_in_path_and_cwd(tmp_path, monkeypatch, index):
    name = setup._scanner_names(os.name, 'amd64')[index]
    executable = tmp_path / name
    executable.write_bytes(b'discovery only'); executable.chmod(0o755)
    monkeypatch.setenv('PATH', '')
    monkeypatch.chdir(tmp_path)
    assert setup.discover_scanner() == executable
    elsewhere = tmp_path / 'elsewhere'; elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.setenv('PATH', str(tmp_path))
    assert setup.discover_scanner() == executable


def test_checksums_and_foreign_release_names_are_not_executables(tmp_path, monkeypatch):
    for name in ('osv-scanner_SHA256SUMS', 'osv-scanner_darwin_amd64', 'osv-scanner_darwin_arm64',
                 'osv-scanner_linux_amd64' if os.name == 'nt' else 'osv-scanner_windows_amd64.exe'):
        candidate = tmp_path / name
        candidate.write_bytes(b'not a supported executable'); candidate.chmod(0o755)
    monkeypatch.chdir(tmp_path); monkeypatch.setenv('PATH', str(tmp_path))
    with pytest.raises(AdvisoryError, match='not found'):
        setup.discover_scanner()


def test_discovery_priorities(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('PATH', '')
    with pytest.raises(AdvisoryError, match='not found'):
        setup.discover_scanner()
    name = 'osv-scanner.exe' if os.name == 'nt' else 'osv-scanner'
    cwd = tmp_path / name
    cwd.write_bytes(b'unapproved'); cwd.chmod(0o755)
    assert setup.discover_scanner() == cwd
    tools = tmp_path / 'tools'; tools.mkdir()
    other = tools / name; other.write_bytes(b'unapproved'); other.chmod(0o755)
    monkeypatch.setenv('PATH', str(tools))
    assert setup.discover_scanner() == other
    assert setup.discover_scanner(tmp_path / 'missing') == tmp_path / 'missing'
    cache = tmp_path / 'cache'
    monkeypatch.setattr(setup, 'user_database', lambda: cache)
    assert setup.discover_database() == cache
    local = tmp_path / 'advisory-db'; local.mkdir()
    assert setup.discover_database() == local
    assert setup.discover_database(tmp_path / 'override') == tmp_path / 'override'


def test_missing_scanner_fallback_and_plain_identification(tmp_path, monkeypatch, versioned, capsys):
    monkeypatch.chdir(tmp_path); monkeypatch.setenv('PATH', '')
    monkeypatch.setattr(setup, 'update_advisory_database', lambda *a, **k: pytest.fail('unexpected download'))
    profiles = tmp_path / 'profiles.sqlite'; dex = tmp_path / 'reference.dex'
    assert main(['identify', str(dex), '--profiles', str(profiles)]) == 0
    plain = json.loads(capsys.readouterr().out)
    assert 'result_kind' not in plain
    for command in ('identify', 'scan'):
        assert main([command, str(dex), '--profiles', str(profiles), '--vulnerabilities']) == 0
        output = capsys.readouterr()
        result = AssessmentResult.from_dict(json.loads(output.out))
        assert result.identification.to_dict() == plain
        assert result.vulnerabilities.status == 'blocked'
        assert result.vulnerabilities.components[0].status == 'not_assessed'
        assert result.vulnerabilities.components[0].reason == 'scanner_missing'
        assert result.vulnerabilities.errors[0].code == 'scanner_missing'
        assert 'warning' in output.err and 'scanner_missing' in output.err
        assert 'https://github.com/google/osv-scanner/releases' in output.err


def test_discovered_real_scanner_and_tables(installed, versioned, capsys, monkeypatch):
    monkeypatch.setattr(setup, 'update_advisory_database', lambda *a, **k: pytest.fail('unexpected download'))
    assert setup.prepare_options(args('--offline')).scanner == installed
    inventory = Path('inventory.json'); versioned.write_json(inventory)
    assert main(['correlate', str(inventory), '--offline', '--format', 'table']) == 0
    table = capsys.readouterr().out
    assert 'OSV-TEST-0001' in table and 'CVE-2099-0001' in table
    assert 'confirmed version match' in table
    unknown = replace(versioned, components=[replace(versioned.components[0], version=None,
        purl=None, version_confidence='unknown', version_candidates=['1.0'])])
    unknown.write_json(inventory)
    assert main(['correlate', str(inventory), '--offline', '--format', 'table']) == 0
    assert 'POTENTIAL' in capsys.readouterr().out


def test_automatic_provision_and_existing_database_no_download(installed, tmp_path, monkeypatch):
    cache = tmp_path / 'new-cache'
    monkeypatch.setattr(setup, 'user_database', lambda: cache)
    calls = []
    def provision(destination, **kwargs):
        calls.append(destination)
        return provision_advisory_database(destination, archives={'Maven': archive(tmp_path / 'feed.zip')})
    monkeypatch.setattr(setup, 'update_advisory_database', provision)
    assert setup.prepare_options(args('--offline')).database == cache
    assert not calls and not cache.exists()
    assert setup.prepare_options(args()).database == cache
    assert calls == [cache]
    setup.prepare_options(args())
    assert calls == [cache]
    local = tmp_path / 'advisory-db'; local.mkdir()
    assert setup.prepare_options(args()).database == local
    assert calls == [cache]  # Existing invalid local directory is not overwritten.
    explicit = tmp_path / 'explicit'
    assert setup.prepare_options(args('--osv-db', str(explicit))).database == explicit
    assert calls == [cache, explicit]


@pytest.mark.parametrize('failure', ['offline', 'download', 'explicit_missing', 'unapproved', 'corrupt'])
def test_preparation_failure_retains_inventory(installed, tmp_path, versioned, monkeypatch, capsys, failure):
    db = tmp_path / 'missing-db'
    monkeypatch.setattr(setup, 'user_database', lambda: db)
    def fail(*a, **k):
        raise OSError('download interrupted')
    monkeypatch.setattr(setup, 'update_advisory_database', fail)
    extra = []
    expected = 'database_provision_failed'
    exit_code = 3
    if failure == 'offline':
        extra = ['--offline']; expected = 'database_unavailable'
    elif failure == 'explicit_missing':
        extra = ['--osv-scanner', str(tmp_path / 'absent')]
        expected = 'scanner_missing'; exit_code = 0
    elif failure == 'unapproved':
        fake = tmp_path / 'fake.exe'; fake.write_bytes(b'fake')
        extra = ['--osv-scanner', str(fake)]; expected = 'scanner_unapproved'
    elif failure == 'corrupt':
        db.mkdir(); (db / 'CURRENT.json').write_text('bad')
        expected = 'database_unavailable'
    output = tmp_path / 'output.json'
    assert main(['identify', str(tmp_path / 'reference.dex'), '--profiles', str(tmp_path / 'profiles.sqlite'),
                 '--vulnerabilities', '--output', str(output), *extra]) == exit_code
    result = AssessmentResult.from_dict(json.loads(output.read_text()))
    assert result.identification == versioned
    assert result.vulnerabilities.errors[0].code == expected
    assert result.vulnerabilities.components[0].status == 'not_assessed'
    assert capsys.readouterr().err
