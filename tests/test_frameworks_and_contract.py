from pathlib import Path
import inspect as signatures
import json
import sqlite3

import pytest

from libidentifier import IdentifyOptions, ScanResult, identify, inspect
from libidentifier.cli import main
from libidentifier.errors import InputError, ProfileError
from libidentifier.extractors.metadata import RULES
from libidentifier.models import FrameworkHint
from conftest import make_apk, make_dex, make_minimal_elf, lib_classes


@pytest.mark.parametrize('framework_id', sorted(RULES))
def test_exact_definitions_weak_and_corroborated(tmp_path, framework_id):
    name, descriptors, _, _ = RULES[framework_id]
    descriptors = sorted(descriptors)
    apk = make_apk(tmp_path / 'app.apk', {'classes2.dex': make_dex([{'descriptor': descriptors[0]}])})
    weak = inspect(apk).frameworks_detected
    assert len(weak) == 1
    assert (weak[0].framework_id, weak[0].name, weak[0].confidence) == (framework_id, name, 'low')
    loc = weak[0].evidence_records[0].location
    assert (loc.container, loc.member, loc.class_descriptor) == (str(apk), 'classes2.dex', descriptors[0])
    assert len(loc.sha256) == 64
    make_apk(apk, {'classes2.dex': make_dex([{'descriptor': d} for d in descriptors[:2]])})
    strong = inspect(apk).frameworks_detected[0]
    assert strong.confidence == 'medium'
    assert len(strong.evidence_records) == 2
    assert strong.application_logic == ('dex_structure_only' if framework_id == 'jetpack_compose' else 'not_supported')


@pytest.mark.parametrize('native,asset', [
    ('libflutter.so', 'assets/flutter_assets/AssetManifest.json'),
    ('libreactnative.so', 'assets/index.android.bundle'),
    ('libunity.so', 'assets/bin/Data/globalgamemanagers'),
    ('libmonodroid.so', 'assemblies/Microsoft.Maui.Controls.dll'),
])
def test_native_needs_corroboration(tmp_path, native, asset):
    apk = tmp_path / 'app.apk'
    make_apk(apk, {'lib/arm64-v8a/' + native: make_minimal_elf()})
    assert not inspect(apk).frameworks_detected
    make_apk(apk, {'lib/arm64-v8a/' + native: make_minimal_elf(), asset: b'fixture'})
    result = inspect(apk)
    assert len(result.frameworks_detected) == 1
    hint = result.frameworks_detected[0]
    assert hint.confidence == 'medium'
    assert {e.location.member for e in hint.evidence_records} == {'lib/arm64-v8a/' + native, asset}
    # An unparseable filename and asset layout do not establish a runtime.
    make_apk(apk, {'lib/arm64-v8a/' + native: b'not an ELF', asset: b'fixture'})
    assert not inspect(apk).frameworks_detected


def test_generic_and_reference_only_types_are_negative(tmp_path):
    classes = [{'descriptor': 'Lexample/App;', 'fields': [
        {'name': 'engine', 'type': 'Lio/flutter/embedding/engine/FlutterEngine;'}]},
        {'descriptor': 'Landroidx/activity/ComponentActivity;'},
        {'descriptor': 'Lkotlin/jvm/internal/Intrinsics;'},
        {'descriptor': 'Lcom/facebook/react/Unrelated;'}]
    apk = make_apk(tmp_path / 'app.apk', {'classes.dex': make_dex(classes),
        'assets/www/cordova.js': b'unrelated', 'assets/index.android.bundle': b'anything',
        'lib/arm64-v8a/libapp.so': make_minimal_elf()})
    assert not inspect(apk).frameworks_detected


def test_multiple_frameworks_api_json_table(tmp_path, demo_db, capsys):
    classes = lib_classes('lib/alpha') + [
        {'descriptor': d} for _, descriptors, _, _ in RULES.values() for d in sorted(descriptors)]
    apk = make_apk(tmp_path / 'all.apk', {'classes.dex': make_dex(classes),
        'lib/arm64-v8a/libflutter.so': make_minimal_elf(),
        'assets/flutter_assets/AssetManifest.json': b'{}',
        'assets/www/cordova.js': b'cordova.define("cordova", function(){})'})
    r = identify(apk, profiles=demo_db)
    assert {f.framework_id for f in r.frameworks_detected} == set(RULES)
    assert next(f for f in r.frameworks_detected if f.framework_id == 'flutter').confidence == 'high'
    payload = json.loads(r.to_json())
    assert ScanResult.from_dict(payload).to_dict() == r.to_dict()
    out = tmp_path / 'out.json'
    assert main(['identify', str(apk), '--profiles', str(demo_db), '--output', str(out)]) == 0
    assert json.loads(out.read_text()) == payload
    assert main(['identify', str(apk), '--profiles', str(demo_db), '--format', 'table']) == 0
    table = capsys.readouterr().out
    assert 'libalpha\t' in table
    for f in r.frameworks_detected:
        assert f'{f.name}\t{f.confidence}\t' in table
    assert 'classes.dex:Lio/flutter/' in table
    assert inspect(apk).frameworks_detected == r.frameworks_detected
    assert r.to_json() == identify(apk, profiles=demo_db).to_json()
    for hint in payload['frameworks_detected']:
        hint['future'] = True
        for record in hint['evidence_records']:
            record['future'] = True
            record['location']['future'] = True
    assert ScanResult.from_dict(payload).to_dict() == r.to_dict()


def test_public_signatures_and_legacy_hint():
    assert str(signatures.signature(identify)) == "(path, *, profiles, options: 'IdentifyOptions | None' = None) -> 'ScanResult'"
    assert str(signatures.signature(inspect)) == "(path, *, options: 'IdentifyOptions | None' = None) -> 'ScanResult'"
    assert IdentifyOptions().max_emitted_unknown_classes is None
    old = {'name': 'Flutter', 'evidence': 'libflutter.so', 'member': 'lib/a/libflutter.so', 'confidence': 'low', 'limitations': []}
    hint = FrameworkHint.from_dict(old)
    assert FrameworkHint('Flutter', 'libflutter.so', 'lib/a/libflutter.so') == hint
    assert hint.evidence_records == [] and hint.framework_id is None


def test_schema_contract_and_additive_fields(tmp_path, demo_db):
    dex = make_apk(tmp_path / 'library.apk', {'classes.dex': make_dex(lib_classes('lib/alpha'))})
    r = identify(dex, profiles=demo_db)
    data = r.to_dict()
    assert set(data) == {'schema_version', 'tool_name', 'tool_version', 'fingerprint_algorithm',
        'profile_database', 'input', 'analyzed_files', 'frameworks_detected', 'components',
        'class_ownership_hints', 'unknown_classes', 'coverage', 'errors'}
    assert data['schema_version'] == 1
    c = data['components'][0]
    assert set(c) == {'component_id', 'name', 'ecosystem', 'purl', 'version', 'version_candidates',
        'identity_confidence', 'version_confidence', 'identification_methods', 'score', 'score_details',
        'matched_code', 'source_artifacts', 'limitations', 'family_purl',
        'version_candidates_total', 'version_candidates_truncated'}
    assert c['version'] is None and c['version_confidence'] == 'unknown'
    assert c['version_candidates'] == ['1.0.0']
    data['future'] = True
    for child in [data['input'], data['coverage'], data['profile_database'], c,
                  c['matched_code'][0], data['analyzed_files'][0], data['class_ownership_hints'][0]]:
        child['future'] = True
    assert ScanResult.from_dict(data).to_dict() == r.to_dict()
    data['schema_version'] = 2
    with pytest.raises(ValueError, match='unsupported scan schema'):
        ScanResult.from_dict(data)


def test_missing_corrupt_incompatible_databases_and_input(tmp_path, demo_db, capsys):
    dex = tmp_path / 'input.dex'
    dex.write_bytes(make_dex(lib_classes('example')))
    missing = tmp_path / 'missing.sqlite'
    with pytest.raises(ProfileError, match='does not exist'):
        identify(dex, profiles=missing)
    assert not missing.exists()
    corrupt = tmp_path / 'corrupt.sqlite'
    corrupt.write_bytes(b'not SQLite')
    with pytest.raises(ProfileError):
        identify(dex, profiles=corrupt)
    conn = sqlite3.connect(demo_db)
    conn.execute("UPDATE db_meta SET value='future' WHERE key='fingerprint_algorithm'")
    conn.commit()
    conn.close()
    with pytest.raises(ProfileError, match='incompatible'):
        identify(dex, profiles=demo_db)
    with pytest.raises(InputError):
        identify(tmp_path / 'missing.apk', profiles=missing)
    assert main(['identify', str(dex), '--profiles', str(missing)]) == 3
    assert 'profile database' in capsys.readouterr().err


def test_partial_and_directory_results(tmp_path, demo_db):
    folder = tmp_path / 'inputs'
    folder.mkdir()
    apk = make_apk(folder / 'app.apk', {'classes.dex': b'dex\n035\0bad',
        'classes2.dex': make_dex([{'descriptor': 'Lorg/apache/cordova/CordovaActivity;'}])})
    r = identify(folder, profiles=demo_db)
    assert r.coverage.dex == 'partial'
    assert r.errors[0].severity == 'error'
    payload = r.to_dict()
    payload['errors'][0]['future'] = True
    payload['unknown_classes'][0]['future'] = True
    assert ScanResult.from_dict(payload).to_dict() == r.to_dict()
    assert r.frameworks_detected[0].evidence_records[0].location.container == str(apk)
    assert r.frameworks_detected[0].evidence_records[0].location.member == 'classes2.dex'
    skipped = inspect(apk, options=IdentifyOptions(max_member_uncompressed_bytes=8))
    assert skipped.coverage.dex == 'partial'
    assert skipped.coverage.limitations


def test_injured_android_flutter():
    apk = Path(__file__).resolve().parents[1] / 'samples/InjuredAndroid-1.0.12-release.apk'
    if not apk.exists():
        pytest.skip('real sample not present')
    result = inspect(apk)
    flutter = next(f for f in result.frameworks_detected if f.framework_id == 'flutter')
    assert flutter.confidence == 'high'
    assert flutter.application_logic == 'not_supported'
    assert any(e.location.class_descriptor == 'Lio/flutter/embedding/android/FlutterActivity;' for e in flutter.evidence_records)
    assert any(e.location.member == 'assets/flutter_assets/AssetManifest.json' for e in flutter.evidence_records)
    assert len([e for e in flutter.evidence_records if e.location.member.endswith('/libflutter.so')]) == 3


def test_cordova_content_corroborates_definition(tmp_path):
    apk = tmp_path / 'cordova.apk'
    members = {'classes.dex': make_dex([{'descriptor': 'Lorg/apache/cordova/CordovaActivity;'}]),
               'assets/www/cordova.js': b'unrelated'}
    assert inspect(make_apk(apk, members)).frameworks_detected[0].confidence == 'low'
    members['assets/www/cordova.js'] = b'cordova.define("cordova", function(){})'
    hint = inspect(make_apk(apk, members)).frameworks_detected[0]
    assert hint.confidence == 'medium'
    assert any(e.location.member == 'assets/www/cordova.js' for e in hint.evidence_records)


def test_elf_metadata_evidence(tmp_path):
    # Exercise extracted ELF metadata as value objects, not mocked LIEF parsers.
    from dataclasses import replace
    from libidentifier.extractors.elf import parse_elf
    from libidentifier.extractors.metadata import detect_frameworks
    from libidentifier.models import ArtifactRecord
    elf = replace(parse_elf(make_minimal_elf()), soname='libflutter.so',
                  exported_symbols=('FlutterEngineRun',))
    artifact = ArtifactRecord('lib/arm64-v8a/renamed.so', 'elf', elf.sha256, 'analyzed')
    hint = detect_frameworks([], [], [(elf, artifact)], container='app.apk')[0]
    assert hint.confidence == 'medium'
    assert {e.indicator for e in hint.evidence_records} == {
        'parsed ELF runtime: libflutter.so', 'ELF exported symbol: FlutterEngineRun'}
    assert all(e.location.member == artifact.member for e in hint.evidence_records)


def test_release_algorithm_and_missing_schema_rejected(tmp_path, demo_db):
    dex = tmp_path / 'input.dex'
    dex.write_bytes(make_dex(lib_classes('example')))
    with sqlite3.connect(demo_db) as conn:
        conn.execute("UPDATE library_release SET fingerprint_algorithm='future'")
    with pytest.raises(ProfileError, match='incompatible release fingerprints'):
        identify(dex, profiles=demo_db)
    empty = tmp_path / 'empty.sqlite'
    sqlite3.connect(empty).close()
    with pytest.raises(ProfileError):
        identify(dex, profiles=empty)


def test_cli_partial_result_is_retained(tmp_path, capsys):
    apk = make_apk(tmp_path / 'bad.apk', {'classes.dex': b'dex\n035\0bad'})
    assert main(['inspect', str(apk)]) == 4
    payload = json.loads(capsys.readouterr().out)
    assert payload['coverage']['dex'] == 'partial'
    assert payload['errors'][0]['severity'] == 'error'


def test_subprocess_json_is_utf8(tmp_path):
    import os
    import subprocess
    import sys
    apk = make_apk(tmp_path / 'unicode.apk', {'classes.dex': make_dex([
        {'descriptor': 'Lexample/\u0149Class;'}])})
    proc = subprocess.run([sys.executable, '-m', 'libidentifier.cli', 'inspect', str(apk)],
        capture_output=True, env={**os.environ, 'PYTHONIOENCODING': 'ascii'})
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout.decode('utf-8'))
    assert data['unknown_classes'][0]['class_descriptor'] == 'Lexample/\u0149Class;'
