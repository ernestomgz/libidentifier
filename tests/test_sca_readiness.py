"""SCA semantics, serialization compatibility and bounded-input regressions."""
from dataclasses import replace
from pathlib import Path
import inspect as signatures
import json
import sqlite3
import struct
import zipfile

import pytest

from libidentifier import IdentifyOptions, ScanResult, build_profile, export_cyclonedx, identify, inspect
from libidentifier.cli import main
from libidentifier.errors import InputError, ProfileBuildError, ProfileError
from libidentifier.models import ComponentMatch, CoverageRecord
from libidentifier.profiles.store import connect_write
from conftest import lib_classes, make_apk, make_dex, make_minimal_elf


def test_inventory_scope_and_unknown_truncation(tmp_path, demo_db):
    apk = make_apk(tmp_path / 'app.apk', {'classes.dex': make_dex(lib_classes('unknown', 8, 'V'))})
    options = IdentifyOptions(max_emitted_unknown_classes=2)
    empty = tmp_path / 'empty.sqlite'
    conn = connect_write(empty)
    conn.commit()
    conn.close()
    for r, mode in [(inspect(apk, options=options), 'not_performed'),
                    (identify(apk, profiles=empty, options=options), 'no_profiles'),
                    (identify(apk, profiles=demo_db, options=options), 'limited')]:
        assert not r.components
        assert r.coverage.library_identification == mode
        assert r.coverage.unknown_classes_total == 8
        assert r.coverage.unknown_classes_emitted == len(r.unknown_classes) == 2
        assert r.coverage.unknown_classes_truncated is True
        assert any('truncated' in s for s in r.coverage.limitations)
        assert ScanResult.from_dict(json.loads(r.to_json())) == r
    r = inspect(apk, options=IdentifyOptions(max_emitted_unknown_classes=0))
    assert r.coverage.unknown_classes_total == 8 and not r.unknown_classes
    assert r.coverage.unknown_classes_truncated
    r = inspect(apk)
    assert r.coverage.unknown_classes_emitted == 8 and not r.coverage.unknown_classes_truncated


def test_versionless_identity_and_table(tmp_path, demo_db, capsys):
    apk = make_apk(tmp_path / 'app.apk', {'classes.dex': make_dex(lib_classes('lib/alpha'))})
    r = identify(apk, profiles=demo_db)
    c = r.components[0]
    assert c.family_purl == 'pkg:maven/example/libalpha'
    assert c.purl is None and c.version is None
    assert c.identity_confidence == 'high' and c.version_confidence == 'unknown'
    assert c.version_candidates_total == 1 and not c.version_candidates_truncated
    assert main(['identify', str(apk), '--profiles', str(demo_db), '--format', 'table']) == 0
    output = capsys.readouterr().out
    assert 'Library' in output and 'Identity' in output and 'Version' in output
    assert 'libalpha' in output and 'Unknown [1.0.0]' in output and 'High   (' in output
    assert 'VULNERABILITIES' not in output
    old = c.to_dict()
    for field in ('family_purl', 'version_candidates_total', 'version_candidates_truncated'):
        old.pop(field)
    assert ComponentMatch.from_dict(old).family_purl is None
    legacy = CoverageRecord.from_dict({'dex': 'analyzed'})
    assert legacy.unknown_classes_total is None and legacy.library_identification == 'unknown'


def test_candidate_truncation_and_weak_release_exclusion(tmp_path):
    db = tmp_path / 'db.sqlite'
    ref = tmp_path / 'lib.dex'
    classes = lib_classes('known/lib', 6)
    ref.write_bytes(make_dex(classes))
    for version in ['1', '2', '3']:
        build_profile(ref, purl='pkg:maven/example/lib@' + version, database=db)
    # One shared class among an otherwise different release is not a supported version candidate.
    ref.write_bytes(make_dex(classes[:1] + lib_classes('different', 50, 'V')))
    build_profile(ref, purl='pkg:maven/example/lib@99', database=db)
    apk = make_apk(tmp_path / 'app.apk', {'classes.dex': make_dex(classes)})
    r = identify(apk, profiles=db, options=IdentifyOptions(max_version_candidates=1))
    c = r.components[0]
    assert c.version is None and c.version_candidates == ['1']
    assert c.version_candidates_total == 3 and c.version_candidates_truncated
    assert c.score_details['version_candidate_scores']['99']['exact_descriptor_matches'] == 1


def native_profile(tmp_path, versions=('1.0',)):
    ref, db = tmp_path / 'native.so', tmp_path / 'native.sqlite'
    ref.write_bytes(make_minimal_elf())
    for version in versions:
        build_profile(ref, purl='pkg:generic/runtime@' + version, database=db)
    return ref, db


def test_elf_ambiguous_versions_keep_identity(tmp_path):
    ref, db = native_profile(tmp_path, ('1.0', '1.1'))
    r = identify(ref, profiles=db, options=IdentifyOptions(max_version_candidates=1))
    c = r.components[0]
    assert c.name == 'runtime' and c.family_purl == 'pkg:generic/runtime'
    assert c.identity_confidence == 'high'
    assert c.version is None and c.purl is None and c.version_confidence == 'unknown'
    assert c.version_candidates_total == 2 and c.version_candidates_truncated
    out = tmp_path / 'bom.json'
    export_cyclonedx(r, out)
    bom = json.loads(out.read_text())
    assert bom['components'] == []
    assert bom['compositions'] == [{'aggregate': 'incomplete'}]
    props = {p['name']: p['value'] for p in bom['metadata']['properties']}
    assert c.component_id in props['libidentifier:excluded_components']
    assert 'not a complete software inventory' in props['libidentifier:inventory_scope']


def test_duplicate_native_occurrences_have_unique_sbom_and_exact_evidence(tmp_path):
    ref, db = native_profile(tmp_path)
    folder = tmp_path / 'apks'
    folder.mkdir()
    for name in ('one.apk', 'two.apk'):
        make_apk(folder / name, {'lib/x86_64/runtime.so': ref.read_bytes()})
    r = identify(folder, profiles=db)
    assert len(r.components) == 1
    c = r.components[0]
    assert c.version == '1.0' and c.version_confidence == 'high'
    assert {loc.container for loc in c.matched_code} == {str(folder / n) for n in ('one.apk', 'two.apk')}
    assert {a.container for a in r.analyzed_files} == {loc.container for loc in c.matched_code}
    out = tmp_path / 'bom.json'
    export_cyclonedx(r, out)
    bom = json.loads(out.read_text())
    assert len(bom['components']) == 1
    assert bom['components'][0]['bom-ref'] == c.component_id
    assert json.loads(bom['components'][0]['properties'][0]['value']) == [loc.to_dict() for loc in c.matched_code]
    props = {p['name']: p['value'] for p in bom['metadata']['properties']}
    assert json.loads(props['libidentifier:profile_database'])['sha256'] == r.profile_database.sha256


def test_same_name_different_native_bytes_not_identified(tmp_path):
    ref, db = native_profile(tmp_path)
    ref.write_bytes(ref.read_bytes() + b'different binary')
    r = identify(ref, profiles=db)
    assert r.components == []
    assert r.analyzed_files[0].status == 'analyzed'


@pytest.mark.parametrize('change', [
    {'version': None, 'version_confidence': 'unknown'},
    {'identity_confidence': 'medium'},
    {'purl': 'pkg:generic/runtime@9.9'},
    {'purl': 'not-a-purl'},
])
def test_sbom_does_not_promote_uncertain_or_inconsistent_identity(tmp_path, change):
    ref, db = native_profile(tmp_path)
    r = identify(ref, profiles=db)
    r = replace(r, components=[replace(r.components[0], **change)])
    out = tmp_path / 'bom.json'
    export_cyclonedx(r, out)
    bom = json.loads(out.read_text())
    assert bom['components'] == []
    props = {p['name']: p['value'] for p in bom['metadata']['properties']}
    assert json.loads(props['libidentifier:excluded_components'])[0]['component_id'] == r.components[0].component_id


def test_directory_ownership_includes_container(tmp_path, demo_db):
    folder = tmp_path / 'apks'
    folder.mkdir()
    make_apk(folder / 'one.apk', {'classes.dex': make_dex(lib_classes('lib/alpha'))})
    other = make_apk(folder / 'two.apk', {'classes.dex': make_dex(lib_classes('lib/alpha', 1, 'V'))})
    r = identify(folder, profiles=demo_db)
    assert r.components
    assert any(loc.container == str(other) and loc.class_descriptor == 'Llib/alpha/Class0;' for loc in r.unknown_classes)


def test_binary_and_archive_resource_limits(tmp_path):
    dex = tmp_path / 'app.dex'
    dex.write_bytes(make_dex(lib_classes('known')))
    with pytest.raises(InputError, match='byte limit'):
        inspect(dex, options=IdentifyOptions(max_member_uncompressed_bytes=8))
    apk = make_apk(tmp_path / 'app.apk', {'classes.dex': dex.read_bytes()})
    r = inspect(apk, options=IdentifyOptions(max_total_selected_uncompressed_bytes=16))
    assert any(e.code == 'archive_budget' for e in r.errors)
    assert r.coverage.dex == 'partial'
    assert not r.unknown_classes


def test_directory_depth_is_reported(tmp_path):
    root = tmp_path / 'root'
    (root / 'deep').mkdir(parents=True)
    (root / 'deep/app.dex').write_bytes(make_dex(lib_classes('deep')))
    r = inspect(root, options=IdentifyOptions(max_directory_depth=1))
    assert any(e.code == 'directory_depth_limit' for e in r.errors)
    assert r.coverage.dex == 'partial'


def test_duplicate_zip_members_are_not_ambiguous_evidence(tmp_path):
    apk = tmp_path / 'duplicate.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('classes.dex', make_dex(lib_classes('one')))
        with pytest.warns(UserWarning):
            z.writestr('classes.dex', make_dex(lib_classes('two')))
    r = inspect(apk)
    assert not r.unknown_classes
    assert any(e.code == 'duplicate_member' for e in r.errors)
    assert r.coverage.dex == 'partial'


def test_corrupt_zip_member_retains_valid_members(tmp_path):
    apk = tmp_path / 'corrupt.apk'
    with zipfile.ZipFile(apk, 'w', compression=zipfile.ZIP_STORED) as z:
        z.writestr('classes.dex', make_dex(lib_classes('bad')))
        z.writestr('classes2.dex', make_dex(lib_classes('good')))
    with zipfile.ZipFile(apk) as z:
        offset = z.getinfo('classes.dex').header_offset
    raw = bytearray(apk.read_bytes())
    name_size, extra_size = struct.unpack_from('<HH', raw, offset + 26)
    raw[offset + 30 + name_size + extra_size + 12] ^= 1
    apk.write_bytes(raw)
    r = inspect(apk)
    assert any(e.code == 'member_read_error' for e in r.errors)
    assert r.coverage.dex == 'partial'
    assert {c.member for c in r.unknown_classes} == {'classes2.dex'}


def test_compatibility_signatures_and_reserved_timeout():
    assert list(signatures.signature(build_profile).parameters) == ['path', 'purl', 'database', 'd8', 'android_jar', 'reference_sha256']
    assert list(signatures.signature(export_cyclonedx).parameters) == ['result', 'path']
    assert IdentifyOptions(max_scan_seconds=1).max_scan_seconds == 1
    with pytest.raises(ValueError):
        IdentifyOptions(max_emitted_unknown_classes=-1)
    with pytest.raises(ValueError):
        IdentifyOptions(max_member_uncompressed_bytes=0)


def test_invalid_profile_identity_is_rejected(tmp_path):
    ref, db = native_profile(tmp_path)
    with pytest.raises(ProfileBuildError):
        build_profile(ref, purl='pkg:maven/missinggroup@1', database=db)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE library_release SET version='wrong'")
    with pytest.raises(ProfileError, match='disagrees'):
        identify(ref, profiles=db)


@pytest.mark.parametrize('filename,names', [
    ('allsafe-1.6.apk', {'okhttp', 'rootbeer-lib'}),
    ('AndroGoat-2.0.1.apk', {'okhttp'}),
    ('diva.apk', set()),
    ('InjuredAndroid-1.0.12-release.apk', set()),
    ('InsecureBankv2-2.3.1.apk', set()),
    ('ovaa-1.0.0-app-debug.apk', {'gson', 'okhttp', 'retrofit'}),
])
def test_real_apk_sca_regression(tmp_path, filename, names):
    root = Path(__file__).resolve().parents[1]
    apk = root / 'samples' / filename
    import os
    db = Path(os.environ.get('LIBIDENTIFIER_TEST_PROFILES', root / '.local/profiles/profiles.sqlite'))
    if not apk.is_file() or not db.is_file():
        pytest.skip('local sample and validation database required')
    result = identify(apk, profiles=db)
    assert not result.errors
    assert {c.name for c in result.components} == names
    assert all(c.version is None and c.version_confidence == 'unknown' and c.purl is None for c in result.components)
    assert result.coverage.library_identification == 'limited'
    assert result.coverage.unknown_classes_total >= result.coverage.unknown_classes_emitted
    framework_ids = {f.framework_id for f in result.frameworks_detected}
    assert framework_ids == ({'flutter'} if filename.startswith('InjuredAndroid') else set())
    output = tmp_path / 'bom.json'
    export_cyclonedx(result, output)
    assert json.loads(output.read_text())['components'] == []
