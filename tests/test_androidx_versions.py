"""AndroidX declarations are evidence, never metadata-only installed components."""
import hashlib
from dataclasses import replace

import pytest

from conftest import lib_classes, make_apk, make_dex
from libidentifier import IdentifyOptions, ScanResult, build_profile, identify, inspect
from libidentifier.extractors.version_metadata import read_androidx_version, apply_version_metadata
from libidentifier.inventory import Inventory


MEMBER = 'META-INF/androidx.core_core.version'


@pytest.mark.parametrize('member,data', [
    ('META-INF/other.library_demo.version', b'1.0'),
    ('assets/androidx.core_core.version', b'1.0'),
    ('META-INF/androidx.core_core_extra.version', b'1.0'),
    (MEMBER, b''), (MEMBER, b'1.0\n2.0'), (MEMBER, b'1.0\x00'),
    (MEMBER, b'\xff'), (MEMBER, b'[1,2)'), (MEMBER, b'1' * 4097),
])
def test_reject_unrecognized_or_malformed_declarations(member, data):
    assert read_androidx_version(data, member) is None


def test_metadata_only_is_preserved_without_inventing_components(tmp_path):
    data = b'\xef\xbb\xbf1.12.0-alpha01\r\n'
    apk = make_apk(tmp_path/'app.apk', {
        MEMBER: data, 'META-INF/custom.version': b'9.0',
        'META-INF/other.library_demo.version': b'2.0',
    })
    result = inspect(apk)
    assert not result.components
    declarations = [e for e in result.evidence_records if e.kind == 'version_metadata']
    assert len(declarations) == 1
    evidence = declarations[0]
    assert evidence.details['declared'] == {
        'groupId': 'androidx.core', 'artifactId': 'core', 'version': '1.12.0-alpha01'}
    assert evidence.details['component_ids'] == []
    assert evidence.location.member == MEMBER
    assert evidence.location.container == str(apk)
    assert evidence.location.sha256 == hashlib.sha256(data).hexdigest()
    assert ScanResult.from_dict(result.to_dict()).evidence_records == result.evidence_records


def test_code_corroboration_and_cross_convention_conflict(tmp_path):
    dex = make_dex(lib_classes('androidx/core'))
    reference = tmp_path/'ref.dex'; reference.write_bytes(dex)
    db = tmp_path/'profiles.sqlite'
    build_profile(reference, purl='pkg:maven/androidx.core/core@1.12.0', database=db)
    apk = tmp_path/'app.apk'
    members = {'classes.dex': dex, MEMBER: b'1.12.0\n'}
    result = identify(make_apk(apk, members), profiles=db,
                      options=IdentifyOptions(max_version_candidates=0))
    component = result.components[0]
    assert component.version == '1.12.0'
    assert component.version_confidence == 'high'
    assert component.purl == 'pkg:maven/androidx.core/core@1.12.0'
    assert 'androidx_version_file' in component.identification_methods
    members['META-INF/maven/androidx.core/core/pom.properties'] = (
        b'groupId=androidx.core\nartifactId=core\nversion=99.0\n')
    conflict = identify(make_apk(apk, members), profiles=db)
    assert conflict.components[0].version is None
    assert conflict.components[0].purl is None
    assert next(r for r in conflict.analysis_runs if r.capability == 'version_metadata').status == 'partial'
    assert len([e for e in conflict.evidence_records if e.kind == 'version_metadata']) == 2


def test_unrepresented_version_or_wrong_identity_never_promoted(tmp_path):
    reference = tmp_path/'ref.dex'; reference.write_bytes(make_dex(lib_classes('androidx/core')))
    db = tmp_path/'profiles.sqlite'
    build_profile(reference, purl='pkg:maven/androidx.core/core@1.0', database=db)
    for path, version in [(MEMBER, b'99.0'), ('META-INF/androidx.other_other.version', b'1.0')]:
        apk = make_apk(tmp_path/'app.apk', {'classes.dex': reference.read_bytes(), path: version})
        result = identify(apk, profiles=db)
        assert result.components[0].version is None
        assert result.components[0].version_confidence == 'unknown'
        assert any(e.kind == 'version_metadata' for e in result.evidence_records)


def test_metadata_cannot_cross_container_or_weak_code_boundary(tmp_path):
    reference = tmp_path/'ref.dex'; reference.write_bytes(make_dex(lib_classes('androidx/core')))
    db = tmp_path/'profiles.sqlite'
    build_profile(reference, purl='pkg:maven/androidx.core/core@1.0', database=db)
    code = make_apk(tmp_path/'code.apk', {'classes.dex': reference.read_bytes()})
    make_apk(tmp_path/'metadata.apk', {MEMBER: b'1.0'})
    result = identify(tmp_path, profiles=db)
    assert result.components[0].version is None
    inspected = inspect(tmp_path/'metadata.apk')
    evidence = next(e for e in inspected.evidence_records if e.kind == 'version_metadata')
    local = identify(code, profiles=db)
    inv = Inventory(local.input, version_metadata=[
        (replace(evidence.location, container=str(code)), evidence.details['declared'])])
    weak = replace(local.components[0], score_details={'exact_descriptor_matches': 1})
    assert apply_version_metadata(replace(local, components=[weak]), inv).components[0].version is None


def test_malformed_known_file_reports_partial_and_duplicate_skipped(tmp_path):
    apk = make_apk(tmp_path/'app.apk', {MEMBER: b'not a version'})
    result = inspect(apk)
    run = next(r for r in result.analysis_runs if r.capability == 'version_metadata')
    assert run.status == 'partial'
    assert run.errors[0].code == 'version_metadata_unsupported'
    import zipfile
    with pytest.warns(UserWarning, match='Duplicate name'):
        with zipfile.ZipFile(apk, 'a') as archive:
            archive.writestr(MEMBER, '1.0')
    result = inspect(apk)
    assert any(e.code == 'duplicate_member' for e in result.errors)
    assert not any(e.kind == 'version_metadata' for e in result.evidence_records)


def test_corroboration_controls_native_offline_advisory_matching(tmp_path, monkeypatch):
    import tempfile
    from test_offline_assessment import EXE, archive, record
    from libidentifier import correlate, provision_advisory_database, VulnerabilityOptions
    if not EXE.is_file():
        pytest.skip('qualified OSV executable not installed for native AndroidX assessment')
    monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))
    raw = record()
    raw['affected'][0]['package']['name'] = 'androidx.core:core'
    advisory = tmp_path/'advisories'
    provision_advisory_database(advisory, archives={'Maven': archive(tmp_path/'Maven.zip', [raw])})
    reference = tmp_path/'reference.dex'
    reference.write_bytes(make_dex(lib_classes('androidx/core')))
    db = tmp_path/'profiles.sqlite'
    build_profile(reference, purl='pkg:maven/androidx.core/core@1.0', database=db)
    for declaration, expected in [(b'1.0', 'affected'), (b'99.0', 'potential')]:
        apk = make_apk(tmp_path/'app.apk', {'classes.dex': reference.read_bytes(), MEMBER: declaration})
        result = identify(apk, profiles=db)
        report = correlate(result, options=VulnerabilityOptions(EXE, advisory))
        assert report.components[0].status == expected
        assert report.findings[0].applicability == expected
        assert report.findings[0].evaluated_version == ('1.0' if expected == 'affected' else None)
    report = correlate(inspect(apk), options=VulnerabilityOptions(EXE, advisory))
    assert not report.findings  # Declarations alone do not enter vulnerability assessment.
