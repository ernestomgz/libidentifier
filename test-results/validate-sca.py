"""Reproduce real-APK SCA checks after provisioning the validation databases.

Run from the repository root. Optional validation-tool dependencies and the
upstream CycloneDX schemas are stored in test-results/tmp, never runtime deps.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys
import zipfile

from libidentifier import ScanResult, build_profile, export_cyclonedx, identify, inspect
from libidentifier.profiles.store import connect_write

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'test-results/tmp/sca'
OUTPUT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT / 'test-results/tmp/schema-validation'))
from jsonschema import Draft7Validator
from referencing import Registry, Resource

schema_dir = ROOT / 'test-results/tmp'
schema = json.loads((schema_dir / 'bom-1.5.schema.json').read_text())
registry = Registry()
for name in ('bom-1.5.schema.json', 'spdx.schema.json', 'jsf-0.82.schema.json'):
    document = json.loads((schema_dir / name).read_text())
    resource = Resource.from_contents(document)
    registry = registry.with_resource(document['$id'], resource)
    registry = registry.with_resource('http://cyclonedx.org/schema/' + name, resource)
validator = Draft7Validator(schema, registry=registry)


def definitions(data):
    # Independent traversal of the raw DEX class_defs table, without LIEF.
    string_count, string_offset = struct.unpack_from('<II', data, 0x38)
    type_count, type_offset = struct.unpack_from('<II', data, 0x40)
    class_count, class_offset = struct.unpack_from('<II', data, 0x60)
    names = []
    for i in range(string_count):
        pos = struct.unpack_from('<I', data, string_offset + 4 * i)[0]
        while data[pos] & 0x80:
            pos += 1
        pos += 1
        end = data.index(0, pos)
        names.append(data[pos:end].decode('utf-8', errors='replace'))
    types = [names[struct.unpack_from('<I', data, type_offset + i * 4)[0]] for i in range(type_count)]
    return {types[struct.unpack_from('<I', data, class_offset + i * 32)[0]] for i in range(class_count)}


def check_evidence(result, dex_defs, hashes):
    locators = [loc for c in result.components for loc in c.matched_code] + result.unknown_classes
    locators += [e.location for f in result.frameworks_detected for e in f.evidence_records]
    checked = 0
    for loc in locators:
        assert loc.container == result.input.path, loc
        assert hashes[loc.member] == loc.sha256, loc
        if loc.class_descriptor:
            assert loc.class_descriptor in dex_defs[loc.member], loc
            checked += 1
    return checked


expected = {
    'allsafe-1.6.apk': {'okhttp', 'rootbeer-lib'}, 'AndroGoat-2.0.1.apk': {'okhttp'},
    'diva.apk': set(), 'InjuredAndroid-1.0.12-release.apk': set(),
    'InsecureBankv2-2.3.1.apk': set(), 'ovaa-1.0.0-app-debug.apk': {'gson', 'okhttp', 'retrofit'},
}
databases = {'baseline': ROOT / 'test-results/samples/reference-profiles.sqlite',
             'targeted': ROOT / 'test-results/sca-reference-profiles.sqlite'}
report = {'samples': [], 'schema_validation': 'official CycloneDX 1.5 JSON schema',
          'schema_sha256': hashlib.sha256((schema_dir / 'bom-1.5.schema.json').read_bytes()).hexdigest()}
for filename, expected_names in expected.items():
    apk = ROOT / 'samples' / filename
    before = hashlib.sha256(apk.read_bytes()).hexdigest()
    with zipfile.ZipFile(apk) as z:
        dex_defs, hashes = {}, {}
        for name in z.namelist():
            data = z.read(name)
            hashes[name] = hashlib.sha256(data).hexdigest()
            if data.startswith(b'dex\n'):
                dex_defs[name] = definitions(data)
    row = {'sample': filename, 'input_sha256': before, 'scans': {}}
    for label, db in databases.items():
        r = identify(apk, profiles=db)
        assert not r.errors, r.errors
        assert {c.name for c in r.components} == expected_names
        assert all(c.version is None and c.purl is None and c.version_confidence == 'unknown' for c in r.components)
        assert all(c.family_purl for c in r.components)
        assert ScanResult.from_dict(json.loads(r.to_json())) == r
        checked = check_evidence(r, dex_defs, hashes)
        defined_count = sum(len(names) for names in dex_defs.values())
        matched_classes = {(loc.member, loc.class_descriptor) for c in r.components
                           for loc in c.matched_code if loc.class_descriptor}
        assert r.coverage.analyzed_count['classes'] == defined_count
        assert r.coverage.unknown_classes_total == defined_count - len(matched_classes)
        assert r.coverage.unknown_classes_emitted == len(r.unknown_classes)
        assert r.coverage.unknown_classes_truncated == (len(r.unknown_classes) < r.coverage.unknown_classes_total)
        r.write_json(OUTPUT / f'{filename}.{label}.json')
        bom_path = OUTPUT / f'{filename}.{label}.cdx.json'
        export_cyclonedx(r, bom_path)
        bom = json.loads(bom_path.read_text())
        validator.validate(bom)
        assert bom['components'] == []
        assert bom['compositions'][0]['aggregate'] == 'incomplete'
        row['scans'][label] = {
            'tool_version': r.tool_version, 'profile_database': r.profile_database.to_dict(),
            'components': [{k: v for k, v in c.to_dict().items() if k not in {'matched_code', 'source_artifacts'}} |
                           {'matched_class_locations': len(c.matched_code)} for c in r.components],
            'frameworks': [f.to_dict() for f in r.frameworks_detected],
            'coverage': r.coverage.to_dict(), 'errors': [],
            'definition_locators_independently_verified': checked,
            'sbom_components': 0, 'sbom_schema_valid': True,
        }
    no_profiles = inspect(apk)
    assert no_profiles.coverage.library_identification == 'not_performed'
    assert no_profiles.components == []
    check_evidence(no_profiles, dex_defs, hashes)
    row['inspect_coverage'] = no_profiles.coverage.to_dict()
    assert before == hashlib.sha256(apk.read_bytes()).hexdigest(), 'sample changed'
    report['samples'].append(row)
    print(filename, 'passed; components', sorted(expected_names), flush=True)

# Empty valid database is explicitly distinguished from no matching operation.
empty = OUTPUT / 'empty.sqlite'
conn = connect_write(empty)
conn.commit()
conn.close()
r = identify(ROOT / 'samples/ovaa-1.0.0-app-debug.apk', profiles=empty)
assert r.coverage.library_identification == 'no_profiles' and not r.components
report['empty_database_coverage'] = r.coverage.to_dict()

# Positive exact-version export, not merely empty-schema validation.
sys.path.insert(0, str(ROOT / 'tests'))
from conftest import make_minimal_elf, make_apk
ref, native_db = OUTPUT / 'reference.so', OUTPUT / 'native.sqlite'
ref.write_bytes(make_minimal_elf())
build_profile(ref, purl='pkg:generic/validation-runtime@1.0', database=native_db)
apk = make_apk(OUTPUT / 'native.apk', {'lib/abi-one/runtime.so': ref.read_bytes(), 'lib/abi-two/runtime.so': ref.read_bytes()})
r = identify(apk, profiles=native_db)
export_cyclonedx(r, OUTPUT / 'native.cdx.json')
bom = json.loads((OUTPUT / 'native.cdx.json').read_text())
validator.validate(bom)
assert len(bom['components']) == 1 and len(r.components[0].matched_code) == 2
report['positive_native_sbom_schema_valid'] = True
report['positive_native_bom_refs_unique'] = True
(ROOT / 'test-results/sca-readiness-validation.json').write_bytes((json.dumps(report, indent=2) + '\n').encode())
print('All real samples, no-profile/empty-DB semantics, and 13 CycloneDX exports passed.', flush=True)
