from __future__ import annotations

from libidentifier.extractors.dex import parse_dex
from libidentifier.extractors.elf import parse_elf
from libidentifier.fingerprint.dex_v1 import digest_class

from conftest import lib_classes, make_dex, make_minimal_elf


def test_lief_extracts_real_dex_classes():
    dex = make_dex(lib_classes("sample/lib", 3))
    classes = parse_dex(dex, container="fixture.dex", member=None, sha256="x")
    assert len(classes) == 3
    assert classes[0].descriptor.startswith("Lsample/lib/")
    assert classes[0].methods
    assert classes[0].fields


def test_dex_extraction_excludes_reference_only_types():
    dex = make_dex(
        [
            {
                "descriptor": "Lsample/lib/UsesPlatform;",
                "fields": [{"name": "bundle", "type": "Landroid/os/Bundle;"}],
                "methods": [
                    {
                        "name": "read",
                        "return": "Ljava/lang/String;",
                        "params": ["Ljava/io/InputStream;"],
                    }
                ],
            }
        ]
    )
    classes = parse_dex(dex, container="fixture.dex", member=None, sha256="x")
    assert [c.descriptor for c in classes] == ["Lsample/lib/UsesPlatform;"]
    assert "Landroid/os/Bundle;" not in {c.descriptor for c in classes}
    assert "Ljava/io/InputStream;" not in {c.descriptor for c in classes}
    assert "Ljava/lang/String;" not in {c.descriptor for c in classes}


def test_empty_package_private_definition_is_not_lost():
    dex = make_dex([{"descriptor": "Lsample/Empty;", "flags": 0}])
    classes = parse_dex(dex, container="fixture.dex", member=None, sha256="x")
    assert [c.descriptor for c in classes] == ["Lsample/Empty;"]


def test_dex_shape_is_rename_invariant_and_shape_sensitive():
    a = parse_dex(make_dex(lib_classes("first/name", 1)), container="a", member=None, sha256="a")[0]
    b = parse_dex(make_dex(lib_classes("second/name", 1)), container="b", member=None, sha256="b")[0]
    c = parse_dex(make_dex(lib_classes("first/name", 1, "Ljava/lang/Object;")), container="c", member=None, sha256="c")[0]
    assert digest_class(a) == digest_class(b)
    assert digest_class(a) != digest_class(c)


def test_lief_extracts_real_elf_identity():
    feature = parse_elf(make_minimal_elf())
    assert feature.sha256
    assert "x86_64" in feature.abi

