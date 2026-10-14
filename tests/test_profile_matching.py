from __future__ import annotations

import sqlite3

import pytest

from libidentifier.api import build_profile, identify, inspect
from libidentifier.errors import ProfileError
from libidentifier.profiles.builder import validate_database

from conftest import lib_classes, make_apk, make_dex, make_minimal_elf


def test_profile_build_validate_and_identify_two_libraries(tmp_path, demo_db):
    app_classes = (
        lib_classes("zzz/app", 2, "V")
        + lib_classes("lib/alpha", 6)
        + lib_classes("lib/beta", 6, "Ljava/lang/Object;")
    )
    apk = make_apk(tmp_path / "sample.apk", {"classes.dex": make_dex(app_classes)})
    validate_database(demo_db)
    result = identify(apk, profiles=demo_db)
    assert [c.name for c in result.components] == ["libalpha", "libbeta"]
    assert all(c.identity_confidence == "high" for c in result.components)
    assert all(c.version is None and c.version_confidence == "unknown" for c in result.components)
    assert len(result.unknown_classes) == 2
    assert {u.class_descriptor for u in result.unknown_classes} == {"Lzzz/app/Class0;", "Lzzz/app/Class1;"}


def test_tiny_shape_overlap_does_not_suppress_distinct_libraries(tmp_path):
    db = tmp_path / "profiles.sqlite"
    shared_a = lib_classes("lib/a/shared", 1)
    shared_b = [{"descriptor": "Llib/b/shared/Class0;", "fields": shared_a[0]["fields"], "methods": shared_a[0]["methods"]}]
    ref_a_classes = shared_a + lib_classes("lib/a/unique", 5)
    ref_b_classes = shared_b + lib_classes("lib/b/unique", 5, "Ljava/lang/Object;")
    ref_a = tmp_path / "a.dex"
    ref_b = tmp_path / "b.dex"
    ref_a.write_bytes(make_dex(ref_a_classes))
    ref_b.write_bytes(make_dex(ref_b_classes))
    build_profile(ref_a, purl="pkg:maven/example/liba@1.0.0", database=db)
    build_profile(ref_b, purl="pkg:maven/example/libb@1.0.0", database=db)
    apk = make_apk(tmp_path / "overlap.apk", {"classes.dex": make_dex(ref_a_classes + ref_b_classes)})

    result = identify(apk, profiles=db)

    assert [c.name for c in result.components] == ["liba", "libb"]
    assert all(c.identity_confidence == "high" for c in result.components)


def test_incompatible_fingerprint_database_is_rejected(demo_db):
    conn = sqlite3.connect(demo_db)
    try:
        conn.execute(
            "UPDATE db_meta SET value=? WHERE key='fingerprint_algorithm'",
            ("dex-shape-v1+elf-identity-v1",),
        )
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(ProfileError):
        validate_database(demo_db)


def test_multidex_library_spanning_two_dex_files(tmp_path):
    db = tmp_path / "profiles.sqlite"
    ref = tmp_path / "split.dex"
    ref.write_bytes(make_dex(lib_classes("lib/split", 6)))
    build_profile(ref, purl="pkg:maven/example/libsplit@1.0.0", database=db)
    apk = make_apk(
        tmp_path / "multi.apk",
        {
            "classes.dex": make_dex(lib_classes("app/main", 2, "V") + lib_classes("lib/split", 3)),
            "classes2.dex": make_dex(lib_classes("lib/split", 6)[3:]),
        },
    )
    result = identify(apk, profiles=db)
    assert [c.name for c in result.components] == ["libsplit"]
    assert result.components[0].score_details["matched_classes"] == 6
    assert {loc.member for loc in result.components[0].matched_code} == {"classes.dex", "classes2.dex"}


def test_version_ambiguity_is_not_guessed(tmp_path):
    db = tmp_path / "profiles.sqlite"
    ref1 = tmp_path / "ambiguous-1.dex"
    ref2 = tmp_path / "ambiguous-2.dex"
    dex = make_dex(lib_classes("renamed/ambiguous", 6))
    ref1.write_bytes(dex)
    ref2.write_bytes(dex)
    build_profile(ref1, purl="pkg:maven/example/ambiguous@1.0.0", database=db)
    build_profile(ref2, purl="pkg:maven/example/ambiguous@1.1.0", database=db)
    apk = make_apk(tmp_path / "ambiguous.apk", {"classes.dex": dex})
    result = identify(apk, profiles=db)
    assert result.components[0].name == "ambiguous"
    assert result.components[0].version is None
    assert result.components[0].version_candidates == ["1.0.0", "1.1.0"]


def test_unknown_app_does_not_false_positive(tmp_path, demo_db):
    apk = make_apk(tmp_path / "unknown.apk", {"classes.dex": make_dex(lib_classes("only/app", 8, "V"))})
    result = identify(apk, profiles=demo_db)
    assert result.components == []
    assert len(result.unknown_classes) == 8


def test_elf_exact_identity_match(tmp_path):
    db = tmp_path / "profiles.sqlite"
    so = tmp_path / "libdemo.so"
    so.write_bytes(make_minimal_elf())
    build_profile(so, purl="pkg:generic/libdemo@1.2.3", database=db)
    apk = make_apk(tmp_path / "native.apk", {"lib/x86_64/libdemo.so": so.read_bytes()})
    result = identify(apk, profiles=db)
    assert [(c.name, c.version, c.version_confidence) for c in result.components] == [
        ("libdemo", "1.2.3", "high")
    ]


def test_api_inspect_has_no_matching(tmp_path, demo_db):
    apk = make_apk(tmp_path / "sample.apk", {"classes.dex": make_dex(lib_classes("lib/alpha", 6))})
    inspected = inspect(apk)
    identified = identify(apk, profiles=demo_db)
    assert inspected.components == []
    assert identified.components

