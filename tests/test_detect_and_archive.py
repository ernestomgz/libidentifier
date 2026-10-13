from __future__ import annotations

import zipfile

import pytest

from libidentifier.archive import read_selected_members
from libidentifier.config import IdentifyOptions
from libidentifier.detect import detect_bytes
from libidentifier.errors import InputError
from libidentifier.api import inspect

from conftest import lib_classes, make_apk, make_dex


def test_magic_detection_ignores_extension():
    assert detect_bytes(make_dex(lib_classes("x/y", 1)), name="not_a_dex.txt") == "dex"
    assert detect_bytes(b"\x7fELF....", name="classes.dex") == "elf"
    assert detect_bytes(b"plain", name="classes.dex") == "unknown"


def test_safe_archive_skips_traversal_member(tmp_path):
    apk = tmp_path / "bad.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("../classes.dex", make_dex(lib_classes("x/y", 1)))
        zf.writestr("classes.dex", make_dex(lib_classes("x/y", 1)))
    members, errors = read_selected_members(apk, IdentifyOptions())
    assert [m.name for m in members] == ["classes.dex"]
    assert any(e.code == "unsafe_member_path" for e in errors)


def test_malformed_dex_reports_member_error(tmp_path):
    apk = make_apk(tmp_path / "bad.apk", {"classes.dex": b"dex\n035\0bad"})
    result = inspect(apk)
    assert result.coverage.dex == "partial"
    assert any(e.code == "dex_parse_error" for e in result.errors)

