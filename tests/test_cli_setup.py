"""Managed first run consent and resources; legacy commands/APIs remain explicit."""
import io
import json
from pathlib import Path
import shutil

import pytest

from libidentifier import scan
from libidentifier.cli import build_parser, main
from libidentifier import cli_setup as setup
from libidentifier.cli_resources import ScannerRelease, supported_scanner
from libidentifier.errors import AdvisoryError, ProfileError
from conftest import lib_classes, make_apk, make_dex
from test_offline_assessment import EXE, isolated_temp_root, local_db, qualified_options


class Terminal(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def managed(tmp_path, demo_db, monkeypatch):
    home = tmp_path / "managed"
    monkeypatch.setenv("LIBIDENTIFIER_HOME", str(home))
    monkeypatch.delenv("LIBIDENTIFIER_PROFILES", raising=False)
    calls = []
    def install(*, database):
        calls.append("profiles")
        Path(database).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(demo_db, database)
    def missing():
        raise AdvisoryError("not installed", code="scanner_missing")
    monkeypatch.setattr(setup, "install_profiles", install)
    monkeypatch.setattr(setup, "discover_scanner", missing)
    monkeypatch.setattr(setup, "update_advisory_database", lambda *a, **k: pytest.fail("unapproved advisory download"))
    monkeypatch.setattr(setup, "_read_url", lambda *a, **k: pytest.fail("unapproved scanner download"))
    app = make_apk(tmp_path / "demo.apk", {"classes.dex": make_dex(lib_classes("lib/alpha"))})
    return home, app, calls


@pytest.mark.parametrize("answer", ["n\n", "\n", "", "yes\n"])
def test_interactive_consent_once(managed, monkeypatch, capsys, answer):
    home, app, calls = managed
    monkeypatch.setattr(setup.sys, "stdin", Terminal(answer))
    code = main(["scan", str(app)])
    output = capsys.readouterr()
    assert output.err.count("Download and set up these resources?") == 1
    assert "Your APK will stay" in output.err
    if answer.strip() == "yes":
        assert code == 0 and calls == ["profiles"]
        assert "LIBRARIES" in output.out
    else:
        assert code == 3 and not calls and not home.exists()


def test_noninteractive_does_not_read_or_download(managed, monkeypatch, capsys):
    home, app, calls = managed
    class NoInput:
        def isatty(self): return False
        def readline(self): pytest.fail("noninteractive prompt")
    monkeypatch.setattr(setup.sys, "stdin", NoInput())
    assert main(["scan", str(app)]) == 3
    assert "--yes" in capsys.readouterr().err
    assert not calls and not home.exists()


def test_yes_profiles_only_table_then_silent_reuse(managed, capsys):
    home, app, calls = managed
    assert main(["scan", str(app), "--yes"]) == 0
    output = capsys.readouterr()
    assert calls == ["profiles"]
    assert "First-time setup" in output.err and "OSV-Scanner:" not in output.err
    assert "LIBRARIES" in output.out
    assert not (home / "tools").exists() and not (home / "advisory-db").exists()
    assert main(["scan", str(app)]) == 0
    output = capsys.readouterr()
    assert not output.err and calls == ["profiles"]


def test_managed_json_output_and_table_file(managed, tmp_path, capsys):
    _, app, _ = managed
    assert main(["scan", str(app), "--yes", "--format", "json"]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["identification"]["components"][0]["name"] == "libalpha"
    destination = tmp_path / "scan.json"
    assert main(["scan", str(app), "--output", str(destination)]) == 0
    assert json.loads(destination.read_text())["result_kind"] == "assessment"
    assert not capsys.readouterr().out
    table = tmp_path / "scan.txt"
    assert main(["scan", str(app), "--format", "table", "--output", str(table)]) == 0
    assert "LIBRARIES" in table.read_text(encoding="utf-8")
    assert not capsys.readouterr().out


def test_legacy_profiles_and_environment_keep_json(managed, demo_db, monkeypatch, capsys):
    home, app, calls = managed
    assert main(["scan", str(app), "--profiles", str(demo_db)]) == 0
    assert json.loads(capsys.readouterr().out)["result_kind"] == "assessment"
    monkeypatch.setenv("LIBIDENTIFIER_PROFILES", str(demo_db))
    assert main(["scan", str(app)]) == 0
    assert json.loads(capsys.readouterr().out)["result_kind"] == "assessment"
    assert not calls and not home.exists()
    assert build_parser().parse_args(["scan", str(app), "--vulns"]).vulnerabilities
    assert build_parser().parse_args(["identify", str(app), "--vulns"]).vulnerabilities


def test_offline_overrides_yes_and_invalid_input_no_setup(managed, capsys):
    home, app, calls = managed
    assert main(["scan", str(app), "--yes", "--offline", "--vulns"]) == 3
    assert "Offline mode" in capsys.readouterr().err
    assert not calls and not home.exists()
    assert main(["scan", str(app) + ".missing", "--yes"]) == 2
    assert not calls


def test_optional_setup_decline_retains_inventory(managed, monkeypatch, capsys):
    _, app, _ = managed
    assert main(["scan", str(app), "--yes"]) == 0
    capsys.readouterr()
    monkeypatch.setattr(setup.sys, "stdin", Terminal("n\n"))
    assert main(["scan", str(app), "--vulns", "--format", "json"]) == 3
    output = capsys.readouterr()
    data = json.loads(output.out)
    assert data["identification"]["components"]
    assert data["vulnerabilities"]["status"] == "blocked"
    assert data["vulnerabilities"]["errors"][0]["code"] == "setup_not_performed"
    assert "not fully assessed" in output.err


def test_optional_scanner_failure_and_bad_existing_scanner_never_refresh(managed, capsys, monkeypatch):
    home, app, _ = managed
    def failed(*a, **k):
        raise ProfileError("download unavailable")
    monkeypatch.setattr(setup, "_read_url", failed)
    assert main(["scan", str(app), "--yes", "--vulns", "--format", "json"]) == 3
    data = json.loads(capsys.readouterr().out)
    assert data["identification"]["components"]
    assert data["vulnerabilities"]["status"] == "blocked"
    release = supported_scanner()
    scanner = home / "tools/osv-scanner" / release.version / release.filename
    assert not scanner.exists()
    scanner.write_bytes(b"corrupt existing executable")
    monkeypatch.setattr(setup, "_read_url", lambda *a, **k: pytest.fail("must not repair existing scanner"))
    assert main(["scan", str(app), "--yes", "--vulns", "--format", "json"]) == 3
    data = json.loads(capsys.readouterr().out)
    assert data["vulnerabilities"]["errors"][0]["code"] == "scanner_unapproved"
    assert scanner.read_bytes() == b"corrupt existing executable"


def test_scanner_checksum_precedes_execution(tmp_path, monkeypatch):
    release = ScannerRelease("2.7.0", "osv-scanner_windows_amd64.exe", "0" * 64)
    args = build_parser().parse_args(["scan", "app.apk"])
    args.osv_db = str(tmp_path / "database")
    args.osv_scanner_sha256 = release.sha256
    def download(url, writer, **kwargs):
        assert "/v2.7.0/" in url and "latest" not in url
        writer.write(b"untrusted executable")
    monkeypatch.setattr(setup, "_read_url", download)
    monkeypatch.setattr(setup, "_verify", lambda *a: pytest.fail("unverified executable ran"))
    with pytest.raises(AdvisoryError, match="checksum"):
        setup._install_scanner(args, release, tmp_path / "tools/scanner.exe")
    assert not (tmp_path / "tools/scanner.exe").exists()
    assert not list((tmp_path / "tools").glob(".download-*"))


def test_bad_existing_profiles_and_api_no_setup(managed, demo_db, monkeypatch, capsys):
    home, app, calls = managed
    profiles = home / "profiles/profiles.sqlite"
    profiles.parent.mkdir(parents=True)
    profiles.write_bytes(b"invalid database")
    assert main(["scan", str(app), "--yes"]) == 3
    assert not calls and profiles.read_bytes() == b"invalid database"
    capsys.readouterr()
    result = scan(app, profiles=demo_db)
    assert result.identification.components and not calls


def test_platform_pins_do_not_guess_architecture():
    assert supported_scanner("Windows", "AMD64").version == "2.7.0"
    assert supported_scanner("Linux", "x86_64").sha256 != supported_scanner("Windows", "AMD64").sha256
    for system, machine in [("Windows", "ARM64"), ("Linux", "i386"), ("Darwin", "arm64")]:
        with pytest.raises(AdvisoryError, match="No project-qualified"):
            supported_scanner(system, machine)


def test_native_managed_first_run_reuse_and_existing_database(managed, local_db, qualified_options, monkeypatch, capsys):
    home, app, calls = managed
    release = supported_scanner()
    urls = []
    def download(url, writer, **kwargs):
        urls.append(url)
        with EXE.open("rb") as source:
            shutil.copyfileobj(source, writer)
    def update(destination, **kwargs):
        calls.append("advisories")
        shutil.copytree(local_db, destination)
    monkeypatch.setattr(setup, "_read_url", download)
    monkeypatch.setattr(setup, "update_advisory_database", update)
    assert main(["scan", str(app), "--vulns", "--yes", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["vulnerabilities"]["scanner"]["sha256"] == release.sha256
    assert urls == [release.url] and calls == ["profiles", "advisories"]
    assert main(["scan", str(app), "--vulns", "--offline", "--format", "json"]) == 0
    repeated = json.loads(capsys.readouterr().out)["vulnerabilities"]
    assert repeated["status"] == data["vulnerabilities"]["status"]
    assert repeated["status"] in {"complete", "partial"} and not repeated["errors"]
    assert urls == [release.url] and calls == ["profiles", "advisories"]
    # An existing incomplete snapshot is never silently downloaded over.
    marker = home / "advisory-db/CURRENT.json"
    marker.write_text("invalid json")
    assert main(["scan", str(app), "--vulns", "--yes", "--format", "json"]) == 3
    assert json.loads(capsys.readouterr().out)["vulnerabilities"]["status"] == "blocked"
    assert calls == ["profiles", "advisories"]
