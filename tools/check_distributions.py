"""Check release archive contents and version consistency without extracting code."""
from pathlib import Path, PurePosixPath
import sys
import tarfile
import zipfile
from email.parser import BytesParser


def check(folder):
    archives = sorted(Path(folder).glob("*.whl")) + sorted(Path(folder).glob("*.tar.gz"))
    if not archives:
        raise ValueError("no Python distributions found")
    versions = set()
    for path in archives:
        if path.suffix == ".whl":
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
                metadata = archive.read(next(n for n in names if n.endswith(".dist-info/METADATA")))
        else:
            with tarfile.open(path, "r:gz") as archive:
                names = archive.getnames()
                metadata = archive.extractfile(next(n for n in names if n.count("/") == 1 and n.endswith("/PKG-INFO"))).read()
        for name in names:
            parts = PurePosixPath(name).parts
            if (name.startswith("/") or ".." in parts or any(p in parts for p in (
                ".local", ".tools", ".development-deps", "test-results", "samples", "__pycache__"))
                or "moraine" in name.lower() or name.endswith((".sqlite", ".exe", ".pyc"))):
                raise ValueError(f"unexpected distribution member: {name}")
        assert any(n.endswith("libidentifier/profiles/distribution.py") for n in names)
        assert any(n.endswith("libidentifier/cli_setup.py") for n in names)
        assert any(n.endswith("libidentifier/cli_resources.py") for n in names)
        assert any(n.endswith("libidentifier/fingerprint/dex_v2.py") for n in names)
        assert not any(n.endswith("fingerprint/dex_v1.py") for n in names)
        record = BytesParser().parsebytes(metadata)
        assert record["Name"] == "libidentifier"
        versions.add(record["Version"])
        print(path.name, "validated", record["Version"])
    assert len(versions) == 1, "sdist/wheel version mismatch"


if __name__ == "__main__":
    check(sys.argv[1] if len(sys.argv) > 1 else "dist")
