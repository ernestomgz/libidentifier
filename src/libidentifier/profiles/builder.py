"""Reference profile generation."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
import zipfile
from collections import Counter
from pathlib import Path

from ..archive import read_selected_members
from ..config import IdentifyOptions
from ..detect import detect_bytes, detect_file
from ..errors import ProfileBuildError
from ..extractors.dex import parse_dex
from ..extractors.elf import parse_elf
from ..fingerprint.dex_v2 import digest_counts
from ..fingerprint.dex_v2 import digest_class
from ..fingerprint.elf_v1 import identity_record
from ..models import ProfileBuildResult
from ..purl import reference_coordinates
from .pom import parse_pom, MAX_POM_BYTES
from .store import connect_write, sha256_file, upsert_release


def _run_d8(path: Path, d8: Path, android_jar: Path | None) -> bytes:
    with tempfile.TemporaryDirectory(prefix="libidentifier-d8-") as tmp:
        out = Path(tmp) / "out"
        out.mkdir()
        cmd = [str(d8), str(path), "--output", str(out)]
        if android_jar is not None:
            if not android_jar.exists():
                raise ProfileBuildError(f"android.jar does not exist: {android_jar}")
            cmd.extend(["--lib", str(android_jar)])
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode("utf-8", errors="replace").strip() if exc.stderr else ""
            stdout = exc.stdout.decode("utf-8", errors="replace").strip() if exc.stdout else ""
            detail = stderr or stdout or f"exit status {exc.returncode}"
            raise ProfileBuildError(f"D8 failed while building profile for {path}: {detail}") from exc
        dex = out / "classes.dex"
        if not dex.exists():
            raise ProfileBuildError("D8 did not produce classes.dex")
        if len(list(out.glob('classes*.dex'))) != 1:
            raise ProfileBuildError('Multidex reference output is unsupported; use explicit DEX reference artifacts')
        return dex.read_bytes()


def _aar_classes_jar(path: Path) -> Path:
    with zipfile.ZipFile(path) as zf, tempfile.NamedTemporaryFile(delete=False, suffix=".jar") as tmp:
        try:
            info = zf.getinfo("classes.jar")
        except KeyError as exc:
            raise ProfileBuildError("AAR does not contain classes.jar") from exc
        with zf.open(info) as src:
            shutil.copyfileobj(src, tmp)
        return Path(tmp.name)


def _compiler_version(d8):
    # Normalize Windows batch paths just as the actual build invocation does.
    # A wrapper may support compilation without version reporting.
    try:
        completed = subprocess.run([str(Path(d8)), '--version'], capture_output=True, timeout=30, shell=False)
        value = (completed.stdout or completed.stderr).decode('utf-8', errors='replace').strip()
        return value if completed.returncode == 0 and value.startswith('D8 ') else None
    except (OSError, subprocess.SubprocessError):
        return None


def build_profile(
    path,
    *,
    purl: str,
    database,
    d8=None,
    android_jar=None,
    reference_sha256: str | None = None,
) -> ProfileBuildResult:
    try:
        ecosystem, namespace, name, release_version, _ = reference_coordinates(purl)
    except ValueError as exc:
        raise ProfileBuildError(str(exc)) from exc
    ref = Path(path)
    if not ref.exists() or not ref.is_file():
        raise ProfileBuildError("reference input must be an existing file")
    source_sha = sha256_file(ref)
    if reference_sha256 and source_sha.lower() != reference_sha256.lower():
        raise ProfileBuildError("reference SHA-256 does not match")
    fmt = detect_file(ref)
    data = ref.read_bytes()
    dex_shapes = None
    dex_class_descriptors = None
    elf_identity = None
    source_format = fmt
    build_configuration = {'kind': 'original'}
    output_sha256 = source_sha
    metadata = None
    pom = ref.with_suffix('.pom')
    if pom.is_file() and ecosystem == 'maven':
        try:
            with pom.open('rb') as stream:
                metadata = parse_pom(stream.read(MAX_POM_BYTES + 1), source=str(pom), expected=(namespace, name, release_version))
        except (ValueError, OSError) as exc:
            raise ProfileBuildError(f'Invalid reference POM: {exc}') from exc
    temp_jar: Path | None = None
    try:
        if fmt == "dex":
            features = parse_dex(data, container=str(ref), member=None, sha256=source_sha)
            dex_shapes = digest_counts(features)
            dex_class_descriptors = Counter((digest_class(f), f.descriptor) for f in features)
            if not dex_shapes:
                raise ProfileBuildError("reference DEX contains no class shapes")
        elif fmt == "elf":
            elf_identity = identity_record(parse_elf(data))
        elif fmt in {"jar", "aar", "zip"}:
            if d8 is None:
                raise ProfileBuildError("JAR/AAR profile building requires explicit d8")
            build_input = ref
            if fmt == "aar":
                temp_jar = _aar_classes_jar(ref)
                build_input = temp_jar
            dex = _run_d8(build_input, Path(d8), Path(android_jar) if android_jar else None)
            output_sha256 = hashlib.sha256(dex).hexdigest()
            compiler_version = _compiler_version(d8)
            build_configuration = {'kind': 'd8', 'executable_sha256': sha256_file(d8),
                                   'compiler_version': compiler_version,
                                   'compiler_version_status': 'reported' if compiler_version else 'unavailable',
                                   'android_jar_sha256': sha256_file(android_jar) if android_jar else None,
                                   'arguments': ['--output', '<temporary>', *(['--lib', '<android.jar>'] if android_jar else [])]}
            features = parse_dex(dex, container=str(ref), member="classes.dex", sha256=hashlib.sha256(dex).hexdigest())
            dex_shapes = digest_counts(features)
            dex_class_descriptors = Counter((digest_class(f), f.descriptor) for f in features)
            if not dex_shapes:
                raise ProfileBuildError("D8 output contains no class shapes")
            source_format = fmt
        else:
            raise ProfileBuildError(f"unsupported reference format: {fmt}")
    finally:
        if temp_jar is not None:
            temp_jar.unlink(missing_ok=True)

    conn = connect_write(database)
    try:
        provenance = {"path": str(ref), "source_sha256": source_sha}
        rid, fid, version = upsert_release(
            conn,
            purl=purl,
            source_sha256=source_sha,
            source_format=source_format,
            provenance=provenance,
            dex_shapes=dex_shapes,
            dex_classes=dex_class_descriptors,
            elf_identity=elf_identity,
            build_configuration=build_configuration,
            output_sha256=output_sha256,
            published_metadata=metadata,
        )
    finally:
        conn.close()
    return ProfileBuildResult(
        database=str(database),
        release_id=rid,
        family_id=fid,
        purl=purl,
        version=version,
        source_format=source_format,
        source_sha256=source_sha,
        dex_shapes=sum(dex_shapes.values()) if dex_shapes else 0,
        elf_identities=1 if elf_identity else 0,
    )


def validate_database(path) -> None:
    from .store import connect_readonly

    conn = connect_readonly(path)
    conn.close()

