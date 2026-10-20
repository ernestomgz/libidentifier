# Preview releases and installation

LibIdentifier is independent of its consumers. The engine is a Python package;
reference profiles are separately versioned GitHub release assets. OSV-Scanner
and the Maven advisory snapshot are optional separately provisioned resources.
Package installation does not download them. The initial package is `0.2.0rc1`;
the initial small profile snapshot is `2026.10.20-preview.1`.

## User installation after publication

These commands require the maintainer to publish the releases first. Until then,
install the locally built wheel or the reviewed source checkout instead of PyPI.

```powershell
python -m pip install "libidentifier==0.2.0rc1"
libidentifier profiles install --database profiles.sqlite
libidentifier profiles validate profiles.sqlite
libidentifier identify app.apk --profiles profiles.sqlite --format table
```

`profiles install` defaults to the immutable initial official snapshot URL,
not GitHub's mixed package/profile `latest` release. Supply `--manifest` to pin a
different compatible snapshot. New catalogs can be published without a new
engine. The first release contains six families/eight releases and no published
POM metadata; a small catalog is not a production accuracy claim.

For a disconnected host, copy all three profile assets from a trusted release:

```powershell
libidentifier profiles install --manifest ./download/profiles-manifest.json --database profiles.sqlite --offline
```

`--offline` rejects remote manifests. Downloads require HTTPS, including redirects.
Manifest input is bounded to 1 MiB, compressed data to 512 MiB and the database
to 2 GiB. Declared compressed and expanded sizes/hashes, engine compatibility,
schema, fingerprint bundle, SQLite integrity/foreign keys and catalog inventory
are checked before publishing a new installation. `--timeout-seconds` controls
network socket timeout, not a hard whole-operation deadline. POSIX exclusive
installation requires a filesystem supporting hard links; Windows uses rename.

Existing destinations are never silently refreshed:

```powershell
libidentifier profiles install --manifest ./new-release/profiles-manifest.json --database profiles.sqlite --offline --replace
```

Failed validation preserves the existing database. Stop readers before explicit
replacement and retain the old engine/database pair for rollback. A SHA-256
protects integrity relative to its manifest; authenticate release provenance
over HTTPS and optionally pin the manifest with `--manifest-sha256` from a
separately trusted record. Checksums downloaded together are not signatures.

## Python provisioning API

```python
from pathlib import Path
from libidentifier import install_profiles

manifest = install_profiles(
    Path("download/profiles-manifest.json"),
    database=Path("profiles.sqlite"),
    offline=True,
)
```

`install_profiles` is an explicit maintenance API that may download when passed
an HTTPS URL. It returns the validated manifest; it does not select analysis
paths or modify global configuration. `validate_profiles(database)` provides a
download-free Python health check with compatibility, integrity and inventory
results. `identify`, `inspect`, `scan` and
`correlate` never invoke it. Public analysis JSON remains schema 1; the profile
database is schema 2; release/catalog manifest schemas are separate.

## Optional OSV setup

Install a supported native scanner through its official distribution channel,
then run:

```powershell
libidentifier vulnerabilities update --database advisory-db --ecosystem Maven
libidentifier identify app.apk --profiles profiles.sqlite --vulnerabilities --offline --osv-db advisory-db
```

Scanner discovery and missing-scanner fallback are preserved. Without `--offline`,
the assessment CLI may prepare a wholly missing advisory database. Existing data
requires explicit update. Actual assessment is always offline; see the
[public contract](integration.md). Consumer applications own scanner installation
and resource provisioning during their initialization, never during analysis.

## Maintainer: prepare the Python release

Use a clean committed checkout and run local qualification; the hosted Tests
matrix must also pass for the exact commit before public release.

```powershell
python -m pip install ".[dev,release]"
python -m pytest -q -ra
python -m build
python -m twine check --strict dist/*.whl dist/*.tar.gz
python tools/check_distributions.py dist
```

`src/libidentifier/version.py` is the single version authority. Build a new
version for every PyPI upload: published versions cannot be reused. Keep the
regular wheel and sdist in `dist/`; do not upload local tools/databases or
consumer notes. The `release` extra supplies build and metadata checks.

### Account configuration (manual, once)

1. Sign in to PyPI and enable the account security it requires. Confirm that
   `libidentifier` is available to you; local code does not reserve the name.
2. In PyPI's [publishing settings](https://pypi.org/manage/account/publishing/),
   add a pending GitHub publisher for a new project, or use the existing
   project's Publishing settings if you already own it:
   - PyPI project: `libidentifier`
   - Owner: `ernestomgz`
   - Repository: `libidentifier`
   - Workflow filename: `release.yml`
   - Environment: `pypi`
3. In GitHub repository Settings → Environments create `pypi`. Configure your
   chosen reviewer/tag restrictions before publishing. For a TestPyPI rehearsal,
   configure a separate publisher at TestPyPI and a `testpypi` environment using
   the same repository/workflow with environment `testpypi`.

This uses short-lived GitHub OIDC credentials rather than storing an API token.
See [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) and
the [publishing guide](https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/).
If the project name is unavailable, settle ownership/name before publishing;
do not silently install a different identically named package.

### Publish the package (manual trigger)

1. Push the committed branch to GitHub and wait for its Tests matrix to pass.
2. Create and push the tag from that commit:

   ```powershell
   git tag v0.2.0rc1
   git push origin v0.2.0rc1
   ```

3. Optional rehearsal: Actions → **Preview package release** → Run workflow,
   select tag `v0.2.0rc1` and destination `testpypi`. Selecting `build-only` on
   any branch prepares artifacts without publishing.
4. GitHub Releases → Draft a new release → select `v0.2.0rc1` → mark it as a
   prerelease → publish. The workflow builds and checks distributions, rebuilds
   the sdist, installs the wheel in a fresh environment, then publishes to PyPI.
   Approve the configured environment if requested. As an alternative, dispatch
   the workflow on that tag with destination `pypi`; use one publishing path,
   not both for the same version.
5. Inspect the workflow result and install the exact published version in a
   fresh environment. Hosted qualification and real public acquisition remain
   pending until these manual steps actually succeed.

The workflow does not upload wheels to the GitHub release itself; it retains
them as `python-distributions` Actions artifacts. Download those if you also
want wheel/sdist assets on GitHub. Profile-tag releases do not trigger PyPI.

## Maintainer: prepare and publish profiles

The current schema-2 development database has already been rebuilt. Publish a
small validated snapshot first; catalog expansion and R8 variants come later.
From the clean commit used to package the release:

```powershell
$releaseRevision = git rev-parse HEAD
libidentifier profiles package --database .local/profiles/profiles.sqlite --output-dir dist/profiles-2026.10.20-preview.1 --snapshot-version 2026.10.20-preview.1 --source-revision $releaseRevision
```

The output directory must be new. Packaging creates a sanitized SQLite backup
without changing the source. It removes local source paths from artifact
provenance, retains compiler/source hashes and metadata, stamps the snapshot ID,
validates integrity and emits:

- `profiles.sqlite.gz`
- `profiles-manifest.json`
- `SHA256SUMS`

The manifest records engine compatibility, database/fingerprint versions,
producer revision, compressed/uncompressed hashes and sizes, counts, source
coordinates/hashes/licenses/URLs and explicit coverage limitations. Keep each
snapshot immutable. Use a new identifier for updated data.

1. GitHub Releases → Draft a new release.
2. Create tag **`profiles-2026.10.20-preview.1`** targeting the committed release
   revision. The exact tag matters because the default acquisition URL uses it.
3. Upload the three files from `dist/profiles-2026.10.20-preview.1/`.
4. Describe six families/eight releases, missing POM metadata, engine requirement
   `>=0.2.0rc1,<0.3.0` and preview limitations. Mark the release as a prerelease.
5. Publish, then test `libidentifier profiles install --database fresh.sqlite`
   with the released package. Compare the installed database hash to the manifest.

After publication, release maintainers own data updates; each consuming
application owns when it upgrades its pinned engine/profile pair.
