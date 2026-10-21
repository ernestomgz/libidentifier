"""Project-qualified managed scanner builds, independent of GitHub's latest tag."""
from dataclasses import dataclass
import platform

from .errors import AdvisoryError


@dataclass(frozen=True)
class ScannerRelease:
    version: str
    filename: str
    sha256: str

    @property
    def url(self):
        return f"https://github.com/google/osv-scanner/releases/download/v{self.version}/{self.filename}"


# Publisher release SHA-256 values qualified by the project's native CI matrix.
SUPPORTED_SCANNERS = {
    ("Windows", "amd64"): ScannerRelease("2.7.0", "osv-scanner_windows_amd64.exe",
        "9964ed64ec9a387391eb4cc006ad5c531154821aef29b793e02c448de4686438"),
    ("Linux", "amd64"): ScannerRelease("2.7.0", "osv-scanner_linux_amd64",
        "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b"),
}


def supported_scanner(system=None, machine=None):
    system, machine = system or platform.system(), (machine or platform.machine()).lower()
    architecture = "amd64" if machine in {"amd64", "x86_64"} else machine
    try:
        return SUPPORTED_SCANNERS[(system, architecture)]
    except KeyError as error:
        raise AdvisoryError(f"No project-qualified automatic OSV installation for {system}/{machine}; "
                            "use an explicitly configured compatible native scanner",
                            code="scanner_platform_unsupported") from error
