"""elf-identity-v1 helper functions."""

from __future__ import annotations

from ..extractors.elf import ElfFeature


def identity_record(feature: ElfFeature) -> dict[str, str | None]:
    return {
        "abi": feature.abi,
        "sha256": feature.sha256,
        "build_id": feature.build_id,
        "soname": feature.soname,
        "symbol_digest": feature.symbol_digest,
    }

