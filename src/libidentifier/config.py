"""Configuration knobs for scanning and matching."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IdentifyOptions:
    max_archive_members: int = 20_000
    max_member_uncompressed_bytes: int = 128 * 1024 * 1024
    max_total_selected_uncompressed_bytes: int = 512 * 1024 * 1024
    max_compression_ratio: int = 200
    max_directory_files: int = 20_000
    max_directory_depth: int = 8
    max_scan_seconds: int = 180
    max_emitted_unknown_classes: int = 5_000
    medium_min_discriminative_classes: int = 3
    medium_min_weighted_coverage: float = 0.75
    medium_partial_min_exact_classes: int = 25
    medium_partial_min_weighted_coverage: float = 0.65
    medium_partial_min_unique_anchors: int = 10
    high_min_discriminative_classes: int = 5
    high_min_weighted_coverage: float = 0.90
    high_min_unique_anchors: int = 2
    high_min_runner_up_delta: float = 0.15
    min_material_runner_overlap: float = 0.25
    max_version_candidates: int = 12


FINGERPRINT_ALGORITHM = "dex-shape-v1-defs+elf-identity-v1"
SCHEMA_VERSION = 1

