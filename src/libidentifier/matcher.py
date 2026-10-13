"""Generic profile matching engine."""

from __future__ import annotations

import hashlib
import math
import sqlite3
from collections import Counter, defaultdict

from .config import IdentifyOptions
from .extractors.dex import ClassFeature
from .extractors.elf import ElfFeature
from .fingerprint.dex_v1 import digest_class, is_trivial_shape
from .models import CodeLocator, CodeOwnerHint, ComponentMatch
from .profiles.store import release_rows


def _component_id(name: str, family_id: str, input_sha: str) -> str:
    return "cmp-" + hashlib.sha256(f"{name}:{family_id}:{input_sha}".encode()).hexdigest()[:16]


def _dex_matches(
    conn: sqlite3.Connection,
    classes: list[ClassFeature],
    *,
    input_sha: str,
    options: IdentifyOptions,
) -> tuple[list[ComponentMatch], list[CodeOwnerHint], set[tuple[str | None, str | None]]]:
    observed = Counter()
    locators: dict[str, list[CodeLocator]] = defaultdict(list)
    discriminative_observed: set[str] = set()
    for feature in classes:
        digest = digest_class(feature)
        observed[digest] += 1
        locators[digest].append(feature.locator)
        if not is_trivial_shape(feature):
            discriminative_observed.add(digest)
    if not observed:
        return [], [], set()

    placeholders = ",".join("?" for _ in observed)
    rows = list(
        conn.execute(
            f"SELECT digest, release_id, multiplicity FROM dex_shape WHERE digest IN ({placeholders})",
            tuple(sorted(observed)),
        )
    )
    release_ids = {row[1] for row in rows}
    releases = release_rows(conn, release_ids)
    if not rows:
        return [], [], set()

    digest_family_counts = {
        digest: count
        for digest, count in conn.execute(
            f"""
            SELECT ds.digest, COUNT(DISTINCT lr.family_id)
            FROM dex_shape ds JOIN library_release lr USING(release_id)
            WHERE ds.digest IN ({placeholders})
            GROUP BY ds.digest
            """,
            tuple(sorted(observed)),
        )
    }
    family_count = conn.execute("SELECT COUNT(*) FROM library_family").fetchone()[0] or 1
    weights = {d: 1.0 + math.log((1.0 + family_count) / (1.0 + digest_family_counts.get(d, family_count))) for d in observed}

    reference_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for digest, rid, multiplicity in rows:
        reference_counts[rid][digest] = int(multiplicity)
    totals: dict[str, float] = {}
    for rid in reference_counts:
        totals[rid] = sum(
            weights.get(d, 1.0) * count
            for d, count in conn.execute("SELECT digest, multiplicity FROM dex_shape WHERE release_id=?", (rid,))
        )

    candidates = []
    for rid, counts in reference_counts.items():
        matched = sum(min(observed[d], c) for d, c in counts.items())
        weighted = sum(weights.get(d, 1.0) * min(observed[d], c) for d, c in counts.items())
        total = totals.get(rid) or 1.0
        discriminative = sum(min(observed[d], c) for d, c in counts.items() if d in discriminative_observed)
        unique_anchors = sum(1 for d in counts if d in discriminative_observed and digest_family_counts.get(d, 99) <= 1)
        candidates.append(
            {
                "release_id": rid,
                "family_id": releases[rid]["family_id"],
                "coverage": weighted / total,
                "matched": matched,
                "profile_classes": sum(counts.values()),
                "discriminative": discriminative,
                "unique_anchors": unique_anchors,
                "digests": set(counts),
                "counts": counts,
            }
        )

    by_family: dict[str, list[dict]] = defaultdict(list)
    for cand in candidates:
        by_family[cand["family_id"]].append(cand)
    family_best = []
    for fid, cands in by_family.items():
        best = sorted(cands, key=lambda c: (-c["coverage"], -c["matched"], c["release_id"]))[0]
        family_best.append(best)
    family_best.sort(key=lambda c: (-c["coverage"], -c["matched"], c["family_id"]))

    components: list[ComponentMatch] = []
    hints: list[CodeOwnerHint] = []
    assigned: set[tuple[str | None, str | None]] = set()
    for index, cand in enumerate(family_best):
        runner = max(
            (
                c["coverage"]
                for j, c in enumerate(family_best)
                if j != index and cand["digests"].intersection(c["digests"])
            ),
            default=0.0,
        )
        runner_delta = cand["coverage"] - runner
        if cand["discriminative"] >= options.high_min_discriminative_classes and cand["coverage"] >= options.high_min_weighted_coverage and cand["unique_anchors"] >= options.high_min_unique_anchors and runner_delta >= options.high_min_runner_up_delta:
            confidence = "high"
        elif cand["discriminative"] >= options.medium_min_discriminative_classes and cand["coverage"] >= options.medium_min_weighted_coverage and runner_delta >= 0:
            confidence = "medium"
        else:
            continue
        family_releases = sorted(by_family[cand["family_id"]], key=lambda c: (-c["coverage"], c["release_id"]))
        candidate_versions = sorted({releases[c["release_id"]]["version"] for c in family_releases})[: options.max_version_candidates]
        exact = [
            releases[c["release_id"]]
            for c in family_releases
            if releases[c["release_id"]]["source_sha256"] == input_sha
        ]
        version = exact[0]["version"] if len(exact) == 1 else None
        purl = exact[0]["purl"] if len(exact) == 1 else None
        version_confidence = "high" if version else "unknown"
        matched_locs = []
        for digest in sorted(cand["digests"]):
            remaining = cand["counts"][digest]
            for locator in locators[digest]:
                if remaining <= 0:
                    break
                key = (locator.member, locator.class_descriptor)
                if key not in assigned:
                    matched_locs.append(locator)
                    remaining -= 1
        if not matched_locs:
            continue
        release = releases[cand["release_id"]]
        cid = _component_id(release["name"], cand["family_id"], input_sha)
        for locator in matched_locs:
            key = (locator.member, locator.class_descriptor)
            assigned.add(key)
            hints.append(
                CodeOwnerHint(
                    subject=locator.class_descriptor or "",
                    origin="third_party",
                    component_id=cid,
                    confidence=confidence,
                    method="structural_fingerprint",
                )
            )
        components.append(
            ComponentMatch(
                component_id=cid,
                name=release["name"],
                ecosystem=release["ecosystem"],
                purl=purl,
                version=version,
                version_candidates=candidate_versions,
                identity_confidence=confidence,
                version_confidence=version_confidence,
                identification_methods=["dex_shape_v1"],
                score=round(cand["coverage"], 6),
                score_details={
                    "matched_classes": cand["matched"],
                    "profile_classes": cand["profile_classes"],
                    "weighted_coverage": round(cand["coverage"], 6),
                    "unique_anchors": cand["unique_anchors"],
                    "runner_up_delta": round(runner_delta, 6),
                },
                matched_code=sorted(matched_locs, key=lambda x: (x.member or "", x.class_descriptor or "")),
                source_artifacts=sorted({x.member or x.container for x in matched_locs}),
                limitations=[] if version else ["release version cannot be distinguished from structural fingerprints alone"],
            )
        )
    return components, hints, assigned


def _elf_matches(
    conn: sqlite3.Connection,
    elf_features: list[tuple[ElfFeature, object]],
    *,
    input_sha: str,
    container: str,
) -> list[ComponentMatch]:
    components: list[ComponentMatch] = []
    for feature, artifact in elf_features:
        rows = list(
            conn.execute(
                """
                SELECT r.release_id, r.family_id, r.version, r.purl, f.name, f.ecosystem
                FROM elf_identity e
                JOIN library_release r USING(release_id)
                JOIN library_family f USING(family_id)
                WHERE e.sha256=?
                ORDER BY f.name, r.version
                """,
                (feature.sha256,),
            )
        )
        if len(rows) != 1:
            continue
        rid, fid, version, purl, name, ecosystem = rows[0]
        cid = _component_id(name, fid, input_sha + feature.sha256)
        locator = CodeLocator(container=container, member=getattr(artifact, "member", None), sha256=feature.sha256)
        components.append(
            ComponentMatch(
                component_id=cid,
                name=name,
                ecosystem=ecosystem,
                purl=purl,
                version=version,
                version_candidates=[version],
                identity_confidence="high",
                version_confidence="high",
                identification_methods=["elf_identity_v1"],
                score=1.0,
                score_details={
                    "matched_classes": 0,
                    "profile_classes": 0,
                    "weighted_coverage": 1.0,
                    "unique_anchors": 1,
                    "runner_up_delta": 1.0,
                },
                matched_code=[locator],
                source_artifacts=[getattr(artifact, "member", None) or getattr(artifact, "path", None) or "elf"],
                limitations=[],
            )
        )
    return components


def match_inventory(conn: sqlite3.Connection, inventory, options: IdentifyOptions):
    dex_components, hints, assigned = _dex_matches(conn, inventory.dex_classes, input_sha=inventory.input.sha256, options=options)
    elf_components = _elf_matches(conn, inventory.elf_features, input_sha=inventory.input.sha256, container=inventory.input.path)
    components = sorted(dex_components + elf_components, key=lambda c: (c.name, c.component_id))
    hints = sorted(hints, key=lambda h: (h.component_id, h.subject))
    unknown = [
        feature.locator
        for feature in inventory.dex_classes
        if (feature.locator.member, feature.locator.class_descriptor) not in assigned
    ]
    unknown.sort(key=lambda x: (x.member or "", x.class_descriptor or ""))
    return components, hints, unknown

