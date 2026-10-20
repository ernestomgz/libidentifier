"""Generic profile matching engine."""

from __future__ import annotations

import hashlib
import math
import sqlite3
from collections import Counter, defaultdict

from .config import IdentifyOptions
from .extractors.dex import ClassFeature
from .extractors.elf import ElfFeature
from .fingerprint.dex_v2 import digest_class, is_trivial_shape
from .models import CodeLocator, CodeOwnerHint, ComponentMatch
from .profiles.store import dex_class_rows, release_rows
from .purl import family_purl


def _component_id(name: str, family_id: str, input_sha: str) -> str:
    return "cmp-" + hashlib.sha256(f"{name}:{family_id}:{input_sha}".encode()).hexdigest()[:16]


def _dex_matches(
    conn: sqlite3.Connection,
    classes: list[ClassFeature],
    *,
    input_sha: str,
    options: IdentifyOptions,
) -> tuple[list[ComponentMatch], list[CodeOwnerHint], set[tuple[str, str | None, str | None]]]:
    observed = Counter()
    locators: dict[str, list[CodeLocator]] = defaultdict(list)
    observed_descriptors: dict[str, Counter[str]] = defaultdict(Counter)
    discriminative_observed: set[str] = set()
    for feature in classes:
        digest = digest_class(feature)
        observed[digest] += 1
        locators[digest].append(feature.locator)
        observed_descriptors[digest][feature.descriptor] += 1
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
    profile_class_totals = {
        rid: sum(
            count
            for _digest, count in conn.execute("SELECT digest, multiplicity FROM dex_shape WHERE release_id=?", (rid,))
        )
        for rid in reference_counts
    }

    candidates = []
    for rid, counts in reference_counts.items():
        structural_matched = sum(min(observed[d], c) for d, c in counts.items())
        structural_weighted = sum(weights.get(d, 1.0) * min(observed[d], c) for d, c in counts.items())
        reference_descriptors = dex_class_rows(conn, rid, set(counts))
        exact_matched = 0
        exact_weighted = 0.0
        for digest, descriptor_counts in reference_descriptors.items():
            for descriptor, ref_count in descriptor_counts.items():
                count = min(observed_descriptors[digest][descriptor], ref_count)
                exact_matched += count
                exact_weighted += weights.get(digest, 1.0) * count
        matched = exact_matched or structural_matched
        weighted = exact_weighted or structural_weighted
        match_mode = "exact_descriptor" if exact_matched else "structural_shape"
        total = totals.get(rid) or 1.0
        discriminative = sum(min(observed[d], c) for d, c in counts.items() if d in discriminative_observed)
        unique_anchors = sum(1 for d in counts if d in discriminative_observed and digest_family_counts.get(d, 99) <= 1)
        candidates.append(
            {
                "release_id": rid,
                "family_id": releases[rid]["family_id"],
                "coverage": weighted / total,
                "matched": matched,
                "structural_matched": structural_matched,
                "exact_descriptor_matches": exact_matched,
                "profile_classes": profile_class_totals.get(rid, sum(counts.values())),
                "discriminative": discriminative,
                "unique_anchors": unique_anchors,
                "digests": set(counts),
                "counts": counts,
                "reference_descriptors": reference_descriptors,
                "match_mode": match_mode,
                "weighted_total": total,
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
    assigned: set[tuple[str, str | None, str | None]] = set()
    for index, cand in enumerate(family_best):
        runner = 0.0
        for j, other in enumerate(family_best):
            if j == index:
                continue
            overlap = cand["digests"].intersection(other["digests"])
            if not overlap:
                continue
            overlap_weight = sum(
                weights.get(d, 1.0) * min(cand["counts"].get(d, 0), other["counts"].get(d, 0))
                for d in overlap
            )
            material_overlap = overlap_weight / max(min(cand["weighted_total"], other["weighted_total"]), 1.0)
            if material_overlap >= options.min_material_runner_overlap:
                runner = max(runner, other["coverage"])
        runner_delta = cand["coverage"] - runner
        if cand["discriminative"] >= options.high_min_discriminative_classes and cand["coverage"] >= options.high_min_weighted_coverage and cand["unique_anchors"] >= options.high_min_unique_anchors and runner_delta >= options.high_min_runner_up_delta:
            confidence = "high"
            partial_match = False
        elif cand["discriminative"] >= options.medium_min_discriminative_classes and cand["coverage"] >= options.medium_min_weighted_coverage and runner_delta >= 0:
            confidence = "medium"
            partial_match = False
        elif (
            cand["match_mode"] == "exact_descriptor"
            and cand["exact_descriptor_matches"] >= options.medium_partial_min_exact_classes
            and cand["coverage"] >= options.medium_partial_min_weighted_coverage
            and cand["unique_anchors"] >= options.medium_partial_min_unique_anchors
            and runner_delta >= 0
        ):
            confidence = "medium"
            partial_match = True
        else:
            continue
        family_releases = sorted(by_family[cand["family_id"]], key=lambda c: (-c["coverage"], c["release_id"]))
        supported_releases = [c for c in family_releases if c is cand or (
            c["coverage"] >= options.medium_min_weighted_coverage
            and c["discriminative"] >= options.medium_min_discriminative_classes
        ) or (
            c["match_mode"] == "exact_descriptor"
            and c["coverage"] >= options.medium_partial_min_weighted_coverage
            and c["exact_descriptor_matches"] >= options.medium_partial_min_exact_classes
            and c["unique_anchors"] >= options.medium_partial_min_unique_anchors
        )]
        all_versions = sorted({releases[c["release_id"]]["version"] for c in supported_releases})
        candidate_versions = all_versions[: options.max_version_candidates]
        exact = [
            releases[c["release_id"]]
            for c in family_releases
            if input_sha in releases[c["release_id"]]['source_hashes']
        ]
        ambiguous_exact = False
        if exact:
            families = conn.execute('SELECT COUNT(DISTINCT r.family_id) FROM reference_artifact a JOIN library_release r USING(release_id) WHERE a.sha256=?', (input_sha,)).fetchone()[0]
            if families != 1:
                ambiguous_exact = True
                exact = []
        version = exact[0]["version"] if len(exact) == 1 else None
        purl = exact[0]["purl"] if len(exact) == 1 else None
        version_confidence = "high" if version else "unknown"
        matched_locs = []
        ambiguous_locs = []
        for digest in sorted(cand["digests"]):
            remaining = cand["counts"][digest]
            descriptor_counts = Counter(cand["reference_descriptors"].get(digest, {}))
            exact_locators = [
                locator
                for locator in locators[digest]
                if locator.class_descriptor in descriptor_counts and descriptor_counts[locator.class_descriptor] > 0
            ]
            if cand["exact_descriptor_matches"]:
                locator_pool = exact_locators
            else:
                locator_pool = locators[digest]
            if len(locator_pool) > remaining:
                # A shape/count cannot choose which physical definition belongs.
                ambiguous_locs.extend(locator_pool)
                matched_locs.extend(locator_pool)
                continue
            for locator in locator_pool:
                if remaining <= 0:
                    break
                matched_locs.append(locator)
                if locator.class_descriptor in descriptor_counts:
                    descriptor_counts[locator.class_descriptor] -= 1
                remaining -= 1
        if not matched_locs:
            continue
        release = releases[cand["release_id"]]
        cid = _component_id(release["name"], cand["family_id"], input_sha)
        for locator in matched_locs:
            key = (locator.container, locator.member, locator.class_descriptor)
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
                family_purl=family_purl(release["purl"]),
                version_candidates_total=len(all_versions),
                version_candidates_truncated=len(candidate_versions) < len(all_versions),
                version=version,
                version_candidates=candidate_versions,
                identity_confidence=confidence,
                version_confidence=version_confidence,
                identification_methods=["dex_shape_v1"],
                score=round(cand["coverage"], 6),
                score_details={
                    "version_candidate_scores": {releases[c["release_id"]]["version"]: {"weighted_coverage": round(c["coverage"], 6), "exact_descriptor_matches": c["exact_descriptor_matches"], "supported": c in supported_releases} for c in family_releases},
                    "matched_classes": cand["matched"],
                    "profile_classes": cand["profile_classes"],
                    "exact_descriptor_matches": cand["exact_descriptor_matches"],
                    "structural_matched_classes": cand["structural_matched"],
                    "match_mode": cand["match_mode"],
                    "partial_match": partial_match,
                    "weighted_coverage": round(cand["coverage"], 6),
                    "unique_anchors": cand["unique_anchors"],
                    "runner_up_delta": round(runner_delta, 6),
                    "ambiguous_code": [x.to_dict() for x in ambiguous_locs],
                },
                matched_code=sorted(matched_locs, key=lambda x: (x.container, x.member or "", x.class_descriptor or "")),
                source_artifacts=sorted({x.member or x.container for x in matched_locs}),
                limitations=(
                    ([] if version else ["release version cannot be distinguished from structural fingerprints alone"])
                    + (["Exact reference bytes are assigned to multiple library families; identity/version remain ambiguous"] if ambiguous_exact else [])
                    + (["partial library match; not all reference classes were observed"] if partial_match else [])
                    + (
                        ["matched code is assigned by structural shape because reference descriptors were not observed"]
                        if cand["match_mode"] == "structural_shape"
                        else []
                    )
                ),
            )
        )
    return components, hints, assigned


def _elf_matches(
    conn: sqlite3.Connection,
    elf_features: list[tuple[ElfFeature, object]],
    *,
    input_sha: str,
    container: str,
    options: IdentifyOptions,
) -> list[ComponentMatch]:
    components: dict[str, ComponentMatch] = {}
    for feature, artifact in elf_features:
        rows = list(conn.execute(
            """
            SELECT DISTINCT r.family_id, r.version, r.purl, f.name, f.ecosystem
            FROM elf_identity e
            JOIN library_release r USING(release_id)
            JOIN library_family f USING(family_id)
            WHERE e.sha256=? ORDER BY f.name, r.version, r.purl
            """, (feature.sha256,),
        ))
        # Identical bytes assigned to different families cannot establish identity.
        if not rows or len({r[0] for r in rows}) != 1:
            continue
        fid, _, _, name, ecosystem = rows[0]
        versions = sorted({r[1] for r in rows})
        version = versions[0] if len(versions) == 1 else None
        purls = {r[2] for r in rows}
        purl = next(iter(purls)) if version and len(purls) == 1 else None
        families = {family_purl(r[2]) for r in rows}
        cid = _component_id(name, fid, input_sha + feature.sha256)
        locator = CodeLocator(container=getattr(artifact, "container", None) or container,
                              member=getattr(artifact, "member", None), sha256=feature.sha256)
        source = getattr(artifact, "member", None) or getattr(artifact, "path", None) or container
        if cid in components:
            components[cid].matched_code.append(locator)
            if source not in components[cid].source_artifacts:
                components[cid].source_artifacts.append(source)
            continue
        candidates = versions[:options.max_version_candidates]
        components[cid] = ComponentMatch(
            component_id=cid, name=name, ecosystem=ecosystem, purl=purl,
            family_purl=next(iter(families)) if len(families) == 1 else None,
            version=version, version_candidates=candidates,
            version_candidates_total=len(versions), version_candidates_truncated=len(candidates) < len(versions),
            identity_confidence="high", version_confidence="high" if version else "unknown",
            identification_methods=["elf_identity_v1"], score=1.0,
            score_details={"matched_classes": 0, "profile_classes": 0, "weighted_coverage": 1.0,
                           "unique_anchors": 1, "runner_up_delta": 1.0},
            matched_code=[locator], source_artifacts=[source],
            limitations=[] if version else ["Identical ELF bytes occur in multiple reference releases; exact version is unknown"],
        )
    for component in components.values():
        component.matched_code.sort(key=lambda loc: (loc.container, loc.member or ""))
        component.source_artifacts.sort()
    return list(components.values())


def match_inventory(conn: sqlite3.Connection, inventory, options: IdentifyOptions):
    dex_components, hints, assigned = _dex_matches(conn, inventory.dex_classes, input_sha=inventory.input.sha256, options=options)
    elf_components = _elf_matches(conn, inventory.elf_features, input_sha=inventory.input.sha256, container=inventory.input.path, options=options)
    from dataclasses import replace
    from .models import OwnershipAssertion
    claims = defaultdict(set)
    ambiguous = set()
    for component in dex_components:
        for loc in component.matched_code:
            claims[(loc.container, loc.member, loc.class_descriptor)].add(component.component_id)
        for raw in component.score_details.get('ambiguous_code', []):
            ambiguous.add((raw['container'], raw['member'], raw['class_descriptor']))
    descriptors = Counter(c.descriptor for c in inventory.dex_classes)
    assigned = set()
    assertions = []
    for feature in inventory.dex_classes:
        loc = feature.locator
        key = (loc.container, loc.member, loc.class_descriptor)
        owners = sorted(claims[key])
        disputed = len(owners) > 1 or key in ambiguous or descriptors[feature.descriptor] > 1
        status = 'ambiguous' if disputed else ('attributed' if owners else 'unattributed')
        if status == 'attributed':
            assigned.add(key)
        assertions.append(OwnershipAssertion(loc, status, owners,
            limitations=['Competing or duplicate code definitions; ownership unresolved'] if disputed else []))
    inventory.ownership_assertions = assertions
    cleaned = []
    for component in dex_components:
        locations = [loc for loc in component.matched_code if (loc.container, loc.member, loc.class_descriptor) in assigned]
        cleaned.append(replace(component, matched_code=locations,
            limitations=component.limitations + (['Some matching evidence has ambiguous ownership'] if len(locations) < len(component.matched_code) else [])))
    components = sorted(cleaned + elf_components, key=lambda c: (c.name, c.component_id))
    hints = [CodeOwnerHint(loc.class_descriptor or '', 'third_party', c.component_id, c.identity_confidence, 'structural_fingerprint')
             for c in cleaned for loc in c.matched_code]
    hints.sort(key=lambda h: (h.component_id, h.subject))
    unknown = [
        feature.locator
        for feature in inventory.dex_classes
        if (feature.locator.container, feature.locator.member, feature.locator.class_descriptor) not in assigned
    ]
    unknown.sort(key=lambda x: (x.container, x.member or "", x.class_descriptor or ""))
    return components, hints, unknown

