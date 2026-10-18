"""Deterministic inexpensive clustering; clusters make no library-origin claim."""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from .models import UnattributedCluster


def locator_key(loc):
    return (loc.container, loc.member or '', loc.class_descriptor or '')


def stable_id(prefix, value):
    return prefix + '-' + hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()[:24]


def group_unknown(classes, unknown, relationships):
    locators = {locator_key(loc): loc for loc in unknown}
    parent = {key: key for key in locators}
    def root(key):
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key
    def join(a, b):
        a, b = root(a), root(b)
        parent[max(a,b)] = min(a,b)
    namespaces = defaultdict(list)
    for key in locators:
        desc = key[2]
        package = desc[1:].rsplit('/', 1)[0] if '/' in desc else None
        # Root/default and broad namespace prefixes are not useful identities.
        if package and '/' in package and package not in {'com/google', 'com/android', 'org/apache'}:
            namespaces[package].append(key)
    for members in namespaces.values():
        for key in members[1:]:
            join(members[0], key)
    structural_pairs = []
    for rel in relationships:
        if rel.source.location is None or rel.target.location is None:
            continue
        a, b = locator_key(rel.source.location), locator_key(rel.target.location)
        if a in parent and b in parent and rel.type in {'inheritance', 'interface_implementation'}:
            # Type-signature/call connectivity alone easily bridges separate code.
            join(a, b)
            structural_pairs.append((a,b,rel.type))
    groups = defaultdict(list)
    for key in sorted(locators):
        groups[root(key)].append(key)
    supports = defaultdict(list)
    used_methods = defaultdict(set)
    for members in namespaces.values():
        if len(members) > 1:
            used_methods[root(members[0])].add('namespace')
    for a,b,kind in structural_pairs:
        used_methods[root(a)].add(kind)
    for rel in relationships:
        if rel.type not in {'inheritance','interface_implementation'} or not rel.source.location or not rel.target.location:
            continue
        a,b=locator_key(rel.source.location),locator_key(rel.target.location)
        if a in parent and b in parent and root(a)==root(b):
            supports[root(a)].append(rel.id)
    results = []
    for group,members in groups.items():
        methods = used_methods[group] or {'singleton'}
        packages = {k[2][1:].rsplit('/',1)[0] for k in members if '/' in k[2]}
        hint = next(iter(packages)).replace('/', '.') if len(packages) == 1 else None
        results.append(UnattributedCluster(stable_id('cluster', members), len(members),
            [locators[k] for k in members], hint, sorted(methods),
            quality={'namespace_count': len(packages), 'singleton': len(members) == 1},
            limitations=['Grouping does not establish common library origin; namespace reuse and obfuscation may mix code'],
            supporting_relationship_ids=sorted(supports[group])))
    return sorted(results, key=lambda c:c.id)
