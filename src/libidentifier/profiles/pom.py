"""Direct POM declarations with local, bounded property substitution only."""
from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET

MAX_POM_BYTES = 1024 * 1024


def parse_pom(data: bytes, *, source: str, expected: tuple[str, str, str] | None = None):
    if len(data) > MAX_POM_BYTES or b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise ValueError('Oversized or unsupported POM XML declaration')
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError(f'Invalid POM XML: {exc}') from exc
    for element in root.iter():
        element.tag = element.tag.rsplit('}', 1)[-1]
    def text(node, name, default=None):
        value = node.findtext(name)
        return value.strip() if value else default
    if root.tag != 'project':
        raise ValueError('POM root is not project')
    group, artifact, version = (text(root, name) for name in ('groupId', 'artifactId', 'version'))
    props = {child.tag: (child.text or '').strip() for child in root.findall('properties/*')}
    for name, value in [('groupId', group), ('artifactId', artifact), ('version', version)]:
        if value:
            props['project.' + name] = value
            props['pom.' + name] = value
    def resolve(value):
        if value is None:
            return None
        seen = set()
        for _ in range(16):
            if value in seen:
                break
            seen.add(value)
            changed = re.sub(r'\$\{([^}]+)\}', lambda m: props.get(m[1], m[0]), value)
            if changed == value:
                break
            value = changed
        return None if '${' in value else value
    coordinates = tuple(resolve(x) for x in (group, artifact, version))
    if expected and any(a is not None and a != b for a, b in zip(coordinates, expected)):
        raise ValueError('POM coordinates disagree with reference release')
    limitations = ['Only direct declarations and local properties are interpreted; no build dependency tree is reconstructed']
    if root.find('parent') is not None:
        limitations.append('Parent inheritance is not resolved')
    if root.find('dependencyManagement') is not None:
        limitations.append('Dependency management and BOMs are retained but not resolved')
    if root.find('profiles') is not None:
        limitations.append('Profile activation and profile dependencies are not resolved')
    declarations = []
    for dep in root.findall('dependencies/dependency'):
        raw = {key: text(dep, key) for key in ('groupId', 'artifactId', 'version', 'scope', 'optional', 'type', 'classifier')}
        values = {key: resolve(value) for key, value in raw.items()}
        # A missing managed version is unresolved, never an empty exact version.
        status = 'resolved' if all(values[k] for k in ('groupId', 'artifactId', 'version')) else 'unresolved'
        declarations.append({'declared': raw, 'interpreted': values, 'status': status,
                             'exclusions': [{'groupId': text(x, 'groupId'), 'artifactId': text(x, 'artifactId')}
                                            for x in dep.findall('exclusions/exclusion')]})
    return {'sha256': hashlib.sha256(data).hexdigest(), 'source': source,
            'coordinates': coordinates, 'declarations': declarations,
            'status': 'partial' if len(limitations) > 1 or any(d['status'] == 'unresolved' for d in declarations) else 'complete',
            'limitations': limitations, 'raw_xml': data.decode('utf-8-sig')}
