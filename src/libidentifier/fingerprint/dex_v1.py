"""dex-shape-v1 canonical class fingerprints."""

from __future__ import annotations

import hashlib
import json
from collections import Counter

from ..extractors.dex import ClassFeature

PLATFORM_PREFIXES = (
    "Ljava/",
    "Ljavax/",
    "Landroid/",
    "Landroidx/",
    "Ldalvik/",
    "Lkotlin/",
)


def normalize_type(descriptor: str | None) -> str:
    if not descriptor:
        return "UNKNOWN"
    primitive_names = {
        "void": "V",
        "boolean": "Z",
        "byte": "B",
        "short": "S",
        "char": "C",
        "int": "I",
        "long": "J",
        "float": "F",
        "double": "D",
    }
    descriptor = primitive_names.get(descriptor, descriptor)
    depth = 0
    while descriptor.startswith("["):
        depth += 1
        descriptor = descriptor[1:]
    if descriptor in {"V", "Z", "B", "S", "C", "I", "J", "F", "D"}:
        base = descriptor
    elif descriptor.startswith(PLATFORM_PREFIXES):
        base = descriptor
    elif descriptor.startswith("L"):
        base = "OBJECT"
    else:
        base = "UNKNOWN"
    return ("ARRAY:" * depth) + base


def _method_kind(name: str) -> str:
    if name == "<init>":
        return "constructor"
    if name == "<clinit>":
        return "class_initializer"
    return "method"


def class_shape_map(feature: ClassFeature) -> dict:
    fields = [
        {"type": normalize_type(f.type_descriptor), "flags": sorted(f.access_flags)} for f in feature.fields
    ]
    methods = [
        {
            "kind": _method_kind(m.name),
            "return": normalize_type(m.return_type),
            "params": [normalize_type(p) for p in m.parameter_types],
            "flags": sorted(m.access_flags),
        }
        for m in feature.methods
    ]
    return {
        "class_flags": sorted(feature.access_flags),
        "field_count": len(feature.fields),
        "method_count": len(feature.methods),
        "interface_count": len(feature.interfaces),
        "super": normalize_type(feature.superclass),
        "interfaces": sorted(normalize_type(i) for i in feature.interfaces),
        "fields": sorted(fields, key=lambda x: json.dumps(x, sort_keys=True, separators=(",", ":"))),
        "methods": sorted(methods, key=lambda x: json.dumps(x, sort_keys=True, separators=(",", ":"))),
    }


def digest_class(feature: ClassFeature) -> str:
    payload = json.dumps(class_shape_map(feature), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    return hashlib.sha256(b"dex-shape-v1\0" + payload).hexdigest()


def digest_counts(features: list[ClassFeature]) -> Counter[str]:
    return Counter(digest_class(f) for f in features)


def is_trivial_shape(feature: ClassFeature) -> bool:
    return len(feature.fields) == 0 and len(feature.methods) <= 1 and len(feature.interfaces) == 0

