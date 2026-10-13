"""LIEF DEX feature extraction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..models import CodeLocator


@dataclass(frozen=True)
class FieldFeature:
    name: str
    type_descriptor: str
    access_flags: list[str]


@dataclass(frozen=True)
class MethodFeature:
    name: str
    return_type: str
    parameter_types: tuple[str, ...]
    access_flags: list[str]


@dataclass(frozen=True)
class ClassFeature:
    descriptor: str
    access_flags: list[str]
    superclass: str | None
    interfaces: tuple[str, ...]
    fields: tuple[FieldFeature, ...]
    methods: tuple[MethodFeature, ...]
    source_filename: str | None
    locator: CodeLocator


def _flags(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, int):
        return [str(value)] if value else []
    try:
        iterable = list(value)
    except TypeError:
        return [str(value)]
    return sorted(str(x).split(".")[-1].lower() for x in iterable)


def _type_descriptor(value: Any) -> str:
    if value is None:
        return "V"
    for attr in ("descriptor", "fullname", "name"):
        got = getattr(value, attr, None)
        if isinstance(got, str):
            return got
    return str(value)


def _method_proto(method: Any) -> tuple[str, tuple[str, ...]]:
    proto = getattr(method, "prototype", None)
    if proto is None:
        proto = getattr(method, "proto", None)
    return_type = _type_descriptor(getattr(proto, "return_type", None))
    params = getattr(proto, "parameters_type", None)
    if params is None:
        params = getattr(proto, "parameters", None)
    if params is None:
        params = []
    return return_type, tuple(_type_descriptor(p) for p in params)


def parse_dex(data: bytes, *, container: str, member: str | None, sha256: str) -> list[ClassFeature]:
    import lief

    try:
        parsed = lief.DEX.parse(list(data), name=member or container)
    except TypeError:
        parsed = lief.DEX.parse(list(data))
    if parsed is None:
        raise ValueError("LIEF returned no DEX object")
    classes = []
    for cls in getattr(parsed, "classes", []) or []:
        descriptor = _type_descriptor(cls)
        if not descriptor.startswith("L") and "/" not in descriptor:
            fullname = getattr(cls, "fullname", None)
            descriptor = fullname if isinstance(fullname, str) else descriptor
        superclass = _type_descriptor(getattr(cls, "parent", None)) if getattr(cls, "parent", None) else None
        interfaces = tuple(sorted(_type_descriptor(i) for i in (getattr(cls, "interfaces", []) or [])))
        fields = []
        for field in getattr(cls, "fields", []) or []:
            fields.append(
                FieldFeature(
                    name=str(getattr(field, "name", "")),
                    type_descriptor=_type_descriptor(getattr(field, "type", None)),
                    access_flags=_flags(getattr(field, "access_flags", None)),
                )
            )
        methods = []
        for method in getattr(cls, "methods", []) or []:
            ret, params = _method_proto(method)
            methods.append(
                MethodFeature(
                    name=str(getattr(method, "name", "")),
                    return_type=ret,
                    parameter_types=params,
                    access_flags=_flags(getattr(method, "access_flags", None)),
                )
            )
        access_flags = _flags(getattr(cls, "access_flags", None))
        if not access_flags and not fields and not methods:
            continue
        classes.append(
            ClassFeature(
                descriptor=descriptor,
                access_flags=access_flags,
                superclass=superclass,
                interfaces=interfaces,
                fields=tuple(sorted(fields, key=lambda f: (f.type_descriptor, f.name))),
                methods=tuple(sorted(methods, key=lambda m: (m.name, m.return_type, m.parameter_types))),
                source_filename=getattr(cls, "source_filename", None),
                locator=CodeLocator(container=container, member=member, class_descriptor=descriptor, sha256=sha256),
            )
        )
    if not classes:
        raise ValueError("DEX contains no class definitions")
    return sorted(classes, key=lambda c: c.descriptor)

