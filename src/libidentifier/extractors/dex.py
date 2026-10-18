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
    descriptor: str | None = None
    method_index: int | None = None
    code_offset: int | None = None
    bytecode: bytes = b''


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


def parse_dex(data: bytes, *, container: str, member: str | None, sha256: str, tables=None) -> list[ClassFeature]:
    import lief
    from .dex_tables import DexTables

    tables = tables or DexTables(data)
    defined_descriptors = set(tables.classes)
    try:
        parsed = lief.DEX.parse(list(data), name=member or container)
    except TypeError:
        parsed = lief.DEX.parse(list(data))
    if parsed is None:
        raise ValueError("LIEF returned no DEX object")
    classes = []
    for cls in getattr(parsed, "classes", []) or []:
        descriptor = cls.fullname
        if descriptor not in defined_descriptors:
            continue
        superclass, interfaces = tables.classes[descriptor]
        interfaces = tuple(sorted(interfaces))
        fields = []
        for field in getattr(cls, "fields", []) or []:
            if field.index not in tables.defined_fields:
                continue
            fields.append(
                FieldFeature(
                    name=str(getattr(field, "name", "")),
                    type_descriptor=tables.at(tables.fields, field.index)[1],
                    access_flags=_flags(getattr(field, "access_flags", None)),
                )
            )
        methods = []
        for method in getattr(cls, "methods", []) or []:
            index = method.index
            if index not in tables.defined_methods:
                continue
            _, _, (ret, params) = tables.at(tables.methods, index)
            code_offset, bytecode = tables.code.get(index, (None, b''))
            methods.append(
                MethodFeature(
                    name=str(getattr(method, "name", "")),
                    return_type=ret,
                    parameter_types=params,
                    access_flags=_flags(getattr(method, "access_flags", None)),
                    descriptor=tables.method_descriptor(index),
                    method_index=index,
                    code_offset=code_offset,
                    bytecode=bytecode,
                )
            )
        access_flags = _flags(getattr(cls, "access_flags", None))
        # The raw class_defs table already proves this is an embedded definition.
        # Package-private empty classes are valid and must remain in the inventory.
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

