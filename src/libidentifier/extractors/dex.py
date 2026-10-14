"""LIEF DEX feature extraction."""

from __future__ import annotations

import struct
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


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    pos = offset
    for _ in range(5):
        if pos >= len(data):
            raise ValueError("DEX string data is truncated")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
    raise ValueError("DEX ULEB128 value is too large")


def _cstring(data: bytes, offset: int) -> str:
    _utf16_size, pos = _read_uleb128(data, offset)
    try:
        end = data.index(0, pos)
    except ValueError as exc:
        raise ValueError("DEX string data is not NUL-terminated") from exc
    return data[pos:end].decode("utf-8", errors="replace")


def _class_definition_descriptors(data: bytes) -> set[str]:
    if len(data) < 0x70:
        raise ValueError("DEX header is truncated")
    if not data.startswith(b"dex\n"):
        raise ValueError("DEX magic is invalid")
    endian_tag = struct.unpack_from("<I", data, 0x28)[0]
    if endian_tag != 0x12345678:
        raise ValueError("DEX reverse-endian files are not supported")
    file_size = struct.unpack_from("<I", data, 0x20)[0]
    if file_size > len(data):
        raise ValueError("DEX file size exceeds available data")

    string_ids_size, string_ids_off = struct.unpack_from("<II", data, 0x38)
    type_ids_size, type_ids_off = struct.unpack_from("<II", data, 0x40)
    class_defs_size, class_defs_off = struct.unpack_from("<II", data, 0x60)

    def require_table(offset: int, item_size: int, count: int, name: str) -> None:
        if count == 0:
            return
        if offset == 0:
            raise ValueError(f"DEX {name} offset is missing")
        end = offset + item_size * count
        if offset < 0 or end > len(data) or end < offset:
            raise ValueError(f"DEX {name} table is out of bounds")

    require_table(string_ids_off, 4, string_ids_size, "string_ids")
    require_table(type_ids_off, 4, type_ids_size, "type_ids")
    require_table(class_defs_off, 32, class_defs_size, "class_defs")

    strings: list[str] = []
    for i in range(string_ids_size):
        string_off = struct.unpack_from("<I", data, string_ids_off + 4 * i)[0]
        if string_off >= len(data):
            raise ValueError("DEX string offset is out of bounds")
        strings.append(_cstring(data, string_off))

    types: list[str] = []
    for i in range(type_ids_size):
        descriptor_idx = struct.unpack_from("<I", data, type_ids_off + 4 * i)[0]
        if descriptor_idx >= len(strings):
            raise ValueError("DEX type descriptor index is out of bounds")
        types.append(strings[descriptor_idx])

    descriptors: set[str] = set()
    for i in range(class_defs_size):
        class_idx = struct.unpack_from("<I", data, class_defs_off + 32 * i)[0]
        if class_idx >= len(types):
            raise ValueError("DEX class definition index is out of bounds")
        descriptors.add(types[class_idx])
    return descriptors


def parse_dex(data: bytes, *, container: str, member: str | None, sha256: str) -> list[ClassFeature]:
    import lief

    defined_descriptors = _class_definition_descriptors(data)
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
        if descriptor not in defined_descriptors:
            continue
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

