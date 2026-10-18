from __future__ import annotations

import hashlib
import struct
import zlib
import zipfile
from pathlib import Path

import pytest

from libidentifier.api import build_profile

ACC_PUBLIC = 0x1
ACC_PRIVATE = 0x2
ACC_PROTECTED = 0x4
ACC_STATIC = 0x8
ACC_ABSTRACT = 0x400
ACC_NATIVE = 0x100


def uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def shorty(desc: str) -> str:
    while desc.startswith("["):
        desc = desc[1:]
    if desc.startswith("L"):
        return "L"
    return desc[0]


def make_dex(classes: list[dict]) -> bytes:
    strings: set[str] = {"V", "I", "Ljava/lang/Object;"}
    types: set[str] = {"V", "I", "Ljava/lang/Object;"}
    protos: set[tuple[str, tuple[str, ...]]] = set()
    fields = []
    methods = []
    for cls in classes:
        desc = cls["descriptor"]
        strings.add(desc)
        types.add(desc)
        super_desc = cls.get("superclass", "Ljava/lang/Object;")
        strings.add(super_desc)
        types.add(super_desc)
        for interface in cls.get('interfaces', []):
            strings.add(interface)
            types.add(interface)
        if cls.get("source"):
            strings.add(cls["source"])
        for field in cls.get("fields", []):
            strings.add(field["name"])
            strings.add(field["type"])
            types.add(field["type"])
            fields.append((desc, field["type"], field["name"]))
        for method in cls.get("methods", []):
            ret = method.get("return", "V")
            params = tuple(method.get("params", []))
            strings.add(method["name"])
            strings.add(ret)
            types.add(ret)
            for param in params:
                strings.add(param)
                types.add(param)
            protos.add((ret, params))
            methods.append((desc, ret, params, method["name"]))
    strings.update(shorty(ret) + "".join(shorty(p) for p in params) for ret, params in protos)
    strings_sorted = sorted(strings)
    string_idx = {s: i for i, s in enumerate(strings_sorted)}
    types_sorted = sorted(types, key=lambda t: string_idx[t])
    type_idx = {t: i for i, t in enumerate(types_sorted)}
    protos_sorted = sorted(protos, key=lambda p: (string_idx[shorty(p[0]) + "".join(shorty(x) for x in p[1])], type_idx[p[0]], [type_idx[x] for x in p[1]]))
    proto_idx = {p: i for i, p in enumerate(protos_sorted)}
    fields_sorted = sorted(fields, key=lambda f: (type_idx[f[0]], string_idx[f[2]], type_idx[f[1]]))
    field_idx = {f: i for i, f in enumerate(fields_sorted)}
    methods_sorted = sorted(methods, key=lambda m: (type_idx[m[0]], string_idx[m[3]], proto_idx[(m[1], m[2])]))
    method_idx = {m: i for i, m in enumerate(methods_sorted)}
    classes_sorted = sorted(classes, key=lambda c: type_idx[c["descriptor"]])

    header_size = 0x70
    string_ids_off = header_size
    type_ids_off = string_ids_off + 4 * len(strings_sorted)
    proto_ids_off = type_ids_off + 4 * len(types_sorted)
    field_ids_off = proto_ids_off + 12 * len(protos_sorted)
    method_ids_off = field_ids_off + 8 * len(fields_sorted)
    class_defs_off = method_ids_off + 8 * len(methods_sorted)
    data_off = class_defs_off + 32 * len(classes_sorted)
    data = bytearray()
    string_offsets = {}
    type_list_offsets = {}
    class_data_offsets = {}
    code_offsets = {}

    def align4() -> None:
        while (data_off + len(data)) % 4:
            data.append(0)

    for s in strings_sorted:
        string_offsets[s] = data_off + len(data)
        raw = s.encode("utf-8")
        data.extend(uleb(len(s)))
        data.extend(raw)
        data.append(0)
    for ret, params in protos_sorted:
        if params:
            align4()
            type_list_offsets[(ret, params)] = data_off + len(data)
            data.extend(struct.pack("<I", len(params)))
            for param in params:
                data.extend(struct.pack("<H", type_idx[param]))
            if len(params) % 2:
                data.extend(b"\0\0")
        else:
            type_list_offsets[(ret, params)] = 0
    for cls in classes_sorted:
        if cls.get('interfaces'):
            align4()
            type_list_offsets[cls['descriptor']] = data_off + len(data)
            data.extend(struct.pack('<I', len(cls['interfaces'])))
            for interface in cls['interfaces']:
                data.extend(struct.pack('<H', type_idx[interface]))
        for method in cls.get('methods', []):
            if 'code' in method:
                align4()
                key = (cls['descriptor'], method.get('return', 'V'), tuple(method.get('params', [])), method['name'])
                code_offsets[key] = data_off + len(data)
                words = method['code'](method_idx) if callable(method['code']) else method['code']
                data.extend(struct.pack('<HHHHII', 8, 0, 5, 0, 0, len(words)))
                data.extend(struct.pack('<'+'H'*len(words), *words))
        class_data_offsets[cls["descriptor"]] = data_off + len(data)
        cls_fields = [(cls["descriptor"], f["type"], f["name"], f.get("flags", ACC_PRIVATE)) for f in cls.get("fields", [])]
        cls_methods = [
            (cls["descriptor"], m.get("return", "V"), tuple(m.get("params", [])), m["name"], m.get("flags", ACC_PUBLIC | ACC_ABSTRACT))
            for m in cls.get("methods", [])
        ]
        cls_fields.sort(key=lambda f: field_idx[(f[0], f[1], f[2])])
        cls_methods.sort(key=lambda m: method_idx[(m[0], m[1], m[2], m[3])])
        data.extend(uleb(0))
        data.extend(uleb(len(cls_fields)))
        data.extend(uleb(0))
        data.extend(uleb(len(cls_methods)))
        last = 0
        for field in cls_fields:
            idx = field_idx[(field[0], field[1], field[2])]
            data.extend(uleb(idx - last))
            data.extend(uleb(field[3]))
            last = idx
        last = 0
        for method in cls_methods:
            idx = method_idx[(method[0], method[1], method[2], method[3])]
            data.extend(uleb(idx - last))
            data.extend(uleb(method[4]))
            data.extend(uleb(code_offsets.get((method[0],method[1],method[2],method[3]), 0)))
            last = idx
    align4()
    map_off = data_off + len(data)
    map_items = [
        (0x0001, len(strings_sorted), string_ids_off),
        (0x0002, len(types_sorted), type_ids_off),
    ]
    if protos_sorted:
        map_items.append((0x0003, len(protos_sorted), proto_ids_off))
    if fields_sorted:
        map_items.append((0x0004, len(fields_sorted), field_ids_off))
    if methods_sorted:
        map_items.append((0x0005, len(methods_sorted), method_ids_off))
    if classes_sorted:
        map_items.append((0x0006, len(classes_sorted), class_defs_off))
    type_list_count = sum(1 for p in protos_sorted if p[1]) + sum(bool(c.get('interfaces')) for c in classes_sorted)
    if type_list_count:
        map_items.append((0x1001, type_list_count, min(v for v in type_list_offsets.values() if v)))
    if class_data_offsets:
        map_items.append((0x2000, len(class_data_offsets), min(class_data_offsets.values())))
    if code_offsets:
        map_items.append((0x2001, len(code_offsets), min(code_offsets.values())))
    map_items.append((0x2002, len(strings_sorted), min(string_offsets.values())))
    map_items.append((0x1000, 1, map_off))
    data.extend(struct.pack("<I", len(map_items)))
    for typ, size, off in sorted(map_items):
        data.extend(struct.pack("<HHII", typ, 0, size, off))

    file_size = data_off + len(data)
    header = bytearray(b"dex\n035\0" + b"\0" * 24)
    header.extend(struct.pack("<I", file_size))
    header.extend(struct.pack("<I", header_size))
    header.extend(struct.pack("<I", 0x12345678))
    header.extend(struct.pack("<II", 0, 0))
    header.extend(struct.pack("<I", map_off))
    header.extend(struct.pack("<II", len(strings_sorted), string_ids_off))
    header.extend(struct.pack("<II", len(types_sorted), type_ids_off))
    header.extend(struct.pack("<II", len(protos_sorted), proto_ids_off if protos_sorted else 0))
    header.extend(struct.pack("<II", len(fields_sorted), field_ids_off if fields_sorted else 0))
    header.extend(struct.pack("<II", len(methods_sorted), method_ids_off if methods_sorted else 0))
    header.extend(struct.pack("<II", len(classes_sorted), class_defs_off if classes_sorted else 0))
    header.extend(struct.pack("<II", len(data), data_off))
    ids = bytearray()
    for s in strings_sorted:
        ids.extend(struct.pack("<I", string_offsets[s]))
    for t in types_sorted:
        ids.extend(struct.pack("<I", string_idx[t]))
    for ret, params in protos_sorted:
        sh = shorty(ret) + "".join(shorty(p) for p in params)
        ids.extend(struct.pack("<III", string_idx[sh], type_idx[ret], type_list_offsets[(ret, params)]))
    for cls_desc, type_desc, name in fields_sorted:
        ids.extend(struct.pack("<HHI", type_idx[cls_desc], type_idx[type_desc], string_idx[name]))
    for cls_desc, ret, params, name in methods_sorted:
        ids.extend(struct.pack("<HHI", type_idx[cls_desc], proto_idx[(ret, params)], string_idx[name]))
    for cls in classes_sorted:
        source_idx = string_idx[cls["source"]] if cls.get("source") else 0xFFFFFFFF
        ids.extend(
            struct.pack(
                "<IIIIIIII",
                type_idx[cls["descriptor"]],
                cls.get("flags", ACC_PUBLIC | ACC_ABSTRACT),
                type_idx[cls.get("superclass", "Ljava/lang/Object;")],
                type_list_offsets.get(cls['descriptor'], 0),
                source_idx,
                0,
                class_data_offsets[cls["descriptor"]],
                0,
            )
        )
    blob = header + ids + data
    sig = hashlib.sha1(blob[32:]).digest()
    blob[12:32] = sig
    checksum = zlib.adler32(blob[12:]) & 0xFFFFFFFF
    blob[8:12] = struct.pack("<I", checksum)
    return bytes(blob)


def lib_classes(prefix: str, count: int = 6, extra_return: str = "I") -> list[dict]:
    out = []
    for i in range(count):
        params = ["I"] * ((i % 3) + 1)
        fields = [{"name": f"value{i}", "type": "I"}]
        if i % 2:
            fields.append({"name": f"object{i}", "type": "Ljava/lang/Object;"})
        out.append(
            {
                "descriptor": f"L{prefix}/Class{i};",
                "fields": fields,
                "methods": [
                    {"name": f"call{i}", "return": extra_return, "params": params},
                    {"name": f"make{i}", "return": "Ljava/lang/Object;", "params": []},
                ],
            }
        )
    return out


def make_apk(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def make_minimal_elf() -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\0" * 7
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        3,
        62,
        1,
        0,
        0,
        0,
        0,
        64,
        0,
        0,
        0,
        64,
        0,
    )
    return header


@pytest.fixture
def demo_db(tmp_path):
    db = tmp_path / "profiles.sqlite"
    ref_a = tmp_path / "libalpha.dex"
    ref_b = tmp_path / "libbeta.dex"
    ref_a.write_bytes(make_dex(lib_classes("lib/alpha", 6)))
    ref_b.write_bytes(make_dex(lib_classes("lib/beta", 6, "Ljava/lang/Object;")))
    build_profile(ref_a, purl="pkg:maven/example/libalpha@1.0.0", database=db)
    build_profile(ref_b, purl="pkg:maven/example/libbeta@2.0.0", database=db)
    return db

