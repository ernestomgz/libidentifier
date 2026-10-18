"""Bounded standard DEX tables supplementing LIEF's missing descriptor/interfaces API.

This reader never executes code. Offsets are absolute bytes; instructions are
retained as bytes and decoded separately. Unsupported container versions fail.
"""
from __future__ import annotations

import struct


class DexTables:
    def __init__(self, data: bytes):
        self.data = data
        self.require(0, 0x70)
        if data[:8] not in {b'dex\n035\0', b'dex\n037\0', b'dex\n038\0', b'dex\n039\0', b'dex\n040\0'}:
            raise ValueError('Unsupported standard DEX version')
        if self.u32(0x28) != 0x12345678 or self.u32(0x24) != 0x70:
            raise ValueError('Unsupported DEX header/endian format')
        if self.u32(0x20) != len(data):
            raise ValueError('DEX file size disagrees with available data')
        self.strings = [self.string(self.u32(p)) for p in self.table(0x38, 4)]
        self.types = [self.at(self.strings, self.u32(p)) for p in self.table(0x40, 4)]
        self.protos = [(self.at(self.types, self.u32(p + 4)), self.type_list(self.u32(p + 8)))
                       for p in self.table(0x48, 12)]
        self.fields = [(self.at(self.types, self.u16(p)), self.at(self.types, self.u16(p + 2)),
                        self.at(self.strings, self.u32(p + 4))) for p in self.table(0x50, 8)]
        self.methods = [(self.at(self.types, self.u16(p)), self.at(self.strings, self.u32(p + 4)),
                         self.at(self.protos, self.u16(p + 2))) for p in self.table(0x58, 8)]
        self.classes = {}
        self.code = {}
        self.defined_fields = set()
        self.defined_methods = set()
        for p in self.table(0x60, 32):
            desc = self.at(self.types, self.u32(p))
            if desc in self.classes:
                raise ValueError('Duplicate DEX class definition')
            parent = self.u32(p + 8)
            self.classes[desc] = (None if parent == 0xffffffff else self.at(self.types, parent),
                                  self.type_list(self.u32(p + 12)))
            offset = self.u32(p + 24)
            if offset:
                self.class_data(offset, desc)

    def require(self, offset, size):
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError('DEX table/data out of bounds')

    def u16(self, offset):
        self.require(offset, 2)
        return struct.unpack_from('<H', self.data, offset)[0]

    def u32(self, offset):
        self.require(offset, 4)
        return struct.unpack_from('<I', self.data, offset)[0]

    @staticmethod
    def at(values, index):
        if index < 0 or index >= len(values):
            raise ValueError('DEX reference index out of bounds')
        return values[index]

    def table(self, header, width):
        size, offset = self.u32(header), self.u32(header + 4)
        if size and not offset:
            raise ValueError('DEX table offset missing')
        self.require(offset, size * width)
        return range(offset, offset + size * width, width)

    def uleb(self, offset):
        value = 0
        for shift in range(0, 35, 7):
            self.require(offset, 1)
            byte = self.data[offset]
            offset += 1
            if shift == 28 and byte > 15:
                raise ValueError('DEX ULEB128 overflow')
            value |= (byte & 127) << shift
            if not byte & 128:
                return value, offset
        raise ValueError('DEX ULEB128 overflow')

    def string(self, offset):
        length, pos = self.uleb(offset)
        end = self.data.find(b'\0', pos)
        if end < 0:
            raise ValueError('Unterminated DEX string')
        # DEX MUTF-8 encodes NUL and UTF-16 surrogate pairs specially.
        raw = self.data[pos:end].replace(b'\xc0\x80', b'\0')
        value = raw.decode('utf-8', errors='surrogatepass')
        utf16 = value.encode('utf-16-le', errors='surrogatepass')
        if len(utf16) // 2 != length:
            raise ValueError('DEX string UTF-16 length mismatch')
        return utf16.decode('utf-16-le')

    def type_list(self, offset):
        if not offset:
            return ()
        size = self.u32(offset)
        self.require(offset + 4, size * 2)
        return tuple(self.at(self.types, self.u16(offset + 4 + 2 * i)) for i in range(size))

    def class_data(self, pos, owner):
        counts = []
        for _ in range(4):
            count, pos = self.uleb(pos)
            counts.append(count)
        for count in counts[:2]:
            index = 0
            for _ in range(count):
                delta, pos = self.uleb(pos)
                flags, pos = self.uleb(pos)
                index += delta
                if self.at(self.fields, index)[0] != owner:
                    raise ValueError('DEX field definition owner mismatch')
                if index in self.defined_fields:
                    raise ValueError('Duplicate DEX field definition')
                self.defined_fields.add(index)
        for count in counts[2:]:
            index = 0
            for _ in range(count):
                delta, pos = self.uleb(pos)
                flags, pos = self.uleb(pos)
                offset, pos = self.uleb(pos)
                index += delta
                if self.at(self.methods, index)[0] != owner:
                    raise ValueError('DEX method definition owner mismatch')
                if index in self.defined_methods:
                    raise ValueError('Duplicate DEX method definition')
                self.defined_methods.add(index)
                if offset:
                    size = self.u32(offset + 12)
                    self.require(offset, 16 + size * 2)
                    self.code[index] = (offset + 16, self.data[offset + 16:offset + 16 + size * 2])

    def method_descriptor(self, index):
        owner, name, (ret, params) = self.at(self.methods, index)
        return owner + '->' + name + '(' + ''.join(params) + ')' + ret
