"""Instruction-boundary traversal for standard DEX explicit invocations.

Only declared references are returned. All supported instruction widths are
accounted for, including switch/array payloads. Invalid widths/targets stop the
method and retain preceding observations with a diagnostic.
"""
from __future__ import annotations

import struct

WIDTHS = {}
for start, end, width in [(0x00,0x01,1),(0x02,0x02,2),(0x03,0x03,3),
                         (0x04,0x04,1),(0x05,0x05,2),(0x06,0x06,3),
                         (0x07,0x07,1),(0x08,0x08,2),(0x09,0x09,3),
                         (0x0a,0x12,1),(0x13,0x13,2),(0x14,0x14,3),
                         (0x15,0x16,2),(0x17,0x17,3),(0x18,0x18,5),
                         (0x19,0x1a,2),(0x1b,0x1b,3),(0x1c,0x1c,2),
                         (0x1d,0x1e,1),(0x1f,0x20,2),(0x21,0x21,1),
                         (0x22,0x23,2),(0x24,0x26,3),(0x27,0x28,1),
                         (0x29,0x29,2),(0x2a,0x2c,3),(0x2d,0x3d,2),
                         (0x44,0x6d,2),(0x6e,0x72,3),(0x74,0x78,3),
                         (0x7b,0x8f,1),(0x90,0xaf,2),(0xb0,0xcf,1),
                         (0xd0,0xe2,2),(0xfa,0xfb,4),(0xfc,0xfd,3),(0xfe,0xff,2)]:
    WIDTHS.update({op: width for op in range(start, end + 1)})
INVOKES = dict(zip(range(0x6e,0x73), ('virtual','super','direct','static','interface')))
INVOKES.update({op+6: kind+'/range' for op,kind in list(INVOKES.items())})


def decode_invocations(code: bytes, *, method_count: int, dex_version: int = 35):
    calls, issues = [], []
    units = len(code) // 2
    def u16(i):
        if i >= units:
            raise ValueError('Truncated instruction or payload')
        return struct.unpack_from('<H', code, i * 2)[0]
    pc = 0
    if len(code) % 2:
        return [], ['Odd byte length in instruction stream']
    try:
        while pc < units:
            first = u16(pc)
            op = first & 255
            width = WIDTHS.get(op)
            if width is None:
                raise ValueError(f'Unsupported opcode 0x{op:02x} at code unit {pc}')
            if op >= 0xfa and dex_version < (39 if op >= 0xfe else 38):
                raise ValueError('Opcode is unsupported for this DEX version')
            if op == 0 and first:
                if pc % 2:
                    raise ValueError('Misaligned instruction payload')
                count = u16(pc + 1)
                if first == 0x0100:
                    width = 4 + 2 * count
                elif first == 0x0200:
                    width = 2 + 4 * count
                elif first == 0x0300:
                    size = u16(pc + 2) | (u16(pc + 3) << 16)
                    if count not in (1,2,4,8):
                        raise ValueError('Invalid array payload element width')
                    width = 4 + (count * size + 1) // 2
                else:
                    raise ValueError('Unknown instruction payload')
            if pc + width > units:
                raise ValueError(f'Truncated instruction/payload at code unit {pc}')
            if op in INVOKES:
                if op <= 0x72 and first >> 12 > 5:
                    raise ValueError('Invalid invoke register count')
                index = u16(pc + 1)
                if index >= method_count:
                    raise ValueError('Invocation method index out of bounds')
                calls.append((pc * 2, INVOKES[op], index))
            elif op in (0xfa,0xfb,0xfc,0xfd):
                issues.append(f'Special invocation at code unit {pc}; dynamic target resolution unsupported')
            pc += width
    except ValueError as exc:
        issues.append(str(exc))
    return calls, issues
