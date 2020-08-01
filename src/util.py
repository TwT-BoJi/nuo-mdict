from struct import (
    pack,
    unpack,
)
from ripemd128 import ripemd128


def uint_from_byte_be(b):
    return int.from_bytes(b, 'big')


def uint_from_byte_le(b):
    return int.from_bytes(b, 'little')


def part(sequence, offset, length):
    return sequence[slice(offset, offset + length)]


def part_0(sequence, offset):
    i = offset
    while sequence[i] != 0:
        i += 1
    return sequence[slice(offset, i + 1)]


def part_rn0(sequence, offset):
    i = offset
    while part(sequence, i, 3) != b'\r\n\x00':
        i += 3
    return sequence[slice(offset, i + 3)]


def uint_be(*args, **kwargs):
    p = part(*args, **kwargs)
    return uint_from_byte_be(p)


def uint_le(*args, **kwargs):
    p = part(*args, **kwargs)
    return uint_from_byte_le(p)


def _fast_decrypt(data, key):
    b = bytearray(data)
    k = bytearray(key)
    p = 0x36

    for i in range(len(b)):
        t = (b[i] >> 4 | b[i] << 4) & 0xff
        t = t ^ p ^ (i & 0xff) ^ k[i % len(k)]
        p = b[i]
        b[i] = t

    return bytes(b)


# TODO: rename
def _mdx_decrypt(comp_block):
    key = ripemd128(comp_block[4:8] + pack(b'<L', 0x3695))
    return comp_block[0:8] + _fast_decrypt(comp_block[8:], key)

