def uint_from_byte_be(b):
    return int.from_bytes(b, 'big')


def uint_from_byte_le(b):
    return int.from_bytes(b, 'little')


def part(sequence, offset, length):
    return sequence[slice(offset, offset + length)]


def part_till0(sequence, offset):
    i = offset
    while sequence[i] != 0:
        i += 1
    return sequence[slice(offset, i + 1)]


def uint_be(*args, **kwargs):
    p = part(*args, **kwargs)
    return uint_from_byte_be(p)


def uint_le(*args, **kwargs):
    p = part(*args, **kwargs)
    return uint_from_byte_le(p)

