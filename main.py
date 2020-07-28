import zlib
from struct import (
    pack,
    unpack,
)

from ripemd128 import ripemd128
from log import log
from model import (
    KeywordIndexMate,
    KeywordSectionMate,
)


def test(exp, msg = ''):
    if (not exp):
        log(f'!!!! test fail {msg}')


def uint_from_byte_be(b):
    return int.from_bytes(b, 'big')


def uint_from_byte_le(b):
    return int.from_bytes(b, 'little')


def part(sequence, offset, length):
    return sequence[slice(offset, offset + length)]


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


def uncompressed_block(block, encrypted):
    if encrypted:
        block = _mdx_decrypt(block)

    def uncompressed_none(data):
        return data

    def uncompressed_lzo(data):
        raise Exception('compress not support')

    def uncompressed_zlib(data):
        return zlib.decompress(data)

    compress_type = part(block, 0, 4)
    func_map = dict([
        (b'\x00\x00\x00\x00', uncompressed_none),
        (b'\x01\x00\x00\x00', uncompressed_lzo),
        (b'\x02\x00\x00\x00', uncompressed_zlib),
    ])

    compressed = part(block, 8, len(block) - 8)
    uncompressed = func_map[compress_type](compressed)

    b = part(block, 4, 4)
    checksum = uint_from_byte_be(b)

    assert checksum == zlib.adler32(uncompressed)

    return uncompressed


def analyze_section_header(binary, offset):
    t = part(binary, offset + 0, 4)
    len_xml = uint_from_byte_be(t)

    xml_b = part(binary, offset + 4, len_xml)
    xml_s = xml_b.decode('utf-16le')

    t = part(binary, offset + 4 + len_xml, 4)
    checksum = uint_from_byte_le(t)

    assert zlib.adler32(xml_b) == checksum

    size = 4 + len_xml + 4
    data = {
        'xml': xml_s,
        'end': offset + size,
    }
    return data


def analyze_keyword_index_mate(binary, offset, context):
    ''' TODO:
        If the parameter Encrypted in the header has its second-lowest bit set (i.e. Encrypted | 2 is nonzero),
        then the keyword index is further encrypted.
    '''
    b = part(binary, offset + 0, context.len_index_mate_comp)
    block = uncompressed_block(b, encrypted = True)

    assert len(block) == context.len_index_mate_unco

    def keyword_block_mate(block, offset):
        len_null = 1

        b = part(block, offset + 0, 8)
        num_keyword = uint_from_byte_be(b)

        offset += 8

        b = part(block, offset + 0, 2)
        len_head = uint_from_byte_be(b)

        b = part(block, offset + 2, len_head)
        head_keyword = b

        offset += 2 + len_head + len_null

        b = part(block, offset + 0, 2)
        len_tail = uint_from_byte_be(b)

        b = part(block, offset + 2, len_tail)
        tail_keyword = b

        offset += 2 + len_tail + len_null

        b = part(block, offset + 0, 8)
        len_comp = uint_from_byte_be(b)

        b = part(block, offset + 8, 8)
        len_unco = uint_from_byte_be(b)

        offset += 8 + 8

        mate = KeywordIndexMate(
            num_keyword = num_keyword,
            len_comp = len_comp,
            len_unco = len_unco,
            head_keyword = head_keyword,
            tail_keyword = tail_keyword,
        )

        return (mate, offset)

    mates = []
    index = 0
    count = 0
    while count < context.num_index:
        m, i = keyword_block_mate(block, index)
        mates.append(m)
        index = i
        count = count + 1

    return mates


def analyze_keyword_index(binary, offset, context):
    pass


def analyze_section_keyword(binary, offset):
    ''' TODO:
        If the parameter Encrypted in the header has the lowest bit set (i.e. Encrypted | 1 is nonzero),
        then the 40-byte block from num_blocks are encrypted
    '''
    array = [
        ['num_index', 0, 8],
        ['num_keyword', 8, 8],
        ['len_index_mate_unco', 16, 8],
        ['len_index_mate_comp', 24, 8],
        ['len_indexs', 32, 8],
    ]

    d = {}
    for name, index, length in array:
        b = part(binary, offset + index, length)
        i = uint_from_byte_be(b)
        d[name] = i
    mate = KeywordSectionMate(**d)

    b = part(binary, offset + 40, 4)
    checksum = uint_from_byte_be(b)

    p = part(binary, offset + 0, 40)
    assert zlib.adler32(p) == checksum

    m = analyze_keyword_index_mate(binary, offset + 44, mate)
    mate.index_mate = m

    analyze_keyword_index(binary, offset + mate.len_index_mate_comp, mate)

    return mate


def main():
    with open('./mdict/coca.mdx', 'rb') as file:
        binary = file.read()

        sh = analyze_section_header(binary, 0)
        sk = analyze_section_keyword(binary, sh['end'] )


if __name__ == '__main__':
    main()