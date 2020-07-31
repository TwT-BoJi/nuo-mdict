import zlib

from log import log
from util import (
    part,
    part_till0,
    uint_be,
    uint_le,
    _mdx_decrypt,
)
from model import (
    KeywordIndexMate,
    KeywordSectionMate,
    RecordSectionMate,
)


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

    checksum = uint_be(block, 4, 4)
    assert checksum == zlib.adler32(uncompressed)

    return uncompressed


def analyze_section_header(binary, offset):
    len_xml = uint_be(binary, offset, 4)

    offset += 4

    xml_b = part(binary, offset, len_xml)
    # xml_s = xml_b.decode('utf-16le')

    offset += len_xml

    checksum = uint_le(binary, offset, 4)
    assert zlib.adler32(xml_b) == checksum

    offset += 4

    return offset


def analyze_keyword_index_mate(binary, offset, context):
    def keyword_block_mate(block, offset):
        len_null = 1

        num_keyword = uint_be(block, offset + 0, 8)

        offset += 8

        len_head = uint_be(block, offset + 0, 2)
        head_keyword = part(block, offset + 2, len_head)

        offset += 2 + len_head + len_null

        len_tail = uint_be(block, offset + 0, 2)
        tail_keyword = part(block, offset + 2, len_tail)

        offset += 2 + len_tail + len_null

        len_comp = uint_be(block, offset + 0, 8)
        len_unco = uint_be(block, offset + 8, 8)

        offset += 8 + 8

        mate = KeywordIndexMate(
            num_keyword = num_keyword,
            len_comp = len_comp,
            len_unco = len_unco,
            head_keyword = head_keyword,
            tail_keyword = tail_keyword,
        )

        return (mate, offset)


    ''' TODO:
        If the parameter Encrypted in the header has its second-lowest bit set (i.e. Encrypted | 2 is nonzero),
        then the keyword index is further encrypted.
    '''
    b = part(binary, offset, context.len_index_mate_comp)
    block = uncompressed_block(b, encrypted=True)

    assert len(block) == context.len_index_mate_unco

    mates = []
    index = 0
    count = 0
    while count < context.num_index:
        m, i = keyword_block_mate(block, index)
        mates.append(m)
        index = i
        count = count + 1

    return mates


def analyze_keyword_indexs(binary, offset, mate):
    def analyze_index(block, mate):
        pairs = []
        point = 0
        for _ in range(mate.num_keyword):
            position = uint_be(block, point, 8)
            keyword0 = part_till0(block, point + 8)
            keyword = keyword0[slice(0, -1)]
            pairs.append([keyword, position])
            point += 8 + len(keyword0)
        return pairs

    pairs = []
    point = offset
    for i in range(mate.num_index):
        data = mate.indexs_mate[i]

        b = part(binary, point, data.len_comp)
        block = uncompressed_block(b, encrypted=False)
        pairs += analyze_index(block, data)

        point += data.len_comp

    d = dict(pairs)
    assert len(d) == len(pairs), 'has duplicate keywords'
    assert len(d) == mate.num_keyword
    return d


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
    for name, i, length in array:
        d[name] = uint_be(binary, offset + i, length)
    mate = KeywordSectionMate(**d)

    checksum = uint_be(binary, offset + 40, 4)

    p = part(binary, offset + 0, 40)
    assert zlib.adler32(p) == checksum

    m = analyze_keyword_index_mate(binary, offset + 44, mate)
    mate.indexs_mate = m

    offset += mate.len_index_mate_comp + 44
    analyze_keyword_indexs(binary, offset, mate)

    offset += mate.len_indexs

    return [mate, offset]


def analyze_record_indexs(binary, offset, mate):
    record = b''
    for i in range(mate.num_index):
        s = mate.lens_index_comp[i]
        p = part(binary, offset, s)
        b = uncompressed_block(p, encrypted=False)
        assert len(b) == mate.lens_index_unco[i]
        record += b
        offset += s

    return record


def analyze_section_record(binary, offset, mate_keyword):
    array = [
        ['num_index', 0, 8],
        ['num_record', 8, 8],
        ['len_compunco', 16, 8],
        ['len_indexs', 24, 8],
    ]
    d = {}
    for name, i, length in array:
        d[name] = uint_be(binary, offset + i, length)
    mate_record = RecordSectionMate(**d)

    assert mate_keyword.num_keyword == mate_record.num_record

    offset += 32
    point = offset
    for _ in range(mate_record.num_index):
        len_comp = uint_be(binary, point + 0, 8)
        len_unco = uint_be(binary, point + 8, 8)
        mate_record.lens_index_comp.append(len_comp)
        mate_record.lens_index_unco.append(len_unco)
        point += 16

    assert (point - offset) == mate_record.len_compunco

    offset = point

    analyze_record_indexs(binary, offset, mate_record)


def main():
    with open('./mdict/coca.mdx', 'rb') as file:
        binary = file.read()

        i = analyze_section_header(binary, 0)
        mate, i = analyze_section_keyword(binary, i)
        analyze_section_record(binary, i, mate)


if __name__ == '__main__':
    main()
