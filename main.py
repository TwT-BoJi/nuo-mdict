import zlib
from struct import pack, unpack

from ripemd128 import ripemd128
from log import log


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
    key = bytearray(key)
    previous = 0x36
    for i in range(len(b)):
        t = (b[i] >> 4 | b[i] << 4) & 0xff
        t = t ^ previous ^ (i & 0xff) ^ key[i % len(key)]
        previous = b[i]
        b[i] = t
    return bytes(b)


# TODO: rename
def _mdx_decrypt(comp_block):
    key = ripemd128(comp_block[4:8] + pack(b'<L', 0x3695))
    return comp_block[0:8] + _fast_decrypt(comp_block[8:], key)


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


def analyze_section_keyword(binary, offset):
    array = [
        ['num_block', 0, 8],
        ['num_entry', 8, 8],
        ['len_index_deco', 16, 8],
        ['len_index_comp', 24, 8],
        ['len_block', 32, 8],
    ]

    data = {}
    for name, index, length in array:
        b = part(binary, offset + index, length)
        i = uint_from_byte_be(b)
        data[name] = i

    b = part(binary, offset + 40, 4)
    checksum = uint_from_byte_be(b)

    p = part(binary, offset + 0, 40)
    assert zlib.adler32(p) == checksum

    analyze_keyword_index(binary, offset + 44, data)

    return data


# TODO: rename `keyword_block_info` `keyword_block_mate` `block_mate`
def analyze_keyword_index(binary, offset, meta):
    p = part(binary, offset + 0, meta['len_index_comp'])
    # TODO: if verions > 2
    block_decrypted = _mdx_decrypt(p)

    def uncompressed_none(data):
        return data

    def uncompressed_lzo(data):
        raise Exception('compress not support')

    def uncompressed_zlib(data):
        return zlib.decompress(data)

    compress_type = part(block_decrypted, 0, 4)
    d = dict([
        (b'\x00\x00\x00\x00', uncompressed_none),
        (b'\x01\x00\x00\x00', uncompressed_lzo),
        (b'\x02\x00\x00\x00', uncompressed_zlib),
    ])
    compressed = part(block_decrypted, 8, meta['len_index_comp'] - 8)
    uncompressed = d[compress_type](compressed)

    b = part(block_decrypted, 4, 4)
    checksum = uint_from_byte_be(b)

    log(f'decompressed { uncompressed }')


def _analyze_keyword_index(binary, offset, context):
    t = part(binary, offset + 0, 4)
    num_block0 = uint_from_byte_le(t)
    log(f'num_block0: {num_block0}')

    t = part(binary, offset + 4, 2)
    len_keyword0 = uint_from_byte_le(t)
    log(f'len_keyword0: {len_keyword0}')

    c = part(binary, offset + 0, 100)
    log(f'baoli {c}')

    pass


def main():
    with open('./mdict/coca.mdx', 'rb') as file:
        binary = file.read()

        sh = analyze_section_header(binary, 0)
        sk = analyze_section_keyword(binary, sh['end'] )


if __name__ == '__main__':
    main()