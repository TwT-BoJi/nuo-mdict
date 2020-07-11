from zlib import adler32
from xml.dom.minidom import parseString as parse_xml

from log import log


def test(exp, msg = ''):
    if (not exp):
        log(f'!!!! test fail {msg}')


def int_from_byte_be(b):
    return int.from_bytes(b, 'big')


def int_from_byte_le(b):
    return int.from_bytes(b, 'little')


def part(sequence, offset, length):
    return sequence[slice(offset, offset + length)]


def analyze_section_header(binary, offset):
    t = part(binary, offset + 0, 4)
    len_xml = int_from_byte_be(t)

    xml_b = part(binary, offset + 4, len_xml)
    xml_s = xml_b.decode('utf-16le')

    t = part(binary, offset + 4 + len_xml, 4)
    checksum = int_from_byte_le(t)

    assert adler32(xml_b) == checksum

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
        i = int_from_byte_be(b)
        data[name] = i

    b = part(binary, offset + 40, 4)
    checksum = int_from_byte_be(b)

    p = part(binary, offset + 0, 40)
    assert adler32(p) == checksum

    return data


def main():
    with open('./mdict/coca.mdx', 'rb') as file:
        binary = file.read()

        sh = analyze_section_header(binary, 0)
        log(f'sh { sh }')
        sk = analyze_section_keyword(binary, sh['end'] )
        log(f'sk { sk }')


if __name__ == '__main__':
    main()