from zlib import adler32
from xml.dom.minidom import parseString as parse_xml

from log import log


class Range:
    def __init__(self, min, max):
        self.min = min
        self.max = max


class Section:
    def __init__(self, binary, offset, length):
        # TODO: better name
        self.binary = binary
        self.offset = offset
        self.length = length

    @property
    def range(self):
        return Range(self.offset, self.offset + self.length)

    @property
    def data(self):
        s = slice(self.range.min, self.range.max)
        r = self.binary[s]
        return r


class DictInfoLength(Section):
    @property
    def dict_info_length(self):
        return int.from_bytes(self.data, 'big')


class DictInfo(Section):
    @property
    def xml(self):
        s = self.data.decode('utf-16')
        # return parse_xml(raw).toprettyxml()
        return s

    @property
    def checksum(self):
        return adler32(self.data)


class DictInfoChecksum(Section):
    @property
    def checksum(self):
        return int.from_bytes(self.data, 'little')


class Header(Section):
    pass


class CountKeyBlock(Section):
    @property
    def count(self):
        return int.from_bytes(self.data, 'big')


class CountKeyword(Section):
    @property
    def count(self):
        return int.from_bytes(self.data, 'big')


def test(exp, msg = ''):
    if (not exp):
        log(f'!!!! test fail {msg}')


def test_section_data():
    text = '0123456789ABCDEF'
    s1 = Section(text, 0, 4)
    test(s1.data == '0123')

    s2 = Section(text, s1.range.max, 4)
    test(s2.data == '4567')

    s3 = Section(text, s2.range.max, 8)
    test(s3.data == '89ABCDEF')


def test_section_range():
    s1 = Section('12345', 42, 100)
    test(s1.range.min == 42)
    test(s1.range.max == 42 + 100)


def int_from_byte_be(b):
    return int.from_bytes(b, 'big')


def int_from_byte_le(b):
    return int.from_bytes(b, 'little')


def part(sequence, offset, length):
    return sequence[slice(offset, offset + length)]


def analyze_key_section(binary, offset):
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

    p = part(binary, offset, 40)
    assert adler32(p) == checksum

    return data


def main():
    test_section_range()
    test_section_data()

    with open('./mdict/coca.mdx', 'rb') as file:
        binary = file.read()

        log(f'Encrypted="2"')
        dl = DictInfoLength(binary, 0, 4)
        di = DictInfo(binary, dl.range.max, dl.dict_info_length)
        dc = DictInfoChecksum(binary, di.range.max, 4)
        assert di.checksum == dc.checksum

        data = analyze_key_section(binary, dc.range.max)

        log(f'data {data}')


if __name__ == '__main__':
    main()