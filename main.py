from log import log
from zlib import adler32


class Range:
    def __init__(self, min, max):
        self.min = min
        self.max = max


class Section:
    def __init__(self, binary, offset, length):
        self.binary = binary
        self.offset = offset
        self.length = length

    @property
    def range(self):
        return Range(self.offset, self.offset + self.length)

    @property
    def bytes(self):
        s = slice(self.range.min, self.range.max)
        b = self.binary[s]
        return b


class DictInfoLength(Section):
    @property
    def dict_info_length(self):
        return int.from_bytes(self.bytes, 'big')


class DictInfo(Section):
    @property
    def xml(self):
        return self.bytes.decode('utf-8')

    @property
    def checksum(self):
        return adler32(self.bytes)


class DictInfoChecksum(Section):
    @property
    def checksum(self):
        return int.from_bytes(self.bytes, 'little')


def main():
    with open('./mdict/coca.mdx', 'rb') as file:
        binary = file.read()

        dl = DictInfoLength(binary, 0, 4)
        di = DictInfo(binary, dl.range.max, dl.dict_info_length)
        dc = DictInfoChecksum(binary, di.range.max, 4)

        log(f'di checksum {di.checksum}')
        log(f'hc checksum {dc.checksum}')


if __name__ == '__main__':
    main()