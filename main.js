const fs = require('fs').promises
const assert = require('assert').strict
const Adler32 = require('adler-32')


const kind = x => Object.prototype.toString.call(x)

const parseHead = (bytes) => {
    const infoSize = bytes.readUIntBE(0, 4)
    const dictInfo = Buffer.from(bytes.buffer, 4, infoSize)
    const checksum = bytes.readUIntLE(4 + infoSize, 4)

    assert.ok(Adler32.buf(dictInfo) === checksum)
    fs.writeFile('./dict-info.xml', dictInfo, 'utf16le')

    return infoSize + 8
}

const main = async () => {
    const bytes = await fs.readFile('./mdict/coca.mdx')

    parseHead(bytes)
}

main()