require 'zlib'


def main()
  File.open('./mdict/coca.mdx', 'rb') do |file|
    info_size = file.read(4).unpack('L>').first
    dict_info = file.read(info_size)
    checksum = file.read(4).unpack('L<').first
    puts dict_info
    p checksum
    p Zlib.adler32(dict_info)

  end
end

main()