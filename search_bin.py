import struct
import re

d = 0x7F1F7A0
d = 0x7FC9C44
d = 0x07FC2AA2


def search_bin(addr, d):
    data = " ".join(re.findall(".{2}", struct.pack("I", d).encode("hex")))
    print data

    find_addr = find_binary(addr, SEARCH_DOWN, data)

    while find_addr != idaapi.BADADDR:
        print "find 0x{:X}".format(find_addr)
        find_addr = find_binary(find_addr + 1, SEARCH_DOWN, data)


if __name__ == "__main__":
    data = 0x07FC2AA2
    start_ea = 0x07F00000
    search_bin(start_ea, data)
    search_bin(start_ea, data + 1)
