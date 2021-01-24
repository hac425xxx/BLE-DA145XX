import struct
import re

def search_dword(addr, d):
    data = " ".join(re.findall(".{2}", struct.pack("I", d).encode("hex")))
    print data

    find_addr = find_binary(addr, SEARCH_DOWN, data)

    while find_addr != idaapi.BADADDR:
        print "find 0x{:X} on 0x{:X}".format(d, find_addr)
        find_addr = find_binary(find_addr + 1, SEARCH_DOWN, data)


if __name__ == "__main__":
    data = 0x07FC2AA2
    start_ea = 0x07F00000
    search_dword(start_ea, data)
    search_dword(start_ea, data + 1)
