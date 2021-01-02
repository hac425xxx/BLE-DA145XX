import struct
import re

d = 0x7F1F7A0
d = 0x7FC9C44

data = " ".join(re.findall(".{2}", struct.pack("I", d).encode("hex")))
print data

addr = 0x07F00000

find_addr = find_binary(addr, SEARCH_DOWN, data)

while find_addr != idaapi.BADADDR:
    find_addr = find_binary(find_addr + 1, SEARCH_DOWN, data)
    print "find 0x{:X}".format(find_addr)
    
