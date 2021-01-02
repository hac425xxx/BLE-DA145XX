import struct
import re
import idaapi
import idc


def try_define_func(addr, name=""):

    if addr & 1:
        addr -= 1
        idaapi.split_sreg_range(addr, idaapi.str2reg("T"), 1, idaapi.SR_user)
    else:
        idaapi.split_sreg_range(addr, idaapi.str2reg("T"), 0, idaapi.SR_user)

    if idaapi.create_insn(addr):
        if idc.add_func(addr):
            if name != "":
                idaapi.set_name(addr, name, idaapi.SN_FORCE)

            print "add func 0x{:X} !".format(addr)
            return True

    return False


def is_func_ea(ea):
    func = idaapi.get_func(ea)
    if not func and not try_define_func(ea):
        return False
    return True


def search_msg_handler(msg_id):

    ret = []

    data = " ".join(re.findall(".{2}", struct.pack("I", msg_id).encode("hex")))
    addr = 0x07F00000
    find_addr = idc.find_binary(addr, SEARCH_DOWN, data)

    while find_addr != idaapi.BADADDR:
        find_addr = idc.find_binary(find_addr + 1, SEARCH_DOWN, data)

        if find_addr != idaapi.BADADDR:
            func_addr = idaapi.get_dword(find_addr + 4)
            if is_func_ea(func_addr):
                print "  msg_id 0x{:X} @ 0x{:X}, handler: 0x{:X}".format(msg_id, find_addr, func_addr)
                ret.append(func_addr)

            # custom_msg_handler
            func_addr = idaapi.get_dword(find_addr + 2)
            if is_func_ea(func_addr):
                print "  [custom_msg_handler] msg_id 0x{:X} @ 0x{:X}, handler: 0x{:X}".format(msg_id, find_addr, func_addr)
                ret.append(func_addr)
    return ret


def add_ref(frm, to):
    idaapi.add_dref(frm, to, idaapi.dr_R)
    idaapi.add_dref(to, frm, idaapi.dr_R)

def del_ref(frm, to):
    idaapi.del_dref(frm, to)
    idaapi.del_dref(to, frm)
    idaapi.del_cref(frm, to, 0)
    idaapi.del_cref(to, frm, 0)


usage = {}

with open("msg_id_usage.json", "r") as fp:
    import json
    usage = json.loads(fp.read())


for k, v in usage.items():
    print k
    frm_ea = idaapi.get_name_ea(idaapi.BADADDR, str(k))
    for msg_id in v:
        for handler in search_msg_handler(msg_id):

            if frm_ea & 1:
                frm_ea -= 1

            if handler & 1:
                handler -= 1

            add_ref(frm_ea, handler)
