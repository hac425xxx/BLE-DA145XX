import idc
import idaapi

# idc.get_func_name("ke_task_create")


def define_func(addr, name=""):
    
    if addr & 1:
        addr -= 1
        idaapi.split_sreg_range(addr, idaapi.str2reg("T"), 1, idaapi.SR_user)
    else:
        idaapi.split_sreg_range(addr, idaapi.str2reg("T"), 0, idaapi.SR_user)
    
    if idaapi.create_insn(addr):
        if idc.add_func(addr):
            if name != "":
                idaapi.set_name(addr, name,idaapi.SN_FORCE)
        return True
    
    return False

ea = here()
i = 0

while True:
    func_ea = idaapi.get_dword(ea + 4 + i * 8)
    
    

    if not define_func(func_ea):
        break
    
    idaapi.add_dref(ea, func_ea, idaapi.dr_R)
    
    i += 1

print i











