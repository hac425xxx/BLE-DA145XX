import idaapi
import idc


fpath = "da14531_symbols.txt"


def define_func(addr, name):
    
    if addr & 1:
        addr -= 1
        idaapi.split_sreg_range(addr, idaapi.str2reg("T"), 1, idaapi.SR_user)
    else:
        idaapi.split_sreg_range(addr, idaapi.str2reg("T"), 0, idaapi.SR_user)
    
    if idaapi.create_insn(addr):
        idc.add_func(addr)
        idaapi.set_name(addr, name,idaapi.SN_FORCE)
        

def define_data(addr, name):
    idaapi.set_name(addr, name,idaapi.SN_FORCE)


with open(fpath, "r") as fp:
    for l in fp:
        try:
            print l
            
            addr, type, name = l.strip().split(" ")
            
            if addr.startswith(";"):
                #addr = addr[1:]
                continue
            
            addr = int(addr, 16)
            
            if type == "T":
                define_func(addr, name)
            else:
                define_data(addr, name)
            #break
        except:
            pass