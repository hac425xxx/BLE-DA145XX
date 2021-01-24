import idaapi
import idc
import ida_expr
# idc.get_func_name("ke_task_create")


def define_func(addr, name=""):
    
    if addr & 1:
        addr -= 1
        idaapi.split_sreg_range(addr, idaapi.str2reg("T"), 1, idaapi.SR_user)
    else:
        idaapi.split_sreg_range(addr, idaapi.str2reg("T"), 0, idaapi.SR_user)
    
    if idaapi.create_insn(addr):
        idc.add_func(addr)
        if name != "":
            idaapi.set_name(addr, name,idaapi.SN_FORCE)

def define_ke_state_handler(ea):
    # undefined addr and define struct
    sid = idaapi.get_struc_id("ke_state_handler")
    struct_size = idaapi.get_struc_size(sid)
    idaapi.del_items(ea, struct_size, idaapi.DELIT_DELNAMES)
    idaapi.create_struct(ea, struct_size, sid)
    
    
    msg_table = idaapi.get_dword(ea)
    msg_cnt = idaapi.get_word(ea + 4)
    
    print "msg_table: 0x{:X}, msg_cnt: {}".format(msg_table, msg_cnt)
    
    sid = idaapi.get_struc_id("ke_msg_handler")
    struct_size = idaapi.get_struc_size(sid)
    idaapi.del_items(msg_table, struct_size, idaapi.DELIT_DELNAMES)
    idaapi.create_struct(msg_table, struct_size, sid)
    
    idc.make_array(msg_table, msg_cnt)
    
    
    for i in range(msg_cnt):
        define_func(idaapi.get_dword(msg_table + 4 + i * 8))
    
    
    
def define_ke_task_desc(ea, task_desc_name):

    print "{}: 0x{:X}".format(task_desc_name, ea)

    sid = idaapi.get_struc_id("ke_task_desc")
    struct_size = idaapi.get_struc_size(sid)
    
    # undefined addr and define struct
    idaapi.del_items(ea, struct_size, idaapi.DELIT_DELNAMES)
    idaapi.create_struct(ea, struct_size, sid)
    idaapi.set_name(ea, task_desc_name, idaapi.SN_FORCE)
    

def main():
    ke_task_create_addr = idaapi.get_name_ea(idaapi.BADADDR, "ke_task_create")

    print "ke_task_create_addr: 0x{:X}".format(ke_task_create_addr)


    for xref in XrefsTo(ke_task_create_addr, 0):
        frm_func = idc.get_func_name(xref.frm)

        
        print "frm:0x{:X}, frm_func:{}".format(xref.frm, frm_func)
        # print "  task_desc: 0x{:X}".format(idaapi.get_arg_addrs(xref.frm)[1])
        
        task_desc = idc.print_operand(idaapi.get_arg_addrs(xref.frm)[1], 1)
        task_desc_ea = idaapi.get_name_ea(idaapi.BADADDR, task_desc[1:])
        task_desc_name = "{}_task_desc".format(frm_func.split("_init")[0])

        
        define_ke_task_desc(task_desc_ea, task_desc_name)

        
        print idaapi.get_name(idaapi.get_dword(task_desc_ea + 4))
        
        
        handler = idaapi.get_dword(task_desc_ea + 4)
        define_ke_state_handler(handler)

def extract_ke_task_create(line):
    args = re.findall("ke_task_create\((.*)\)", line)
    if len(args) == 0:
        return ""

    arg = args[0].split(",")[1]
    print arg
    return arg.strip()


def test():
    from get_argument import CodeEmulator, CustomLogger,ArgumentTracker


    logger = CustomLogger()
    m = CodeEmulator()
    at = ArgumentTracker()

    ke_task_create_addr = idaapi.get_name_ea(idaapi.BADADDR, "ke_task_create")
    print "ke_task_create_addr: 0x{:X}".format(ke_task_create_addr)
    for xref in XrefsTo(ke_task_create_addr, 0):
        frm_func = idc.get_func_name(xref.frm)
        ret = at.track_register(xref.frm, "r1")
        if ret.has_key("target_ea"):
            print "target_ea: 0x{:X}".format(ret['target_ea'])
            if m.emulate(ret['target_ea'], xref.frm):
                reg = m.mu.reg_read(UC_ARM_REG_R1)
                logger.log("addr: 0x{:X}, task_struct: 0x{:X}".format(xref.frm, reg))


        print at.decompile_tracer(xref.frm, extract_ke_task_create)

if __name__ == "__main__":
    test()

    
    
    
    
    
    
    
    
    

    
    
    
    
    
    
    
    
    