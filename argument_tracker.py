import idaapi
import idc
from unicorn import *
from unicorn.arm_const import *
import re
import ida_expr

def get_block_by_ea(tgtEA):
    f = idaapi.get_func(tgtEA)
    fc = idaapi.FlowChart(f)

    for block in fc:
        if block.start_ea <= tgtEA:
            if block.end_ea > tgtEA:
                return block.start_ea
    return 0


def map_line2citem(decompilation_text):
    """
    Map decompilation line numbers to citems.
    This function allows us to build a relationship between citems in the
    ctree and specific lines in the hexrays decompilation text.
    Output:
        +- line2citem:
        |    a map keyed with line numbers, holding sets of citem indexes
        |
        |      eg: { int(line_number): sets(citem_indexes), ... }
        '
    """
    line2citem = {}

    #
    # it turns out that citem indexes are actually stored inline with the
    # decompilation text output, hidden behind COLOR_ADDR tokens.
    #
    # here we pass each line of raw decompilation text to our crappy lexer,
    # extracting any COLOR_ADDR tokens as citem indexes
    #

    for line_number in xrange(decompilation_text.size()):
        line_text = decompilation_text[line_number].line
        line2citem[line_number] = lex_citem_indexes(line_text)
        # print "line: {}, text: {}".format(line_number, line_text)

    return line2citem


def map_line2node(cfunc, line2citem):
    """
    Map decompilation line numbers to node (basic blocks) addresses.
    This function allows us to build a relationship between graph nodes
    (basic blocks) and specific lines in the hexrays decompilation text.
    Output:
        +- line2node:
        |    a map keyed with line numbers, holding sets of node addresses
        |
        |      eg: { int(line_number): set(nodes), ... }
        '
    """
    line2node = {}
    treeitems = cfunc.treeitems
    function_address = cfunc.entry_ea

    #
    # prior to this function, a line2citem map was built to tell us which
    # citems reside on any given line of text in the decompilation output.
    #
    # now, we walk through this line2citem map one 'line_number' at a time in
    # an effort to resolve the set of graph nodes associated with its citems.
    #

    for line_number, citem_indexes in line2citem.iteritems():
        nodes = set()

        #
        # we are at the level of a single line (line_number). we now consume
        # its set of citems (citem_indexes) and attempt to identify explicit
        # graph nodes they claim to be sourced from (by their reported EA)
        #

        for index in citem_indexes:

            # get the code address of the given citem
            try:
                item = treeitems[index]
                address = item.ea

            # apparently this is a thing on IDA 6.95
            except IndexError as e:
                continue

            nodes.add(address)

        #
        # finally, save the completed list of node ids as identified for this
        # line of decompilation text to the line2node map that we are building
        #

        line2node[line_number] = nodes

    # all done, return the computed map
    return line2node


def lex_citem_indexes(line):
    """
    Lex all ctree item indexes from a given line of text.
    The HexRays decompiler output contains invisible text tokens that can
    be used to attribute spans of text to the ctree items that produced them.
    This function will simply scrape and return a list of all the these
    tokens (COLOR_ADDR) which contain item indexes into the ctree.
    """
    i = 0
    indexes = []
    line_length = len(line)

    # lex COLOR_ADDR tokens from the line of text
    while i < line_length:

        # does this character mark the start of a new COLOR_* token?
        if line[i] == idaapi.COLOR_ON:

            # yes, so move past the COLOR_ON byte
            i += 1

            # is this sequence for a COLOR_ADDR?
            if ord(line[i]) == idaapi.COLOR_ADDR:

                # yes, so move past the COLOR_ADDR byte
                i += 1

                #
                # A COLOR_ADDR token is followed by either 8, or 16 characters
                # (a hex encoded number) that represents an address/pointer.
                # in this context, it is actually the index number of a citem
                #

                citem_index = int(line[i:i+idaapi.COLOR_ADDR_SIZE], 16)
                i += idaapi.COLOR_ADDR_SIZE

                # save the extracted citem index
                indexes.append(citem_index)

                # skip to the next iteration as i has moved
                continue

        # nothing we care about happened, keep lexing forward
        i += 1

    # return all the citem indexes extracted from this line of text
    return indexes


class CodeEmulator:

    def __init__(self):

        # Initialize emulator in thumb mode
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

        # mu.hook_add(UC_HOOK_MEM_READ, hook_mem_access)
        #mu.hook_add(UC_HOOK_BLOCK, hook_block)
        #mu.hook_add(UC_HOOK_CODE, hook_code)

        self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED |
                         UC_HOOK_MEM_WRITE_UNMAPPED, self.hook_mem_invalid)

        self.map_ida_data(0x007F00000, 0x24000)

        # initialize machine registers
        #self.mumu.reg_write(UC_ARM_REG_SP, 0x1234)
        #self.mumu.reg_write(UC_ARM_REG_R1, 0x1234)

    # callback for tracing basic blocks

    def hook_block(self, uc, address, size, user_data):
        print(">>> Tracing basic block at 0x%x, block size = 0x%x" %
              (address, size))

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        # print "[ hook_mem_invalid ]"
        if access == UC_MEM_WRITE_UNMAPPED:
            #print(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" %(address, size, value))
            uc.mem_map(address & 0xfffff000, 0x1000)
            uc.mem_write(address & 0xfffff000, "\x00" * 0x1000)

            return True
        elif access == UC_MEM_READ_UNMAPPED:
            #print(">>> Missing memory is being read at 0x%x, data size = %u" %(address, size))

            uc.mem_map(address & 0xfffff000, 0x1000, 7)
            uc.mem_write(address & 0xfffff000, "\x00" * 0x1000)

            return True

        else:
            # return False to indicate we want to stop emulation
            return False

    # callback for tracing instructions

    def hook_code(self, uc, address, size, user_data):
        print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %
              (address, size))

        sp = uc.reg_read(UC_ARM_REG_SP)
        r1 = uc.reg_read(UC_ARM_REG_R1)
        print(">>> SP = 0x%x" % sp)
        print(">>> r1 = 0x%x" % r1)

    def map_ida_data(self, addr, size):
        self.mu.mem_map(addr, size)
        self.mu.mem_write(addr, idaapi.get_bytes(addr, size))

    def hook_mem_access(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE:
            print(">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" % (
                address, size, value))

        else:   # READ
            print(">>> Memory is being READ at 0x%x, data size = %u"
                  % (address, size))

            data = uc.mem_read(address, size)
            print str(data).encode("hex")

    def emulate(self, addr, end):
        try:
            self.mu.emu_start(addr | 1, end)
            return True
        except UcError as e:
            print("ERROR: {}, PC: 0x{:X}".format(
                e, self.mu.reg_read(UC_ARM_REG_PC)))

        return False


class ArgumentTracker:
    def __init__(self):
        pass

    def is_call_instr(self, mnem):
        call_instr_list = ["blx", "bx", "bl", "b"]
        if mnem in call_instr_list:
            return True

        return False

    def is_set_argument_instr(self, mnem):
        instr_list = ["ldr", "mov"]
        for i in instr_list:
            if mnem.startswith(i):
                return True
        return False

    def track_register(self, ea, target_dest_reg):

        f_start = idc.get_func_attr(ea, idc.FUNCATTR_START)
        f_end = idc.get_func_attr(ea, idc.FUNCATTR_END)

        curr_ea = ea
        dst = None
        src = None

        target = target_dest_reg.lower()
        target_dest_reg = target_dest_reg.lower()

        target_value = None
        target_ea = idc.BADADDR
        target_type = None
        previous_call = None

        ret_dict = {}

        while curr_ea != idc.BADADDR:
            #instruction = idc.GetDisasm(curr_ea)

            # print "0x%08x %s" % (curr_ea, instruction)

            # looking for the previous place this register was assigned a value
            mnem = idc.print_insn_mnem(curr_ea).lower()
            dst = idc.print_operand(curr_ea, 0).lower()
            src = idc.print_operand(curr_ea, 1).lower()

            if dst == target and self.is_set_argument_instr(mnem):
                target = src
                target_value = src
                target_ea = curr_ea
                # print "            new target set %s (type=%d)" % (target, idc.get_operand_type(curr_ea, 1))
                if target.startswith("="):
                    break

            if dst == target == "r0" and self.is_call_instr(mnem):
                target_value = "<return from previous call>"
                previous_call = curr_ea
                break
            # step to previous instruction
            curr_ea = idc.prev_head(curr_ea-1, f_start)

        if target_value:
            # print ">>> 0x%08x, %s is set to %s @ 0x%08x" % (ea, target_dest_reg, target_value, target_ea)
            ret_dict = {"target": target_dest_reg, "value": target_value,
                        "target_ea": target_ea, "ea": ea}

            if previous_call:
                ret_dict["previous_call"] = previous_call

            return ret_dict

        # fall through if nothing is found
        return {}

    def calc_expr(self, expr):
        rd = {}

        for c in expr.split(" "):
            if c in ["+", "-", "*"]:
                continue

            if c.startswith("0x"):
                continue

            if len(re.findall("^\d+$", c)) > 0:
                continue

            addr = idaapi.get_name_ea(idaapi.BADADDR, c)
            if addr != idaapi.BADADDR:
                value = idaapi.get_dword(addr)
                rd[c] = "0x{:X}".format(value)

        for k, v in rd.items():
            expr = expr.replace(k, v)

        return expr.strip()

    def trace_decompile_var(self, lines, idx, v):
        # print "[ trace_decompile_var ]" + v
        ret = []

        while idx >= 0:
            line = lines[idx]
            # print line
            # print "{}.*?=(.*?);".format(v)
            r = re.findall("{}.*?=(.*?);".format(v), line)
            if len(r) > 0:
                ret.append(self.calc_expr(r[0]))
            idx -= 1

        return ret

    def decompile_tracer(self, ea, extract_func):
        c = idaapi.decompile(ea)

        # decompilation_text = c.get_pseudocode()

        # line2citem = map_line2citem(decompilation_text)
        # line2node = map_line2node(c, line2citem)

        # for line_number, line_nodes in line2node.iteritems():
        #     for i in line_nodes:
        #         if ea == i:
        #             break

        # print line_number

        sink_list = []

        lines = str(c).split("\n")
        idx = 0
        for l in lines:
            arg = extract_func(l)
            if arg != "":
                sink_list.append((idx, arg))
            idx += 1

        # print sink_list

        result_expr = []

        for sink in sink_list:
            idx = sink[0]
            expr = sink[1]

            expr_queue = []
            expr_queue.append(expr)

            cur_expr = ""

            while len(expr_queue) > 0:

                cur_expr = expr_queue.pop()

                # print expr_queue, cur_expr

                rd = {}

                for c in cur_expr.split(" "):
                    c = c.strip()
                    if c in ["+", "-", "*", ">>", "<<", "^", "&", "|"]:
                        continue

                    if c.startswith("0x"):
                        continue

                    if len(re.findall("^\d+$", c)) > 0:
                        continue

                    addr = idaapi.get_name_ea(idaapi.BADADDR, c)
                    if addr == idaapi.BADADDR:
                        value = self.trace_decompile_var(lines, idx, c)
                    else:
                        value = idaapi.get_dword(addr)
                        value = ["0x{:X}".format(value)]

                    rd[c] = value

                # print rd

                if len(rd) > 0:
                    for k, vs in rd.items():
                        for v in vs:
                            cur_expr = cur_expr.replace(k, v)
                            expr_queue.append(cur_expr)
                else:
                    result_expr.append(cur_expr)

        ret = []
        for i in result_expr:
            rv = ida_expr.idc_value_t()
            idaapi.eval_expr(rv, ea, i)
            if rv.num != 0 and rv.num not in ret:
                ret.append(rv.num)
        return ret


class CustomLogger:
    def __init__(self):
        
        self.file = open("log.txt", "w")

    def log(self, data):
        print data
        self.file.write(data + "\n")


def extract_ke_task_create(line):
    args = re.findall("ke_task_create\((.*)\)", line)
    if len(args) == 0:
        return ""

    arg = args[0].split(",")[1]
    # print arg
    return arg.strip()


def dump_ke_task_create():
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


        logger.log("[decompile_tracer] addr: 0x{:X}, task_struct: 0x{:X}".format(xref.frm, at.decompile_tracer(xref.frm, extract_ke_task_create)[0]))



def extract_ke_msg_alloc_msgid(line):
    target = re.findall("ke_msg_alloc\((.*?),", line)

    if len(target) == 0:
        return ""

    return target[0]


def dump_msg_id_usage():
    logger = CustomLogger()
    m = CodeEmulator()
    a = ArgumentTracker()


    ke_msg_alloc_addr = idaapi.get_name_ea(idaapi.BADADDR, "ke_msg_alloc")

    result = {}
    for xref in XrefsTo(ke_msg_alloc_addr, 0):
        frm_func = idc.get_func_name(xref.frm)

        # print "frm:0x{:X}, frm_func:{}".format(xref.frm, frm_func)
        # print "  task_desc: 0x{:X}".format(idaapi.get_arg_addrs(xref.frm)[1])

        ret = a.track_register(xref.frm, "r0")
        if ret.has_key("target_ea"):
            # print "target_ea: 0x{:X}".format(ret['target_ea'])
            if m.emulate(ret['target_ea'], xref.frm):
                if not result.has_key(xref.frm):
                    result[xref.frm] = set()
                r0 = m.mu.reg_read(UC_ARM_REG_R0)
                logger.log("addr: 0x{:X}, msg id: 0x{:X}".format(xref.frm, r0))
                result[xref.frm].add(r0)
            else:

                if not result.has_key(frm_func):
                    result[frm_func] = set()
                # print "emulate 0x{:X}----0x{:X} failed!".format(ret['target_ea'], xref.frm)
                for msg_id in a.decompile_tracer(xref.frm, extract_ke_msg_alloc_msgid):
                    logger.log("[ decompile_tracer ] addr: 0x{:X}, msg id: 0x{:X}".format(xref.frm, msg_id))
                    result[frm_func].add(msg_id)
        else:
            logger.log("0x{:X} failed!".format(xref.frm))

    for k, v in result.items():
        logger.log("{}: {}".format(k, ','.join(["0x{:X}".format(i) for i in v])))
        result[k] = list(result[k])

    import json

    with open("msg_id_usage.json", "w") as fp:
        fp.write(json.dumps(result))


if __name__ == "__main__":
    # dump_ke_task_create()
    dump_msg_id_usage()

