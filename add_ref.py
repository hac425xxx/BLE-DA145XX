


def add_ref(frm, to):
    idaapi.add_dref(frm, to, idaapi.dr_R)
    idaapi.add_dref(to, frm, idaapi.dr_R)

add_ref(0x7F09CC6, 0x7F1F578)