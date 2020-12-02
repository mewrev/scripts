# 0x4012d0 is the function address
# 0x4012dc is an instruction address referencing
# a stack variable. It looks like:
# mov [ebp - 4], ecx

import ida_funcs

# Press [alt]+k to open "Change SP value" dialogue, which contains the
# information we are interested in.

fn = ida_funcs.get_func(0x0)
frame = ida_frame.get_frame(fn)
inst = idautils.DecodeInstruction(0x01)
op = inst[0] #first operand references stack var
member, val = ida_frame.get_stkvar(op, inst, op.addr)
xrefs = xreflist_t()
build_stkvar_xrefs(xrefs, fn, member)
for xref in xrefs:
    print hex(xref.ea) #print xref address

# Contrived member dictionary example.
dictMem = dict()
x = 0
while(x < frame.memqty):
    dictMem[GetMemberName(frame.id, frame.get_member(x).soff)] = frame.get_member(x)
    x = x+1
# given var name you can now use the
# dictionary to grab the member_t to pass
# to build_stkvar_xrefs
pMem = dictMem["var_4"]
xrefs = xreflist_t()
build_stkvar_xrefs(xrefs, fn, pMem)
for xref in xrefs:
    print hex(xref.ea) #print xrefs to var_4
