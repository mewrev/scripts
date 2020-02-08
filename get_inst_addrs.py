import idautils
import idc

# Locate instruction addresses.
#
# based on: https://reverseengineering.stackexchange.com/a/14726

# Use hash map to only record each instruction address once.
insts = {}
inst_addrs = []
for seg in idautils.Segments():
	# Skip extern segment; as used by IDA for external functions.
	#
	# Note: we skip this segment, as otherwise the placeholder entity for
	# external functions is recognized by IDA as a "retn" instruction, rather
	# than the jump target pointer it really is.
	#
	# For instance, when running this script on the `/usr/bin/ls` executable of
	# the 64-bit Arch Linux distribution, IDA reports this entry as a "retn"
	# instruction.
	#
	#    extern:0000000000023558 ; Segment type: Externs
	#    extern:0000000000023558 ; extern
	#    extern:0000000000023558 ; const __int32_t **_ctype_toupper_loc(void)
	#    extern:0000000000023558                 extrn __ctype_toupper_loc:near
	#
	#    Python>idautils.DecodeInstruction(0x23558).get_canon_mnem()
	#    'retn'
	if idc.get_segm_attr(seg, SEGATTR_TYPE) == idc.SEG_XTRN:
		#print("skipping segment ", idc.get_segm_name(seg))
		continue
	for fn in idautils.Functions(seg, idc.get_segm_end(seg)):
		#func_name = idc.get_name(fn)
		for (chunk_start, chunk_end) in idautils.Chunks(fn):
			for head in idautils.Heads(chunk_start, chunk_end):
				flags = idc.get_full_flags(head)
				if not is_code(flags):
					# Skip non-code heads. These may appear in functions containing
					# inlined jump tables or alignment directives.
					continue
				#inst = idc.GetDisasm(head)
				inst_addr = head
				insts[inst_addr] = True

for inst_addr in insts:
	inst_addrs.append(inst_addr)
inst_addrs.sort()

inst_addrs_json = "["
for inst_addr in inst_addrs:
	inst_addrs_json += "\n\t\"0x%08X\","%(inst_addr)
inst_addrs_json = inst_addrs_json.rstrip(',')
inst_addrs_json += "\n]"

print(inst_addrs_json)
