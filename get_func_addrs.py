import idautils
import idc

# Locate function addresses.
#
# based on: https://reverseengineering.stackexchange.com/a/14726
func_addrs = []
for seg in idautils.Segments():
	# Skip extern segment; as used by IDA for external functions.
	if idc.get_segm_attr(seg, SEGATTR_TYPE) == idc.SEG_XTRN:
		#print("skipping segment ", idc.get_segm_name(seg))
		continue
	for fn in idautils.Functions(seg, idc.get_segm_end(seg)):
		#func_name = idc.get_name(fn)
		func_addr = fn
		func_addrs.append(func_addr)
func_addrs.sort()

func_addrs_json = "["
for func_addr in func_addrs:
	func_addrs_json += "\n\t\"0x%08X\","%(func_addr)
func_addrs_json = func_addrs_json.rstrip(',')
func_addrs_json += "\n]"

print(func_addrs_json)
