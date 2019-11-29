import idautils
import idc

# Locate function signatures.
#
# based on: https://reverseengineering.stackexchange.com/a/14726

# func_sigs maps from function address to a record of the function's name and
# type.
func_sigs = {}
func_addrs = []
for seg in idautils.Segments():
	# Skip extern segment; as used by IDA for external functions.
	if idc.get_segm_attr(seg, SEGATTR_TYPE) == idc.SEG_XTRN:
		#print("skipping segment ", idc.get_segm_name(seg))
		continue
	for fn in idautils.Functions(seg, SegEnd(seg)):
		func_addr = fn
		func_name = idc.get_name(func_addr)
		if func_name is None:
			func_name = ""
		func_type = idc.get_type(func_addr)
		if func_type is None:
			func_type = ""
		func_sig = {"func_name": func_name, "func_type": func_type}
		func_sigs[func_addr] = func_sig
		func_addrs.append(func_addr)

# Sort function addresses to be used as key.
func_addrs.sort()

# Example output:
#
#    [
#       {
#          "func_addr": "0x0",
#          "func_name": "foo",
#          "func_type": "int __cdecl(int x, int y)"
#       },
#       {
#          "func_addr": "0x20",
#          "func_name": "main",
#          "func_type": "int __cdecl(int argc, const char **argv, const char **envp)"
#       }
#    ]
func_sigs_json = "["
for func_addr in func_addrs:
	func_sig = func_sigs[func_addr]
	func_name = func_sig["func_name"]
	func_type = func_sig["func_type"]
	func_sigs_json += "\n\t{"
	func_sigs_json += "\n\t\t\"func_addr\": \"0x%08X\","%(func_addr)
	func_sigs_json += "\n\t\t\"func_name\": \"%s\","%(func_name)
	func_sigs_json += "\n\t\t\"func_type\": \"%s\""%(func_type)
	func_sigs_json += "\n\t},"
func_sigs_json = func_sigs_json.rstrip(',')
func_sigs_json += "\n]"

print(func_sigs_json)
