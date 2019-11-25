import idautils
#import idc

# Locate function addresses.
#
# based on: https://reverseengineering.stackexchange.com/a/14726
func_addrs = []
for fn in idautils.Functions():
	#functionName = idc.GetFunctionName(fn)
	func_addr = fn
	func_addrs.append(func_addr)
func_addrs.sort()

func_addrs_json = "{"
for func_addr in func_addrs:
	func_addrs_json += "\n\t\"0x%08X\","%(func_addr)
func_addrs_json = func_addrs_json.rstrip(',')
func_addrs_json += "\n}"

print func_addrs_json
