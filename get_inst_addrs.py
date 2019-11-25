import idautils
#import idc

# Locate instruction addresses.
#
# based on: https://reverseengineering.stackexchange.com/a/14726
inst_addrs = []
for fn in idautils.Functions():
	#functionName = idc.GetFunctionName(fn)
	for (chunk_start, chunk_end) in idautils.Chunks(fn):
		for head in idautils.Heads(chunk_start, chunk_end):
			#inst = idc.GetDisasm(head)
			inst_addr = head
			inst_addrs.append(inst_addr)
inst_addrs.sort()

inst_addrs_json = "{"
for inst_addr in inst_addrs:
	inst_addrs_json += "\n\t\"0x%08X\","%(inst_addr)
inst_addrs_json = inst_addrs_json.rstrip(',')
inst_addrs_json += "\n}"

print inst_addrs_json
