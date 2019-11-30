import sark
import json

# TODO: remove once we upgrade to Python3.
def json_ident(v):
	# indent json output.
	raw = json.dumps(func_addrs, indent=3)
	# convert spaces to tabs.
	raw = raw.replace("   ", "\t")
	# remove trailing spaces.
	return raw.replace(", \n", ",\n")

func_addrs = []
for func in sark.functions():
	func_addr = '0x%08X'%(func.ea)
	func_addrs.append(func_addr)

print(json_ident(func_addrs))
