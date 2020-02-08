import idautils
import idc

# Locate function chunks.
#
# based on: https://reverseengineering.stackexchange.com/a/14726

# chunks maps from chunk start address to a record containing the chunk size in
# bytes and a list of parent functions containing the chunk (as a chunk may be
# used by more than one function).
chunks = {}
chunk_start_addrs = []
for seg in idautils.Segments():
	# Skip extern segment; as used by IDA for external functions.
	if idc.get_segm_attr(seg, SEGATTR_TYPE) == idc.SEG_XTRN:
		#print("skipping segment ", idc.get_segm_name(seg))
		continue
	for fn in idautils.Functions(seg, idc.get_segm_end(seg)):
		fn_addr = fn
		#func_name = idc.get_name(fn)
		for (chunk_start, chunk_end) in idautils.Chunks(fn):
			if not chunk_start in chunks:
				chunk_size = chunk_end - chunk_start
				chunks[chunk_start] = {"chunk_size": chunk_size, "parent_funcs": []}
			chunks[chunk_start]["parent_funcs"].append(fn_addr)
				#chunk = chunks[chunk_start]
				#chunk["parent_funcs"].append(fn_addr)
				#chunks[chunk_start] = chunk # TODO: check if this line is needed.
			chunk_start_addrs.append(chunk_start)

# Sort chunk starting addresses to be used as key.
chunk_start_addrs.sort()

# Sort parent funcs.
for chunk_start_addr in chunk_start_addrs:
	chunk = chunks[chunk_start_addr]
	chunk["parent_funcs"].sort()

# Example output:
#
#    [
#       {
#          "chunk_addr": "0xDAF0",
#          "chunk_size": 331,
#          "parent_funcs": [
#             "0xDC70"
#          ]
#       },
#       {
#          "chunk_addr": "0xDC40",
#          "chunk_size": 8,
#          "parent_funcs": [
#             "0xDC70",
#          ]
#       },
#       {
#          "chunk_addr": "0xDC50",
#          "chunk_size": 19,
#          "parent_funcs": [
#             "0xDC70"
#          ]
#       }
#    ]
chunks_json = "["
for chunk_start_addr in chunk_start_addrs:
	chunk = chunks[chunk_start_addr]
	chunk_size = chunk["chunk_size"]
	chunks_json += "\n\t{"
	chunks_json += "\n\t\t\"chunk_addr\": \"0x%08X\","%(chunk_start_addr)
	chunks_json += "\n\t\t\"chunk_size\": %d,"%(chunk_size)
	chunks_json += "\n\t\t\"parent_funcs\": ["
	for parent_func in chunk["parent_funcs"]:
		chunks_json += "\n\t\t\t\"0x%08X\","%(parent_func)
	chunks_json = chunks_json.rstrip(',')
	chunks_json += "\n\t\t]"
	chunks_json += "\n\t},"
chunks_json = chunks_json.rstrip(',')
chunks_json += "\n]"

print(chunks_json)
