import idautils
import idc

# Locate function chunks.
#
# based on: https://reverseengineering.stackexchange.com/a/14726

# func_chunks maps from function address to list of chunks (each with a start
# address and size in bytes).
func_chunks = {}
func_addrs = []
for seg in idautils.Segments():
	# Skip extern segment; as used by IDA for external functions.
	if idc.get_segm_attr(seg, SEGATTR_TYPE) == idc.SEG_XTRN:
		#print("skipping segment ", idc.get_segm_name(seg))
		continue
	for fn in idautils.Functions(seg, idc.get_segm_end(seg)):
		func_addr = fn
		#func_name = idc.get_name(fn)
		# chunks is a list of chunks contained within the current function.
		chunks = []
		for (chunk_start, chunk_end) in idautils.Chunks(fn):
			chunk_addr = chunk_start
			chunk_size = chunk_end - chunk_start
			chunk = {"chunk_addr": chunk_addr, "chunk_size": chunk_size}
			chunks.append(chunk)
		# Sort chunks based on start address.
		chunks = sorted(chunks, key=lambda chunk: chunk['chunk_addr']) # sort by chunk address
		func_chunks[func_addr] = chunks
		func_addrs.append(func_addr)

# Sort function addresses to be used as key.
func_addrs.sort()

# Example output:
#
#    {
#       "0x00000000": [
#          {
#             "chunk_addr": "0x00000000",
#             "chunk_size": 11
#          },
#          {
#             "chunk_addr": "0x00000011",
#             "chunk_size": 6,
#          }
#       ],
#       "0x0000000B": [
#          {
#             "chunk_addr": "0x0000000B",
#             "chunk_size": 6
#          }
#       ]
#    }

chunks_json = "{"
for func_addr in func_addrs:
	chunks_json += "\n\t\"0x%08X\": ["%(func_addr)
	chunks = func_chunks[func_addr]
	for chunk in chunks:
		chunk_addr = chunk["chunk_addr"]
		chunk_size = chunk["chunk_size"]
		chunks_json += "\n\t\t{"
		chunks_json += "\n\t\t\t\"chunk_addr\": \"0x%08X\","%(chunk_addr)
		chunks_json += "\n\t\t\t\"chunk_size\": %d"%(chunk_size)
		chunks_json += "\n\t\t},"
	chunks_json = chunks_json.rstrip(',')
	chunks_json += "\n\t],"
chunks_json = chunks_json.rstrip(',')
chunks_json += "\n}"

print(chunks_json)
