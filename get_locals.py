import idautils
import ida_frame
import idc

idc.GetFrame()

# Locate local variables of function stack frames.
#
# based on: https://reverseengineering.stackexchange.com/a/14726

# from: https://gist.github.com/nirizr/fe0ce9948b3db05555da42bbfe0e5a1e
def find_stack_members(func_ea):
	members = {}
	base = None
	frame = idc.GetFrame(func_ea)
	for frame_member in idautils.StructMembers(frame):
		member_offset, member_name, _ = frame_member
		members[member_offset] = member_name
		if member_name == ' r':
			base = member_offset
	if not base:
		raise ValueError("Failed identifying the stack's base address using the return address hidden stack member")
	return members, base

# func_frames maps from function address to a record of the function's stack
# frame size and local variables.
func_frames = {}
func_addrs = []
for seg in idautils.Segments():
	# Skip extern segment; as used by IDA for external functions.
	if idc.get_segm_attr(seg, SEGATTR_TYPE) == idc.SEG_XTRN:
		#print("skipping segment ", idc.get_segm_name(seg))
		continue
	for fn in idautils.Functions(seg, idc.get_segm_end(seg)):
		func_addr = fn
		frame = ida_frame.get_frame(func_addr)
		frame_size = ida_frame.get_frame_size(func_addr)
		var_names = []
		for i in range(frame_size):
			var_name = idc.GetMemberName(frame, i)
			# TODO: check if ' r' and ' s' (return address and saved registers) may have
			# duplicates.
			if var_name is None:
				continue
			var_names.append(var_name)
		print(var_names)
		func_frame = {"func_name": func_name, "func_type": func_type}
		func_frames[func_addr] = func_frame
		func_addrs.append(func_addr)

# TODO: check diff between ESP at function entry and each instruction.
#    fn = idaapi.get_func(0)
#    ida_frame.get_effective_spd(fn, inst_ea)
#
# TODO: check whether to use get_effective_spd or get_spd.


# Sort function addresses to be used as key.
func_addrs.sort()

# Example output:
#
#    {
#       "0x0": {
#          "frame_size": 20,
#          "vars": [
#             {
#                "name": "x",
#                "base": "ebp",
#                "offset": -4
#             },
#             {
#                "name": "y",
#                "base": "ebp",
#                "offset": -8
#             },
#             {
#                "name": "foobar",
#                "base": "ebp",
#                "offset": -12
#             }
#          ]
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
