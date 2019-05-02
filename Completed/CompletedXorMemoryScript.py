#Completed demo of Python scripting that xors a selected range of memory
#@author Alexei Bulazel
#@category INFILTRATE
#@keybinding 
#@menupath 
#@toolbar 

# Based off the original Java code for XorMemoryScript.java, included with GHIDRA


from ghidra.program.model.address import AddressSet

def run():
	"""
	currentSelection is available from GhidraScript as a global object - it's an address range representing the region of memory the user has currently highlighted. See notes at ghidra_docs/api/ghidra/app/script/GhidraScript.html#currentAddress for other current* objects
	"""
	memory = currentProgram.getMemory()

	if currentSelection is None or currentSelection.isEmpty():
		print "Use your mouse to highlight some data to XOR"
		return
		
	print type(currentSelection)

	print currentSelection # note the nice __str__ (to string) implementation

	xor_byte = 0x41
	
	addr_itter = currentSelection.getAddresses(True)

	for addr in addr_itter:	
		setByte(addr, getByte(addr) ^ xor_byte)

run()
