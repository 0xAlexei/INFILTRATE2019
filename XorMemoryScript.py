#Fill in the blank - demo of Python scripting that xors a selected range of memory
#@author Alexei Bulazel
#@category INFILTRATE
#@keybinding 
#@menupath 
#@toolbar 

""" Based off the original Java code for XorMemoryScript.java, included with GHIDRA

	Some Ghidra API functions you may find useful...

	[Memory method]
  	byte getByte(Address addr) throws MemoryAccessException
	
		Get byte at addr.
	
		Parameters:
			addr - the Address of the byte.
		
		Returns: the byte.

		Throws: MemoryAccessException - if the address is not contained in any memory block.

		docs/api/ghidra/program/model/mem/Memory.html#getByte(ghidra.program.model.address.Address)

	***********

	[Memory method]
	void setByte(Address addr, byte value) throws MemoryAccessException
		
		Write byte at addr.
		
		Parameters:
			addr - the Address of the byte.
			value - the data to write.

		Throws: MemoryAccessException - if writing is not allowed.

		docs/api/ghidra/program/model/mem/Memory.html#setByte(ghidra.program.model.address.Address,byte)

"""

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
	
	addr_ittr = currentSelection.getAddresses(True)

	"""
	Iterate through addresses in "addr_ittr". You can use Python "for object in iterator:" syntax. For each address, you'll want to get the byte there from "memory", xor it with "xor_byte", then set the modified byte in "memory"

	Note that you'll get an exception if you try to XOR memory that is part of defined functions - just use it to XOR data
	"""


run()
