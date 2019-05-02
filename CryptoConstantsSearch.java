//Fill in the blank demo - search for MD5 crypto constants in code
//@author Alexei Bulazel
//@category INFILTRATE
//@keybinding 
//@menupath 
//@toolbar 

/* Some Ghidra API functions you may find useful...
 	
 	[Memory method]
	Address findBytes​(Address startAddr, byte[] bytes, byte[] masks, boolean forward, TaskMonitor monitor)
		Finds a sequence of contiguous bytes that match the given byte array at all bit positions where the mask contains an "on" bit. Starts at startAddr and ends at endAddr. If forward is true, search starts at startAddr and will end if startAddr ">" endAddr. If forward is false, search starts at start addr and will end if startAddr "<" endAddr.
	
		Parameters:
			startAddr - The beginning address in memory to search.
			bytes - the array of bytes to search for.
			masks - the array of masks. (One for each byte in the byte array) if all bits of each byte is to be checked (ie: all mask bytes are 0xff), then pass a null for masks.
			forward - if true, search in the forward direction.
	
			HINT: for the monitor parameter, you can just use getMonitor()
		
		Returns: The address of where the first match is found. Null is returned if there is no match.
	
	docs/api/ghidra/program/model/mem/Memory.html#findBytes(ghidra.program.model.address.Address,ghidra.program.model.address.Address,byte[],byte[],boolean,ghidra.util.task.TaskMonitor)
 
 ***********
  
	[Address method] 
  	Address add​(long displacement) throws AddressOutOfBoundsException
		
		Creates a new address (possibly in a new space) by adding the displacement to this address.
		
		Parameters:
			displacement - the amount to add to this offset.
			
		Returns: The new address.
		
		Throws: AddressOutOfBoundsException - if wrapping is not supported by the corresponding address space and the addition causes an out-of-bounds error

  		docs/api/ghidra/program/model/address/Address.html#add(long)
  		
 ***********

 	public final Function getFunctionContaining​(Address address)
		Returns the function containing the specified address.

		Parameters:
			address - the address
		
		Returns: the function containing the specified address
		
		docs/api/ghidra/program/flatapi/FlatProgramAPI.html#getFunctionContaining(ghidra.program.model.address.Address)
  
 ***********
  
	[Function method]
	java.lang.String getName()
		Get the name of this function.
		
		Specified by:
			getName in interface Namespace
			
		Returns: the functions name
 
  		docs/api/ghidra/program/model/listing/Function.html#getName()
  
 */

import ghidra.app.script.GhidraScript;
import ghidra.util.DataConverter;
import ghidra.util.LittleEndianDataConverter;
import ghidra.util.BigEndianDataConverter;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

import java.util.ArrayList;

public class CryptoConstantsSearch extends GhidraScript {

	private ArrayList<Address>getAllOccurrences(int searchPattern) {
		DataConverter converter;
		
		Memory memory = currentProgram.getMemory();
		Address baseAddr = memory.getMinAddress();
		ArrayList<Address> occurrences = new ArrayList<Address>();
		
		//convert byte sequence endianness, per current program endianness	
		if (currentProgram.getLanguage().isBigEndian()) {
			converter = new BigEndianDataConverter();
		}
		else {
			converter = new LittleEndianDataConverter();
		}
		
		byte[] asBytes = converter.getBytes(searchPattern);
	
		println("TODO: find the first occurrence of the byte sequence in the program");
		Address currentFind = null; //memory.findBytes(...)

		//loop saving found addresses of found byte sequence occurences, and finding the next
		while(currentFind != null) {
			occurrences.add(currentFind);
						
			//find the next occurrence
			currentFind = memory.findBytes(currentFind.add(4), asBytes, null, true, getMonitor());
		}
		
		return occurrences;
	}
	
    public void run() throws Exception {
    	
    	int[] MD5Constants = new int[] { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    	
    	for (int md5value : MD5Constants) {
    		if(monitor.isCancelled()) {
    			break;
    		}
    			
    		ArrayList <Address> found = getAllOccurrences(md5value);
    		
    		for (Address currentFoundAddress : found) { 

    			println("TODO: get the function at currentFoundAddress");
    			Function currentFunction = null; 
    			String functionName = "n/a";
    			
    			if(currentFunction != null){
    				functionName = "TODO: get the function name!";
    			}

    			printf("MD5 Constant 0x%x found at 0x%x (%s)\n", 
    					md5value, 
    					currentFoundAddress.getOffset(),
    					functionName);
    			
    		}
    	}
    }
    
}
