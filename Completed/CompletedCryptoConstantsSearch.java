//Completed Demo - search for MD5 crypto constants in code 
//@author Alexei Bulazel
//@category INFILTRATE
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.util.DataConverter;
import ghidra.util.LittleEndianDataConverter;
import ghidra.util.BigEndianDataConverter;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

import java.util.ArrayList;

public class CompletedCryptoConstantsSearch extends GhidraScript {

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
			
		Address currentFind = memory.findBytes(baseAddr, asBytes, null, true, getMonitor());

        //loop saving found addresses of found byte sequence occurences, and finding the next
		while(currentFind != null) {
			occurrences.add(currentFind);	
			
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

    			Function currentFunction = getFunctionContaining(currentFoundAddress);
    			String functionName = "";
    			
    			if(currentFunction != null){
    				functionName = currentFunction.getName();
    			}
    			else{
    				functionName = "null";
    			}

    			printf("MD5 Constant 0x%x found at 0x%x (%s)\n", 
    					md5value, 
    					currentFoundAddress.getOffset(),
    					functionName);
    			
    		}
    	}
    }
    
}
