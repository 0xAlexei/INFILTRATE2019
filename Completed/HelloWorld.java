//Hello world example
//@author Alexei Bulazel
//@category INFILTRATE
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;


public class HelloWorld extends GhidraScript {

    public void run() throws Exception {
	println("Hello world");

	Function currentFunc = getFirstFunction();
	while (currentFunc != null){
		println(currentFunc.getName());
		currentFunc = getFunctionAfter(currentFunc);
	}
    }
}




