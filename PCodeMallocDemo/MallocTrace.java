//Analysis to find arguments passed to malloc()
//See our INFILTRATE 2019 presentation at https://vimeo.com/335158460
//@author Alexei Bulazel
//@category INFILTRATE
//@keybinding 
//@menupath
//@toolbar 

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.exception.NotYetImplementedException;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;


public class MallocTrace extends GhidraScript {
	
	private DecompInterface decomplib;
	
	//class for node in a source-sink flow
	class FlowInfo {
		public long constValue;
		private boolean isParent;
		private boolean isChild;
		private Function function;
		private Function targetFunction;
		private ArrayList<FlowInfo> children = new ArrayList<FlowInfo>();
		private ArrayList<FlowInfo> parents = new ArrayList<FlowInfo>();

		private Address callSiteAddress;
		private int argIdx;

		FlowInfo(long constValue){
			this.constValue = constValue;
		}
		
		FlowInfo(Function function){
			this.function = function;
			this.isChild = true;	
		}
			
		FlowInfo(Function function, Function targetFunction, Address callSiteAddress, int argIdx){
			this.function = function;
			this.callSiteAddress = callSiteAddress;
			this.targetFunction = targetFunction;
			this.argIdx = argIdx;
			
			this.isParent = true;
		}

		public void appendNewParent(FlowInfo parent) {
			this.parents.add(parent);
			printf("Adding new parent... \n");
		}
		
		public void appendNewChild(FlowInfo child) {
			this.children.add(child);
			printf("Adding new child...\n");
		}
	
		public boolean isParent() { return isParent; }
		
		public boolean isChild() { return isChild; }
		
		public ArrayList<FlowInfo> getChildren() { return children; }
		
		public ArrayList<FlowInfo> getParents() { return parents; }
		
		public Function getFunction() { return function; }
		
		public Function getTargetFunction() { return targetFunction; }
		
		public Address getAddress() { return callSiteAddress;}
		
		public int getArgIdx() { return argIdx;}

		
	}
	
	// child class representing variables / flows that are phi inputs, e.g., any PhiFlow object
	// is directly an input to a MULTIEQUAL phi node
	class PhiFlow extends FlowInfo{
		PhiFlow(long newConstValue){
			super(newConstValue);
		}
		
		PhiFlow(Function newFunction){
			super(newFunction);
		}
		
		PhiFlow(Function newFunction, Function newTargetFunction, Address newAddr, int newArgIdx){
			super(newFunction, newTargetFunction, newAddr, newArgIdx);
		}
	}
	
	//child class for representing our "sink" function
	class Sink extends FlowInfo{
		Sink(Function newFunction,Function newTargetFunction, Address newAddr){
			//TODO add support for different param indices if we want to support functions other than malloc()
			super(newFunction, newTargetFunction, newAddr, 0);
			super.isParent = false; //hacky
		}
	}

	
	
	public HighFunction decompileFunction(Function f) {
		HighFunction hfunction = null;

		try {
			DecompileResults dRes = decomplib.decompileFunction(f, decomplib.getOptions().getDefaultTimeout(), getMonitor());
			
			hfunction = dRes.getHighFunction();
		}
		catch (Exception exc) {
			printf("EXCEPTION IN DECOMPILATION!\n");
			exc.printStackTrace();
		}
		
		return hfunction;
	}

	/*
	This function analyzes a function called on the way to determining an input to our sink
	e.g.:

		int x = calledFunction();
		sink(x);
	
	We find the function, then find all of it's RETURN pcode ops, and analyze backwards from
	the varnode associated with the RETURN value.

	weird edge case, we can't handle funcs that are just wrappers around other functions, e.g.:
		func(){
			return rand()
		};
	*/
	private void analyzeCalledFunction(FlowInfo path, Function f, boolean isPhi) 
			throws NotYetImplementedException, InvalidInputException, NotFoundException {
		
		FlowInfo newFlow = null;
		if (!isPhi) {
			newFlow = new FlowInfo(f);
			path.appendNewChild(newFlow);
		}
		else {
			newFlow = new PhiFlow(f);
			path.appendNewChild(newFlow);
		}
		
		HighFunction hfunction = decompileFunction(f);
		if(hfunction == null) {
			printf("Failed to decompile function!");
			return;
		}
		
		printf("Function %s entry @ 0x%x\n", 
				f.getName(), 
				f.getEntryPoint().getOffset());
		
		Iterator<PcodeOpAST> ops = hfunction.getPcodeOps();
		
		//Loop through the functions p-code ops, looking for RETURN
		while (ops.hasNext() && !monitor.isCancelled()) {
			PcodeOpAST pcodeOpAST = ops.next();
			
			if (pcodeOpAST.getOpcode() != PcodeOp.RETURN) {
				continue;
			}
			//from here on, we are dealing with a PcodeOp.RETURN
			
			int returnAddress = 0;
			if ( pcodeOpAST.getSeqnum() != null){
				returnAddress = (int) pcodeOpAST.getSeqnum().getTarget().getOffset();
		
				printf("Found %s return @ 0x%x\n", 
					f.getName(),
					returnAddress);
			}

			//get the varnode for the function's return value
			Varnode returnedValue = pcodeOpAST.getInput(1);
			
			if (returnedValue == null) {
				printf("--> Could not resolve return value from %s\n", f.getName());
				return;
			}
			
			//if we had a phi earlier, it's been logged, so going forward we set isPhi back to false
			processOneVarnode(newFlow, f, returnedValue, false);
		}
		
		printf("\n\n\n\n");
	}
	
	/*
	Given a function, analyze all sites where it is called, looking at how the parameter at the call 
	site specified by paramSlot is derived. This is for situations where we determine that a varnode
	we are looking at is a parameter to the current function - we then have to analyze all sites where
	that function is called to determine possible values for that parameter.
	*/
	private FlowInfo analyzeCallSites(FlowInfo path, Function function, int paramSlot, boolean isPhi) 
			throws InvalidInputException, NotYetImplementedException, NotFoundException {	

		ReferenceIterator referencesTo = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint());

		FlowInfo currentPath = null; 
		
		for (Reference currentReference : referencesTo) {
			
			Address fromAddr = currentReference.getFromAddress();
			Function callingFunction  = getFunctionContaining(fromAddr);
			
			if (callingFunction == null) {
				printf("Could not get calling function @ 0x%x\n", fromAddr.getOffset());
				continue;
			}

			printf("analyzeCallSites(..., %s, ...) - found calling function @ 0x%x [%s]\n", 
					function.getName(),
					fromAddr.getOffset(), 
					callingFunction.getName());
			
			//if the reference is a CALL
			if (currentReference.getReferenceType() == RefType.UNCONDITIONAL_CALL) {
				printf("found unconditional call %s -> %s\n", 
						getFunctionContaining(currentReference.getFromAddress()).getName(), 
						function.getName());
			
				/*
				Heavily based off of code at ShowConstantUse.java:729. Previously I had a very hacky callsite
				discovery algorithm here
				*/
				HighFunction hfunction = decompileFunction(callingFunction);
				
				//get the p-code ops at the address of the reference
				Iterator<PcodeOpAST> ops = hfunction.getPcodeOps(fromAddr.getPhysicalAddress());
				
				//now loop over p-code ops ops looking for the CALL operation
				while(ops.hasNext() && !monitor.isCancelled()) {
					
					PcodeOpAST currentOp = ops.next();
					
					if (currentOp.getOpcode() == PcodeOp.CALL) {
						Address parentAddress = currentOp.getSeqnum().getTarget();
						
						FlowInfo parentNode = null;
						
						//get the function which is called by the CALL operation
						Function targetFunction = getFunctionAt(currentOp.getInput(0).getAddress());
						
						//construct and add the appropriate node to our path

						if (!isPhi) {
							parentNode = new FlowInfo(function, targetFunction, parentAddress, paramSlot);
						}
						else {
							parentNode = new PhiFlow(function, targetFunction, parentAddress, paramSlot);
						}

						//dispatch to analysis of the particular function callsite we are examining to determine how the parameter is defined
		    			currentPath = analyzeFunctionCallSite(parentNode, getFunctionContaining(currentReference.getFromAddress()), currentOp, paramSlot);

		    			path.appendNewParent(currentPath);
					}
				}
			}
			
		}
		
		return currentPath;
	}




	
	/*
	
	This function handles one varnode

	If the varnode is a constant, we are done, create a constant node and return

	If the varnode is associated with a parameter to the function, we then find each
	site where the function is called, and analyze how the parameter varnode at the
	corresponding index is derived for each call of the function

	If the varnode is not constant or a parameter, we get the p-code op which defines it,
	and then recursively trace the one or more varnodes associated with that varnode (tracing backwards),
	and see how they are defined

	*/
	private FlowInfo processOneVarnode(FlowInfo path, Function f, Varnode v, boolean isPhi) 
			throws NotYetImplementedException, InvalidInputException, NotFoundException {

		if (v.isAddress()) {
			println("TODO handle addresses");
		}
		
		//If the varnode is constant, we are done, save it off
		if ( v.isConstant()) {
			printf("\t\t\tprocessOneVarnode: Addr or Constant! - %s\n", v.toString());

			long value = v.getOffset();

			//either it's just a constant, or an input to a phi...
			if (!isPhi) {
				FlowInfo terminal = new FlowInfo(value);
				path.appendNewChild(terminal);
			} 
			else {
				PhiFlow terminalPhi = new PhiFlow(value);
				path.appendNewChild(terminalPhi);
			}

			//done! return
			return path;
		}
				
		/*
		check if this varnode is in fact a parameter to the current function

		we retrieve the high level decompiler variable associated with the varnode
		and check if it is an instance of HighParam, a child class of HighVariable
		representing a function parameter. This seems like an unncessarily complex
		way of figuring out if a given varnode is a parameter, but I found examples 
		of doing it this way in officially-published plugins bundled with Ghidra, 
		and I couldn't figure out a better way to do it
		*/

		HighVariable hvar = v.getHigh();

		if (hvar instanceof HighParam) { 
			printf("Varnode is function parameter -> parameter #%d... %s\n", 
				((HighParam)hvar).getSlot(), //the parameter index
				v.toString());

			//ok, so we do have a function parameter. Now we want to analyze all
			//sites in the binary where this function is called, seeing how varnode
			//at the parameter index that we are is derived
			path = analyzeCallSites(path, f, ((HighParam)hvar).getSlot(), isPhi);

			return path;
		}
		
		/*
		varnode is not a constant, or associated with a param
		
		In this case, we get the p-code operation
		which defines the varnode, and analyze it. We are tracing backwards, for example:
		if we had "varnode x = a + b", we will be given the pcode operation "a + b"... 
		from there, we recursively trace further back, seeing how varnode "a" is defined
		and how varnode "b" is defined. 
		
		As we trace backwards, we might terminate on one of the cases handled above, the 
		varnode ultimately resolving into some constant, or resolving into a parameter to 
		the current function.
		
		It possible that we have something like "varnode x = function_a()" - in this 
		case (a PcodeOp.CALL), we want to trace into that function. At that function, we'll
		start tracing backwards from the varnode(s) associated with the function's RETURN 
		p-codeop(s), in order to figure out how the return value is constructed, this happens
		in analyzeCalledFunction
		

		---
		
		Additionally, it's possible that this varnode is defined by a MULTIEQUAL p-code 
		operation. This is an operation inserted by Ghidra's decompilation analysis when it
		is creating a single-static assignment representation of the p-code, you
		will not see it in the regular listing view if you enable p-code view.  

		MULTIEQUAL is the Ghidra p-code operation used to implement phi nodes in Static Single
		Assignment. Briefly, this operation is used to select from different assignments to the 
		same variable along different control flow paths. Consider the following example:

			var x = 5;
			if (a){
				x = 6;
			}
			else if (b){
				x = 7;
			}
			y = x + 5;

		The final line, after the control flow statements in the middle, makes use of the "x" variable, 
		which can obtain values at three different points in the code above. SSA conversion will rename
		each of these variables (each called "x" in the code above) upon assignment, say to "x1", "x2", 
		and "x3", respectively. After renaming these variables, there is no such variable named "x" anymore,
		so the final line needs to be corrected to indicate that what is being denoted by "x" could 
		actually refer to any of the three renamed variables just created. "x = MULTIEQUAL(x1,x2,x3)" 
		defines a new variable, "x", which could take the value of any of those three variables.

		In any case, what we want to do here, is look at each varnode which is input to this MULTIEQUAL,
		and trace backwards from it. In the example above, we'd visit "x = 5", "x = 6", and "x = 7". Because
		each of these constants is a possible value of x which unifies in this MULTIEQUAL, we set the isPhi flag
		as we trace backwards. This lets our analysis know that whatever value we get for x is associated with our
		phi. This information will be displayed to the user when they get the print out later.
		*/

		//get the p-code op defining the varnode
		PcodeOp def = v.getDef();

		if(def == null) {
			printf("NULL DEF!\n");
			return path;
		}
		
		/*
		This is a very hacky way of getting the concrete virtual address
		associated with a given p-code operation (e.g, the address of the
		actual instruction that underlies it.) Best I can tell, this isn't something
		that we're officially supposed to do - in some cases, a p-code operation may
		not have a concrete instruction in the binary behind it. For debugging purposes while
		developing this script, I used this code, but I don't think it's "correct" or 
		the "right way" to do things
		*/
		if (def.getSeqnum().getTarget() != null) {
			printf("0x%x - ", def.getSeqnum().getTarget().getOffset());
		}

		printf("processOneVarnode: %s\n", def.toString());

		//get the enum value of the p-code operation that defines our varnode
		int opcode = def.getOpcode();

		/*
		Switch on the opcode enum value. Note that this script doens't support
		all possible p-code operations, just common ones that I encountered while 
		writing code to test this script

		see Ghidra's included docs/languages/html/pcodedescription.htm for a listing 
		of p-code operations, and check the "next" link at the bottom for even more
		*/
		switch (opcode) {

			/*
			Handle p-code ops that take one input. We just pass through here, 
			analyzing single varnode that the p-code operation takes.

			For example, see "NOT EAX" here. Our output varnode is just the negation
			of the input varnode. So upon seeing a INT_NEGATE p-code operation, we just
			examine the single varnode that is its input

			malloc(~return3());

				004008a9       NOT   EAX
					EAX = INT_NEGATE EAX
				004008ab       CDQE
					RAX = INT_SEXT EAX
				004008ad       MOV   RDI,RAX
					RDI = COPY RAX
				004008b0       CALL  malloc                                           
					RSP = INT_SUB RSP, 8:8
					STORE ram(RSP), 0x4008b5:8
					CALL *[ram]0x400550:8


			*/
			case PcodeOp.INT_NEGATE:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
			case PcodeOp.CAST:
			case PcodeOp.COPY: {
				processOneVarnode(path, f, def.getInput(0), isPhi);
				break;
			}
			
			/*
			Handle p-code ops that take two inputs. 

			The output (our current varnode) = "(pcodeop input1 input2)" or "input1 [pcodeop] input2":

			Because we are not tracing out all the values that effect values going into our sink function,
			just terminating constants and function calls, we don't log constants associated with these operations

			So if we had a current varnode x:

			"x = y + 5" would result in us calling processOneVarnode(y) but ignoring that "5"

			"x = y + z" would result in us calling processOneVarnode(y) and processOneVarnode(z)

			*/
			case PcodeOp.INT_ADD:
			case PcodeOp.INT_SUB:
			case PcodeOp.INT_MULT:
			case PcodeOp.INT_DIV:
			case PcodeOp.INT_AND:
			case PcodeOp.INT_OR:
			case PcodeOp.INT_XOR: {
				if (!def.getInput(0).isConstant()) {
					//only process if not constant
					processOneVarnode(path,f, def.getInput(0), isPhi);
				}
				if(!def.getInput(1).isConstant()) {
					//only process if not constant
					processOneVarnode(path,f, def.getInput(1), isPhi);
				}
				break;
			}
			

			/*
			Handle CALL p-code ops by analyzing the functions that they call
			*/
			case PcodeOp.CALL:{
				printf("Located source - call to %x [%s]\n", 
						def.getInput(0).getAddress().getOffset(), 
						getFunctionAt(def.getInput(0).getAddress()).getName());

				Function pf = getFunctionAt(def.getInput(0).getAddress());
				
				analyzeCalledFunction(path, pf, isPhi);
				break;
			}
				
			/* 
			p-code representation of a PHI operation. 
			 
			So here we choose one varnode from a number of incoming varnodes.
			 
		 	In this case, we want to explore each varnode that the phi handles
			We need to propogate phi status to each of them as well

			 See documentation at /docs/languages/html/additionalpcode.html
			*/
			case PcodeOp.MULTIEQUAL:{
				printf("Processing a MULTIEQUAL with %d inputs", def.getInputs().length);

				//visit each input to the MULTIEQUAL
				for (int i = 0; i < def.getInputs().length; i++) {
					//we set isPhi = true, as we trace each of the phi inputs
					processOneVarnode(path,f, def.getInput(i), true); 
				}
				break;
			}
				
			/*
			This is a p-code op that may be inserted during the decompiler's
			construction of SSA form. To be honest, I don't completely understand 
			this p-code op's purpose

			See documentation at /docs/languages/html/additionalpcode.html
			*/
			case PcodeOp.INDIRECT:{
				printf("USED In INDIRECT --> output %s\n", def.getOutput().toString());
				
				PcodeOp[] pc = getInstructionAt(v.getPCAddress()).getPcode();
				
				for (int i = 0; i < pc.length; i++) {
					printf("PC%d -> %s\n", i, pc[i].toString());
					if(pc[i].getOpcode() == PcodeOp.CALL) {
						printf("INDIRECT Associated with call @ %x (%s)\n", pc[i].getInput(0).getOffset(), 
								getFunctionContaining(pc[i].getInput(0).getAddress()).getName());
					}
				}
				
				/* 
				I'm not sure if I'm doing the right thing handling INDIRECT in this way
				but I found it being used when handling global variables, and inserting this
				call to processOneVarnodeallows us to resolve further back 
				*/
				processOneVarnode(path,f, def.getInput(1), isPhi);
				break;	
			}
			
			/*
			Two more p-code operations which take two inputs
			*/
			case PcodeOp.PIECE:
			case PcodeOp.PTRSUB: {
				processOneVarnode(path,f, def.getInput(0), isPhi);
				processOneVarnode(path,f, def.getInput(1), isPhi);
				break;	
			}
				
			//throw an exception when encountering a p-code op we don't support
			default: {
				throw new NotYetImplementedException("Support for PcodeOp " + def.toString() + "not implemented");
			}
		}
		
		return path;
	}
	
	
	/*
	This function handles analysis of a particular callsite for a function we are looking at -
	we start at knowing we want to analyze a particular input to the function, e.g., the second parameter,
	then find all call sites in the binary where that function is called (see getFunctionCallSitePCodeOps),
	and then call this function, passing it the pcode op for the CALL that dispatches to the function, as
	well as the parameter index that we want to examine. 

	This function then finds the varnode associated with that particular index, and either saves it (if it
	is a constant value), or passes it off to processOneVarnode to be analyzed

	*/
	public FlowInfo analyzeFunctionCallSite(FlowInfo path, Function f, PcodeOpAST callPCOp, int paramIndex) 
			throws InvalidInputException, NotYetImplementedException, NotFoundException {
				
		if (callPCOp.getOpcode() != PcodeOp.CALL) {
			throw new InvalidInputException("PCodeOp that is not CALL passed in to function expecting CALL only");
		}

		Varnode calledFunc = callPCOp.getInput(0);
		
		if (calledFunc == null || !calledFunc.isAddress()) {
			println("call, but not address!");
			return null;
		}
		
		Address pa = callPCOp.getSeqnum().getTarget();
		
		int numParams = callPCOp.getNumInputs();
		
		/*
		the number of p-code operation varnode inputs here is the number of parameters 
		being passed to the function when called
	
		Note that these parameters only become associated with the CALL p-code op during
		decompiler analysis. They are not present in the raw p-code. 
		*/
		printf("\nCall @ 0x%x [%s] to 0x%x [%s] (%d pcodeops)\n",
				pa.getOffset(),
				f.getName(),
				calledFunc.getAddress().getOffset(), 
				getFunctionAt(calledFunc.getAddress()).getName(),
				numParams);
		
		//param index #0 is the call target address, skip it, start at 1, the 0th parameter
		for (int i = 1; i < numParams; i++) {

			//this function is called with param index starting at 0, we subtract 1 from the input #
			if(i - 1 == paramIndex) {
				//ok, we have the parameter of interest
				Varnode parm = callPCOp.getInput(i);
				
				if (parm == null) {
					printf("\tNULL param #%d??\n", i);
					continue;
				}
				
				printf("\tParameter #%d - %s @ 0x%x\n", 
						i, 
						parm.toString(),
						parm.getAddress().getOffset());
				
				//if we have a constant parameter, save that. We are done here
				if(parm.isConstant()) {
					long value = parm.getOffset();
					
					printf("\t\tisConstant: %d\n", value);
										
					FlowInfo newFlowConst = new FlowInfo(value);
					path.appendNewChild(newFlowConst);
				}
				else{
					path = processOneVarnode(path,f, parm, false); //isPhi = false
				}
			}
		}
		return path;
	}
	
	/*
	Within a function "f", look for all p-code operations associated with a call to a specified
	function, calledFunctionName

	Return an array of these p-code CALL sites
	*/
	public ArrayList<PcodeOpAST> getFunctionCallSitePCodeOps(Function f, String calledFunctionName){

		ArrayList<PcodeOpAST> pcodeOpCallSites = new ArrayList<PcodeOpAST>();
			
		HighFunction hfunction = decompileFunction(f);
		if(hfunction == null) {
			printf("ERROR: Failed to decompile function!\n");
			return null;
		}
					
		Iterator<PcodeOpAST> ops = hfunction.getPcodeOps();
		
		//iterate over all p-code ops in the function
		while (ops.hasNext() && !monitor.isCancelled()) {
			PcodeOpAST pcodeOpAST = ops.next();
			
			if (pcodeOpAST.getOpcode() == PcodeOp.CALL) {
				
				//current p-code op is a CALL
				//get the address CALL-ed
				Varnode calledVarnode = pcodeOpAST.getInput(0);
				
				if (calledVarnode == null || !calledVarnode.isAddress()) {
					printf("ERROR: call, but not to address!");
					continue;
				}
				
				//if the CALL is to our function, save this callsite
				if( getFunctionAt(calledVarnode.getAddress()).getName().compareTo(calledFunctionName) == 0) {
					pcodeOpCallSites.add(pcodeOpAST);
				}
			}			
		}
		return pcodeOpCallSites;
	}

	/*
	set up the decompiler
	*/
	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decompInterface = new DecompInterface();

		DecompileOptions options;
		options = new DecompileOptions();
		PluginTool tool = state.getTool();
		if (tool != null) {
			OptionsService service = tool.getService(OptionsService.class);
			if (service != null) {
				ToolOptions opt = service.getOptions("Decompiler");
				options.grabFromToolAndProgram(null, opt, program);
			}
		}
		decompInterface.setOptions(options);

		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}

	/*
	pretty print a path to a sink
	*/
	private void pprintPathInternal(FlowInfo path, String pattern) {
		
		//if we have a phi, add the phi character at the correct column
		if (path instanceof PhiFlow) {
			pattern += "Ø";
		}

		//print the child/parent/phi pattern of "-", "+", and "Ø"
		if (pattern != "") {
			printf("%s", pattern);
		}
		
		//Our sink function
		if(path instanceof Sink) {
			printf("SINK: call to %s in %s @ 0x%x\n", 
					path.getTargetFunction().getName(), 
					getFunctionContaining(path.getAddress()).getName(), 
					path.getAddress().getOffset());
		}
		//a "parent" - a function that calls the previous function
		else if(path.isParent()) {
			printf("P: call %s -> %s @ 0x%x - param #%d\n", 
					getFunctionContaining(path.getAddress()).getName(), 
					path.getTargetFunction().getName(), 
					path.getAddress().getOffset(), 
					path.getArgIdx());
		}
		//a "child" - a function that the current function calls
		else if (path.isChild()){
			printf("C: %s\n", path.getFunction().getName());
		}
		//if we don't have a function, we have a terminal constant
		if (path.function == null) {
			printf("CONST: %d (0x%x)\n", path.constValue, path.constValue);
		}

		//now print all of this node's children
		for (int i = 0; i < path.getChildren().size(); i++) {
			pprintPathInternal(path.getChildren().get(i), pattern + "-");
		}
		
		//now print all of this node's parents
		for (int j = 0; j < path.getParents().size(); j++) {
			pprintPathInternal(path.getParents().get(j), pattern + "+");
		}	
	}
	
	/*
	Wrapper for pprintPathInternal
	*/	
	public void pprintPath(FlowInfo path) {
		pprintPathInternal(path, "");
	}
	

    public void run() throws Exception {
    	
    	//malloc is an easy function to look at, as it takes a single integer argument
    	String sinkFunctionName = "malloc";

    	
    	decomplib = setUpDecompiler(currentProgram);
    	
    	if(!decomplib.openProgram(currentProgram)) {
    		printf("Decompiler error: %s\n", decomplib.getLastMessage());
    		return;
    	}
    
    	Reference[] sinkFunctionReferences;
    	HashSet<Function> functionsCallingSinkFunction = new HashSet<Function>();


    	//iterator over all functions in the program
    	FunctionIterator functionManager = currentProgram.getFunctionManager().getFunctions(true);
    	
    	for (Function function : functionManager) {
    		/*
    		Look for the function with sinkFunctionName (malloc).

    		Unfortunately, we can't look the function up by name as the FlatAPI function
    		getFunction​(java.lang.String name) is deprecated
    		*/
    		if (function.getName().equals(sinkFunctionName)) {
    			
    			printf("Found sink function %s @ 0x%x\n", 
    					sinkFunctionName, 
    					function.getEntryPoint().getOffset());
    			
    			sinkFunctionReferences = getReferencesTo(function.getEntryPoint());
    			
    			//Now find all references to this function
    			for (Reference currentSinkFunctionReference : sinkFunctionReferences) {
    				printf("\tFound %s reference @ 0x%x (%s)\n", 
    						sinkFunctionName,
    						currentSinkFunctionReference.getFromAddress().getOffset(),
    						currentSinkFunctionReference.getReferenceType().getName());
    				
    				//get the function where the current reference occurs (hopefully it is a function)
    				Function callingFunction = getFunctionContaining(currentSinkFunctionReference.getFromAddress());
    				
    				//Only save *unique* calling functions which are not thunks
    				if (callingFunction != null && 
    					!callingFunction.isThunk() &&
    					!functionsCallingSinkFunction.contains(callingFunction) ) {
    						functionsCallingSinkFunction.add(callingFunction);
    				}
    			}
    		}
    	}
    	
    	printf("\nFound %d functions calling sink function\n", functionsCallingSinkFunction.size());
    	for (Function currentFunction : functionsCallingSinkFunction) {
    		printf("\t-> %s\n", currentFunction.toString());
    	}
    	
    	ArrayList<FlowInfo> paths = new ArrayList<FlowInfo>();

    	//iterate through each unique function which references our sink function
    	for (Function currentFunction : functionsCallingSinkFunction) {
    		
    		//get all sites in the function where we CALL the sink 
			ArrayList<PcodeOpAST> callSites = getFunctionCallSitePCodeOps(currentFunction, sinkFunctionName);
			
			printf("\nFound %d sink function call sites in %s\n", 
					callSites.size(),
					currentFunction.getName());
			
			//for each CALL, figure out the inputs into the sink function
			for (PcodeOpAST callSite : callSites) {
				
				Address pa = callSite.getSeqnum().getTarget();
				
				Function targetFunction = getFunctionContaining(callSite.getInput(0).getAddress());
				
    			Sink sink = new Sink(currentFunction, targetFunction, pa);
    		
    			//for now we pass in 0 for param idx because we only care about input #0 to malloc
				FlowInfo currentPath = analyzeFunctionCallSite(sink, currentFunction, callSite, 0);
				
				paths.add(currentPath);	
			}
    	}
    	    	
    	// Done! Now pretty print. Ideally, here, we would instead render a graph, but Ghidra
    	// does not come with a GraphProvider interface :(

    	printf("\n\n\n\n\n---------------------\n\nPRINTING OUTPUTS\n\n\n\n");
    	for (FlowInfo path : paths) {
    		pprintPath(path);
    		printf("\n\n\n-------------\n\n\n");
    	}  	
    }
}