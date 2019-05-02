//Completed demo - Script to compute and print the cyclomatic complexity of all functions
//@author Alexei Bulazel
//@category INFILTRATE
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.AbstractComparableColumnDisplay;
import ghidra.app.tablechooser.AddressableRowObject;
import ghidra.app.tablechooser.ColumnDisplay;
import ghidra.app.tablechooser.StringColumnDisplay;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.util.CyclomaticComplexity;
import ghidra.util.exception.CancelledException;

// based off of ComputeCyclomaticComplexity.java
// CompareFunctionSizesScript.java provides a useful example for writing plugins with UI popups


/*
	./analyzeHeadless [path to directory containing .g] [project name] -process -prescript [path to this script] -noanalysis
	
	$ ./analyzeHeadless ~/research/INFILTRATE/projects/ test.gpr -process -prescript ~/ghidra_scripts/CompletedComputeCyclomaticComplexityForAllFunctions.java -noanalysis
*/

public class ComputeCyclomaticComplexityForAllFunctions extends GhidraScript {

	private CyclomaticComplexity cyclo = new CyclomaticComplexity();

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			printerr("no current program");
			return;
		}
		
		FunctionIterator functionIterator = currentProgram.getFunctionManager().getFunctions(true);
		
		if (!isRunningHeadless()) {
			TableChooserDialog tableDialog = createTableChooserDialog(currentProgram.getName() + " - Function Cyclomatic Complexity", null, false);
			configureTableColumns(tableDialog);
			
			tableDialog.show();
						
			for ( Function currentFunction : functionIterator ) {
				FuncCycloData funcCycloData = new FuncCycloData(currentFunction); 
				tableDialog.add(funcCycloData);
			}
			
		}
		else { //isRunningHeadless
			
			for( Function currentFunction : functionIterator ) {
				int functionCyclomaticComplexity = cyclo.calculateCyclomaticComplexity(currentFunction, getMonitor());;
				printf("%s complexity: %d\n", currentFunction.getName(), functionCyclomaticComplexity);
			}
		}
	}
	
	private class FuncCycloData implements AddressableRowObject {

		private Function function;
		private Integer functionCyclomaticComplexity;
		private Address functionAddress;
		
		public FuncCycloData(Function f) throws CancelledException {
			function = f;
			
			functionAddress = function.getEntryPoint();
			
			functionCyclomaticComplexity = cyclo.calculateCyclomaticComplexity(function, getMonitor());
		}
		
		@Override
		public Address getAddress() {
			return functionAddress;
		} 
		
		public Function getFunction() {
			return function;
		}
		
		public int getCylomaticComplexity() {
			return functionCyclomaticComplexity;
		}
		
	}
	
	private void configureTableColumns(TableChooserDialog dialog) throws CancelledException {
		
		StringColumnDisplay functionNameColumn = new StringColumnDisplay() {
			
			@Override
			public String getColumnName() {
				return "Function Name";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				return ((FuncCycloData) rowObject).getFunction().getName();
			}
		};
		
		ColumnDisplay<Integer> cyclomaticComplexityColumn = new AbstractComparableColumnDisplay<Integer>() {

			@Override
			public Integer getColumnValue(AddressableRowObject rowObject) {
				return ((FuncCycloData) rowObject).getCylomaticComplexity();
			}

			@Override
			public String getColumnName() {
				return "Cyclomatic Complexity";
			}
			
		};
		
		dialog.addCustomColumn(functionNameColumn);
		dialog.addCustomColumn(cyclomaticComplexityColumn);
	
	}
}
