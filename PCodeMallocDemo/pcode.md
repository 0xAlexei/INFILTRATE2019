# Working With Ghidra's P-Code To Identify Vulnerable Function Calls by Alexei Bulazel


This year at [INFILTRATE 2019](https://infiltratecon.com/), I got together with fellow [RPISEC](https://rpis.ec/) alumnus and [Boston Cybernetics Institute](https://www.bostoncybernetics.org/) co-founder [Jeremy Blackthorne](https://twitter.com/0xJeremy) to present ["Three Heads Are Better Than One: Mastering NSA’s Ghidra Reverse Engineering Tool"](https://vimeo.com/335158460). [Around 50 minutes into that presentation](https://vimeo.com/335158460#t=49m45s), I presented a demo of a proof of concept script I built to trace out how inputs to `malloc` are derived. In this blog post, we'll take a deeper look at that script.

For those unfamiliar with the tool, [Ghidra](https://ghidra-sre.org/) is an interactive reverse engineering tool developed by the US National Security Agency, comparable in functionality to tools such as [Binary Ninja](https://binary.ninja) and [IDA Pro](https://www.hex-rays.com/). After years of development internally at NSA, [Ghidra was released open source](https://github.com/NationalSecurityAgency/ghidra/) to the public in [March 2019 at RSA](https://www.rsaconference.com/events/us19/agenda/sessions/16608-come-get-your-free-nsa-reverse-engineering-tool).

My script leverages Ghidra's "p-code" intermediate representation to trace inputs to the `malloc` through functions and interprocedural calls.
Calls to `malloc` are of obvious interest to vulnerability researchers looking for bugs in binary software - if a user-controlled input can somehow effect the size of parameter passed to the function, it may be possible for the user to pass in a argument triggering integer overflow during the calculation of allocation size, leading to memory corruption. 

If you want to follow along with the code, I've published it at: https://github.com/0xAlexei/INFILTRATE2019/tree/master/PCodeMallocDemo See discussion later in "Running The Script" for instructions on how to run it with your local copy of Ghidra.


## Inspiration
The inspiration this demo came from watching [Sophia d’Antoine, Peter LaFosse, and Rusty Wagner’s "Be A Binary Rockstar"](https://vimeo.com/215511922) at INFILTRATE 2017, a presentation on Binary Ninja.
During that presentation, fellow [River Loop Security team member Sophia d'Antoine]({{< relref "supermicro-validation-1.md" >}}) demonstrated a [script to find calls to memcpy with unsafe arguments](https://github.com/trailofbits/binjascripts/blob/master/abstractanalysis/binja_memcpy.py), leveraging Binary Ninja’s intermediate language representations of assembly code.
I figured I would create a Ghidra script to do similar, but when I found that it wouldn’t be as simple as just calling a function like `get_parameter_at`, I began digging into to Ghidra’s code and plugin examples published by NSA with Ghidra.
I ended up with the proof of concept script discussed in this post.
While this script might not be ready for real world 0day discovery, it should give you a sense of working with Ghidra's scripting APIs, p-code intermediate representation, and built-in support for program analysis.


## P-Code
P-code is Ghidra's intermediate representation / intermediate language (IR/IL) for assembly language instructions.
Ghidra "lifts" assembly instructions of various disparate architectures into p-code, allowing reverse engineers to more easily develop automated analyses that work with assembly code.

P-code abstracts away the complexities of working with various CPU architectures - x86's plethora of instructions and prefixes, MIPS' delay slots, ARM's conditional instructions, etc, and presents reverse engineers with a common, simplified instruction set to work with. P-code lifting is a one-to-many translation, a single assembly instruction may be lifted into one or more p-code instruction.

For a simple example, see how an x86 `MOV` instruction translates into a single `COPY` p-code operation

```
MOV   RAX,RSI
	RAX = COPY RSI
```

In a more complex case, a `SHR` instruction expands out into 30 p-code operations.
Note how calculations for x86 flags (`CF`, `OF`, `SF`, and `ZF`) are made explicit.

```
SHR   RAX,0x3f
	$Ub7c0:4 = INT_AND 63:4, 63:4
	$Ub7d0:8 = COPY RAX
	RAX = INT_RIGHT RAX, $Ub7c0
	$U33e0:1 = INT_NOTEQUAL $Ub7c0, 0:4
	$U33f0:4 = INT_SUB $Ub7c0, 1:4
	$U3400:8 = INT_RIGHT $Ub7d0, $U33f0
	$U3410:8 = INT_AND $U3400, 1:8
	$U3430:1 = INT_NOTEQUAL $U3410, 0:8
	$U3440:1 = BOOL_NEGATE $U33e0
	$U3450:1 = INT_AND $U3440, CF
	$U3460:1 = INT_AND $U33e0, $U3430
	CF = INT_OR $U3450, $U3460
	$U3490:1 = INT_EQUAL $Ub7c0, 1:4
	$U34b0:1 = INT_SLESS $Ub7d0, 0:8
	$U34c0:1 = BOOL_NEGATE $U3490
	$U34d0:1 = INT_AND $U34c0, OF
	$U34e0:1 = INT_AND $U3490, $U34b0
	OF = INT_OR $U34d0, $U34e0
	$U2e00:1 = INT_NOTEQUAL $Ub7c0, 0:4
	$U2e20:1 = INT_SLESS RAX, 0:8
	$U2e30:1 = BOOL_NEGATE $U2e00
	$U2e40:1 = INT_AND $U2e30, SF
	$U2e50:1 = INT_AND $U2e00, $U2e20
	SF = INT_OR $U2e40, $U2e50
	$U2e80:1 = INT_EQUAL RAX, 0:8
	$U2e90:1 = BOOL_NEGATE $U2e00
	$U2ea0:1 = INT_AND $U2e90, ZF
	$U2eb0:1 = INT_AND $U2e00, $U2e80
	ZF = INT_OR $U2ea0, $U2eb0

```

P-code itself is generated with SLEIGH, a processor specification language for Ghidra which provides the tool with both disassembly information (e.g., the sequence of bytes `89 d8` means `MOV EAX, EBX`), *and* semantic information (`MOV EAX, EBX` has the p-code semantics `EAX = COPY EBX`). After lifting up to raw p-code (i.e., the direct translation to p-code), additionally follow-on analysis may enhance the p-code, transforming it by adding additional metadata to instructions (e.g., the `CALL` p-code operation only has a call target address in raw p-code form, but may gain parameters associated with the function call after analysis), and adding additional analysis-derived instructions not present in raw p-code, such as `MULTIEQUAL`, representing a phi-node (more on that later), or `PTRSUB`, for pointer arithmetic producing a pointer to a subcomponent of a data type.

During analysis the code is also lifted code into [single static assignment (SSA) form](https://en.wikipedia.org/wiki/Static_single_assignment_form), a representation wherein each variable is only assigned a value once.

P-code operates over `varnodes` - quoting from the Ghidra documentation: "A varnode is a generalization of either a register or a memory location. It is represented by the formal triple: an address space, an offset into the space, and a size. Intuitively, a varnode is a contiguous sequence of bytes in some address space that can be treated as a single value. All manipulation of data by p-code operations occurs on varnodes." 

For readers interested in learning more, Ghidra ships with p-code documentation at `docs/languages/html/pcoderef.html`. Additionally, someone has posted the Ghidra decompiler Doxygen docs (included in the decompiler's source) at https://ghidra-decompiler-docs.netlify.com/index.html.


## This Script
This script identifies inputs to `malloc()` by tracing backwards from the variable given to the function in order to figure out how that variable obtains its value, terminating in either a constant value or an external function call. Along the way, each function call that the value passes through is logged - either where it is returned by a function, or passed as an incoming parameter to a function call. The specific operations along the way that can constrain (e.g., checking equality or comparisons) or modify (e.g., arithmetic or bitwise operations) the values are not logged or processed currently for this proof of concept. 

Calls to `malloc` can go badly in a variety of ways, for example, [if an allocation size of zero is passed in](https://openwall.info/wiki/_media/people/jvanegue/files/woot10.pdf), or if an integer overflow occurs on the way to calculating the number of bytes to allocate. In general, we can expect that the chances of one of these types of bugs occuring is more likely if user input is able to somehow effect the value passed to `malloc`, e.g., if the user is able to specify a number of elements to allocate, and then that value is multiplied by `sizeof(element)`, there may be a chance of an integer overflow. If this script is able to determine that user input taken a few function calls before a call to `malloc` ends up passed to the function call, this code path may be worth auditing by a human vulnerability researcher. 

Understanding where allocations of static, non-user controlled sizes are used is also interesting, as exploit developers looking to turn discovered [heap vulnerabilities](http://security.cs.rpi.edu/courses/binexp-spring2015/lectures/17/10_lecture.pdf) into exploits may need to manipulate heap layout with ["heap grooms"](https://googleprojectzero.blogspot.com/2015/06/what-is-good-memory-corruption.html) relying on specific patterns of controlled allocations and deallocations.

Note that while I've chosen to build this script around analysis of `malloc`, as it is a simple function that just takes a single integer argument, the same sort of analysis could be very easily adapted to look for other vulnerable function call patterns, such as `memcpy` with user controlled lengths or buffers on the stack, or  `system` or `exec`-family functions ingesting user input


## Running The Script

I've published the script, a test binary and its source code, and the output I receive when running the script over the binary at https://github.com/0xAlexei/INFILTRATE2019/tree/master/PCodeMallocDemo

You can run the script by putting it in your Ghidra scripts directory (default `$USER_HOME/ghidra_scripts`), opening Ghidra's Script Manager window, and then looking for it in a folder labeled "INFILTRATE". The green arrow "Run Script" button at the top of the Script Manager window will then run the script, with output printed to the console.

I'd also add that because the script simply prints output to the console, it can be run with Ghidra's command line ["headless mode"](https://ghidra-sre.org/InstallationGuide.html#RunHeadless) as well, to print its output to your command line terminal.

## Algorithm

The script begins by looking for every function that references `malloc`. Then, for each of these function, we look for each `CALL` p-code operation targeting `malloc` inside that function. Analysis then begins, looking at sole parameter to `malloc` (`size_t size`). This parameter is a `varnode`, a generalized representation of a value in the program. After Ghidra's [data-flow analysis](https://en.wikipedia.org/wiki/Data-flow_analysis) has run, we can use `varnode`'s `getDef()` method to retrieve the p-code operation which defines it - e.g., for statement `a = b + c`, if we asked for the operation defining `a`, we'd get `b + c`. From here, we can recursively trace backwards, asking what operations define `varnode`s `b` and `c` in that p-code expression, then what operations define their parents, and so on. 

Eventually, we might arrive on the discovery that one of these parents is a constant value, that a value is derived from a function call, or that a value comes from a parameter to the function. In the case that analysis determines that a constant is the ultimate origin value behind the value passed in to `malloc`, we can simply save the constant and terminate analysis of the particular code path under examination. Otherwise, we have to trace into called functions, and consider possible callsites for functions that call the current function under analysis. Along the way, for each function we traverse in a path to a terminal constant value or external function (where we cannot go any further), we save a node in our path to be printed out to the user at the end.


### Analyzing Inside Function Calls

The value passed to `malloc` may ultimately derive from a function call, e.g.:

```
int x = getNumber();

malloc(x+5);
```

In this case, we would analyze `getNumber`, finding each `RETURN` p-code operation in the function, and analyzing the "input1" varnode associated with it, which represents the value the function returns (on x86, this would be the value in `EAX` at time of function return). Note that similar to the association of function parameters with `CALL` p-code operations, return values are only associated with `RETURN` p-code operations *after* analysis, and are not present in raw p-code.

For example:

```
int getNumber(){
	int number = atoi("8");

	number = number + 10;

	return number;
}
```

In the above code snippet, our analysis would trace backwards from return, to addition, and finally to a call to `atoi`, so we could add `atoi` as a node in path determining the source of input to `malloc`. This analysis may be applied recursively until a terminating value of a constant or external function call is encountered.

### Phi Nodes

Discussing analysis of values returned by called functions gives us a opportunity to consider "phi nodes". In the above example, there's only a single path for how number can be defined, first `atoi`, then `+ 10`. But what if instead, we had:

```
int getNumber(){
	
	int number;

	if (rand() > 100){
		number = 10;
	}
	else {
		number = 20;
	}

	return number;
}
```

Now, it's not so clear what `number`'s definition is at time of function return - it could be 10 or 20. A "phi node" can be used to represent the point in the program at which, going forward, number will possess either value 10 or 20. Ghidra's own analysis will insert a `MULTIEQUAL` operation (not present in the raw p-code) at the point where number is used, but could have either value 10 or 20 (you can imagine this operation as happening in between the closing brace of the `else` statement and before `return`). The `MULTIEQUAL` operation tells us that going forward, `number` can have one value out of a range of possible values defined in previous basic blocks (the `if` and `else` paths).

Representing the function in single static assignment form, it can be better understood as:

```
int getNumber(){

	if (rand() > 100){
		number1 = 10;
	}
	else {
		number2 = 20;
	}

	number3 = MULTIEQUAL(number1, number2);

	return number3;
}
```

`number1` and `number2` represent SSA instantiations of `number`, and we've inserted `MULTIEQUAL` operation before the return, indicating that the return value (`number3`) will be one of these prior two values. `MULTIEQUAL` is not constrained to only taking two values, for example, if we had five values which `number` could take before return, we could have `number6 = MULTIEQUAL(number1, number2, number3, number4, number5);`.

We can handle `MULTIEQUAL` p-code operations by noting that the next node we append to our path will be a phi input, and should be marked accordingly. When we print out paths at the end, inputs to the same phi will be marked accordingly so that end users know that each value is a possible input to the phi.

### Analyzing Parent Calls

In addition to analyzing functions *called* by our current function, our analysis must consider functions *calling* our current function, as values passed to `malloc` could be dependent on parameters to our function. For example:

```
void doMalloc(int int1, int size){
	...
	malloc(size);
}

...

doMalloc(8, 5);
...
doMalloc(10, 7);
```

In cases like these, we will search for each location in the binary where our current function (`doMalloc`) is called, and analyze the parameter passed to the function which effects the value passed to our target function. In the above case, analysis would return that 5 and 7 are both possible values for `size` in a call to `doMalloc`. 

As our analysis simply considers each site in the binary where the current function we are analyzing is called, it can make mistakes in analysis, because it is not "*context sensitive*". Analysis does not consider the specific context in which functions are called, which can lead to inaccuracies in cases that seem obvious. For example, if we have a function:

```
int returnArg0(int arg0){ 
	return arg0;
}
```

And this function is called in several places:

```
int x = returnArg0(9);

int y  = returnArg0(7);

printf("%d", returnArg0(8));

malloc(returnArg0(11));
```
While to us it's very obvious that the call to `malloc` will receive argument 11, our context-insensitive analysis considers every site in the program in which `returnArg0` is called, so it will return 9, 7, 8, and 11 all as possible values for the value at this call to `malloc`

As with analysis of called functions, analysis of calling functions may be applied recursively. Further, these analyses may be interwoven with one another, if for example, a function is invoked with parameter derived from a call into another function.


## Ghidra Resources


I found Ghidra's included plugins [`ShowConstantUse.java`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/ghidra_scripts/ShowConstantUse.java) and [`WindowsResourceReference.java`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/ghidra_scripts/WindowsResourceReference.java) very helpful when working with p-code and the Ghidra decompiler. I borrowed some code from these scripts when building this script, and consulted them extensively.


## Output
The data we’re dealing with is probably best visualized with a graph of connected nodes. [Unfortunately, the publicly released version of Ghidra does not currently have the necessary external "GraphService" needed to work with graphs](https://github.com/NationalSecurityAgency/ghidra/issues/174), as can be observed by running Ghidra’s included scripts [`GraphAST.java`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/ghidra_scripts/GraphAST.java), [`GraphASTAndFlow.java`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/ghidra_scripts/GraphASTAndFlow.java), and [`GraphSelectedAST.java`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/ghidra_scripts/GraphSelectedAST.java) (a popup alert informs the user "GraphService not found: Please add a graph service provider to your tool").

Without a graph provider, I resorted to using ASCII depictions of flow to our "sink" function of `malloc`. Each line of output represents a node on the way to malloc. A series of lines before the node’s value represents how it is derived, with `-` representing a value coming from within a function (either because it returns a constant or calls an external function), `+` representing a value coming from a function parameter, and `Ø` being printed when a series of nodes are inputs to a phi-node. `C:` is used to denote a called "child" function call, `P:` for a calling "parent", and `CONST:` for a terminal constant value.

For example:

```
int return3(){
	return 3;
}

…
malloc(return3());
…
```

Here, we have a call into return3 denoted by `-`, and then inside of that function, a terminal constant value of `3`.

```
SINK: call to malloc in analyzefun @ 0x4008f6
-C: return3
--CONST: 3 (0x3)
```

In a more complex case:

```
int returnmynumberplus5(int x){
	return x+5;
}
...
malloc(returnmynumberplus5(10) | 7);
....


SINK: call to malloc in analyzefun @ 0x40091a
-C: returnmynumberplus5
-+P: call analyzefun -> returnmynumberplus5 @ 0x40090d - param #0
-+-CONST: 10 (0xA)
```

Here we have a call into `returnmynumberplus5` denoted with `-`, then `-+` denoting that the return value for `returnmynumberplus5` is derived from a parameter passed to it by a calling "parent" function, and then finally `-+-` for the final constant value of 10 which was determined to be the ultimate terminating constant in this flow to the sink function.
This is somewhat a contrived example, as the script considers all possible callsites for `returnmynumberplus5`, and would in fact list constants (or other values) passed to the function throughout the entire program, if there were other sites where it was invoked - an example of the script not being context sensitive. 

Finally, lets take a look at a case where a phi node is involved:

```
int phidemo(){
	int x = 0;
	if (rand() > 100){
		x = 100;
	}
	else if (rand() > 200){
		x = 700;
	}
	return x;
}

...
malloc(phidemo());
...


SINK: call to malloc in analyzefun @ 0x4008b0
-C: phidemo
--ØCONST: 100 (0x64)
--ØCONST: 0 (0x0)
--ØCONST: 700 (0x2bc)

```
In this case, we see that the call to `malloc` is the result of a call to `phidemo`. At the next level deeper, we print `-` followed by `Ø`, indicating the three constant values displayed are all phi node inputs, with only one used in returning from `phidemo`.


## Limitations and Future Work

After all that discussion of what this script can do, we should address the various things that it cannot. This proof of concept script has a number of limitations, including:

* Transfers of control flow between functions not based on `CALL` p-code ops with explicitly resolved targets. This includes use of direct jumps to other functions, transfer through function pointers, or C++ vtables
* Handling pointers
* Recursive functions
* Programs using p-code operations that we do not support
* Context sensitive analysis
* etc...

That said, implementing support for these other constructions should be possible and fairly easy. Beyond growing out more robust support for various program constructions, there are many of other directions this code could be taken in:	
* Adding support for actually logging all operations along the way, e.g, letting the user know that the value parsed by `atoi()` is then multiplied by `8`, and compared against `0x100`, and then `2` is added - for example.
* Integrating an SMT solver to allow for more complex analyses of possible values
* Adding context sensitivity
* Modeling process address space

## Conclusion

I hope this blog post has been insightful in elucidating how Ghidra's powerful scripting API, intermediate representation, and built-in data flow analysis can be leveraged together for program analysis. With this script, I've only scratched the surface of what is possible with Ghidra, I hope we'll see more public research on what the tool can do.

I know this script isn't perfect, please do reach out if you find it useful or have suggestions for improvement.

> If you have questions about your reverse engineering and security analysis, consider [contacting our team]({{< relref "contact.md" >}}) of experienced security experts to learn more about what you can do.
> <br/>
> If you have questions or comments about Ghidra, p-code, training, or otherwise want to get in touch, you can email re-training@riverloopsecurity.com, or contact me directly via open DMs on Twitter at https://twitter.com/0xAlexei

## Acknowledgements
Thank you to [Jeremy Blackthorne](https://twitter.com/0xJeremy), my collaborator in presenting on Ghidra - later this summer at REcon Montreal, Jeremy and I will be teaching a four day training on binary exploitation, where we’ll use Ghidra, sign up at: https://recon.cx/2019/montreal/training/trainingmodern.html. Jeremy will also be teaching his own training on Ghidra in August at Ringzer0: https://ringzer0.training/reverse-engineering-with-ghidra.html, and you can find information about his company Boston Cybernetics Insitute's other training offerings at https://www.bostoncyber.org/

Rolf Rolles’ insights into program analysis, p-code, and Ghidra’s scripting interface were invaluable in working on this project. Thank you to the Vector 35 Binary Ninja crew for also elucidating some program analysis concepts during their excellent [Binary Ninja training at INFILTRATE 2019](https://infiltratecon.com/training/) - also thanks to Sophia d’Antoine for her 2017 Binary Ninja memcpy example script. [Dr. Brendan Dolan-Gavitt](https://engineering.nyu.edu/faculty/brendan-dolan-gavitt) shared some program analysis insights as well.

Finally, thank you to all of the developers at NSA who actually created Ghidra. All of this work would not be possible without their creation of the tool. The example plugins published with Ghidra were also invaluable in understanding how to work with p-code.


