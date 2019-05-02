#Hello world Python example
#@author Alexei Bulazel
#@category INFILTRATE
#@keybinding 
#@menupath 
#@toolbar 


print "Hello world!"

f = getFirstFunction()

while f != None:
	print f.getName()
	f = getFunctionAfter(f)