#!/bin/python

import symtable


st = symtable.symtable("x = 5", "ew", "exec")

print(st.get_identifiers())

with open("./TWO.txt", 'r') as f:
    contents = f.read()
    
print(contents)
