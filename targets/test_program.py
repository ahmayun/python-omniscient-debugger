#!/bin/python

import symtable

print("mark1")
print("mark2")
print("mark3")
print("mark4")

st = symtable.symtable("x = 5", "ew", "exec")

print(st.get_identifiers())

with open("./TWO.txt", 'r') as f:
    contents = f.read()
    
print(contents)
